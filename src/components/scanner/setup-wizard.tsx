"use client"

import { useState, useRef, useCallback, useEffect } from "react"
import { Shield, Download, CheckCircle2, AlertCircle, Search, FileSearch, Lock, Cpu, Package, Settings } from "lucide-react"
import { useInstallProgress } from "@/lib/install-context"

interface InstallProgress {
  percent: number
  bytes?: number
  total?: number
  error?: string
  done?: boolean
}

// ─── Category definitions ──────────────────────────────────────────────────────
interface Category {
  key: string
  label: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  bgColor: string
  color: string
}

const CATEGORIES: Category[] = [
  { key: "sast", label: "静态分析 (SAST)", description: "代码质量与安全漏洞扫描", icon: FileSearch, bgColor: "bg-blue-500/10", color: "text-blue-500" },
  { key: "secret", label: "密钥检测", description: "硬编码密码、Token、密钥泄露", icon: Lock, bgColor: "bg-red-500/10", color: "text-red-500" },
  { key: "dependency", label: "依赖扫描 (SCA)", description: "第三方组件漏洞与许可证", icon: Package, bgColor: "bg-amber-500/10", color: "text-amber-500" },
  { key: "filesystem", label: "文件系统", description: "IaC 配置、OS 漏洞、模板扫描", icon: Search, bgColor: "bg-purple-500/10", color: "text-purple-500" },
  { key: "ai", label: "AI 代码审计", description: "DeepSeek LLM 代码分析", icon: Cpu, bgColor: "bg-emerald-500/10", color: "text-emerald-500" },
]

interface ScannerDef {
  name: string
  displayName: string
  category: string
  size: string
}

const ALL_SCANNERS: ScannerDef[] = [
  { name: "semgrep", displayName: "Semgrep", size: "8 MB", category: "sast" },
  { name: "bandit", displayName: "Bandit", size: "28 MB", category: "sast" },
  { name: "gitleaks", displayName: "Gitleaks", size: "22 MB", category: "secret" },
  { name: "trufflehog", displayName: "TruffleHog", size: "22 MB", category: "secret" },
  { name: "npm-audit", displayName: "npm audit", size: "-", category: "dependency" },
  { name: "pip-audit", displayName: "pip-audit", size: "35 MB", category: "dependency" },
  { name: "dependency-check", displayName: "Dependency-Check", size: "36 MB", category: "dependency" },
  { name: "osv-scanner", displayName: "OSV-Scanner", size: "56 MB", category: "dependency" },
  { name: "checkov", displayName: "Checkov", size: "pip", category: "filesystem" },
  { name: "trivy", displayName: "Trivy", size: "165 MB", category: "filesystem" },
  { name: "nuclei", displayName: "Nuclei", size: "131 MB", category: "filesystem" },
  { name: "scorecard", displayName: "Scorecard", size: "131 MB", category: "sast" },
  { name: "cve-cpp", displayName: "CVE-CPP", size: "-", category: "dependency" },
  { name: "swift", displayName: "Swift", size: "-", category: "dependency" },
  { name: "codeql", displayName: "CodeQL", size: "365 MB", category: "sast" },
  { name: "ai-scanner", displayName: "AI Scanner", size: "-", category: "ai" },
]

const SCANNERS_BY_CATEGORY: Record<string, ScannerDef[]> = {}
for (const sc of ALL_SCANNERS) {
  if (!SCANNERS_BY_CATEGORY[sc.category]) SCANNERS_BY_CATEGORY[sc.category] = []
  SCANNERS_BY_CATEGORY[sc.category].push(sc)
}

function getScannersForCategories(categories: Set<string>): ScannerDef[] {
  const result: ScannerDef[] = []
  for (const cat of categories) {
    const scanners = SCANNERS_BY_CATEGORY[cat]
    if (scanners) result.push(...scanners)
  }
  return result
}

function totalSizeForCategories(categories: Set<string>): number {
  let total = 0
  for (const cat of categories) {
    const scanners = SCANNERS_BY_CATEGORY[cat]
    if (scanners) {
      for (const sc of scanners) {
        const match = sc.size.match(/(\d+)/)
        if (match) total += parseInt(match[1], 10)
      }
    }
  }
  return total
}

// ─── Component ─────────────────────────────────────────────────────────────────

interface SetupWizardProps {
  open: boolean
  onFinish: () => void
}

export function SetupWizard({ open, onFinish }: SetupWizardProps) {
  const { installing, startInstall, _updateProgress, _markDone } = useInstallProgress()
  const [step, setStep] = useState<"welcome" | "select" | "done">("welcome")
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set(["sast", "secret", "dependency"]))
  const [isElectron, setIsElectron] = useState(false)
  const abortRef = useRef(false)

  // Proxy settings
  const [proxyEnabled, setProxyEnabled] = useState(false)
  const [httpProxy, setHttpProxy] = useState("http://127.0.0.1:7897")
  const [httpsProxy, setHttpsProxy] = useState("http://127.0.0.1:7897")

  useEffect(() => {
    setIsElectron(typeof window !== "undefined" && !!window.vulnguard?.downloadScanner)
  }, [])

  const toggleCategory = (cat: string) => {
    setSelectedCategories((prev) => {
      const next = new Set(prev)
      if (next.has(cat)) next.delete(cat)
      else next.add(cat)
      return next
    })
  }

  // 保存代理设置到后端
  const saveProxySettings = useCallback(async (): Promise<boolean> => {
    if (!proxyEnabled) return true
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          proxyEnabled: true,
          httpProxy: httpProxy || "",
          httpsProxy: httpsProxy || "",
        }),
      })
      return res.ok
    } catch {
      return false
    }
  }, [proxyEnabled, httpProxy, httpsProxy])

  const handleStartInstall = useCallback(async () => {
    // 先保存代理设置
    await saveProxySettings()

    // 获取要安装的扫描器列表
    const scanners = getScannersForCategories(selectedCategories)
    const names = scanners.map(s => s.name)

    // 通知全局 context 开始安装
    startInstall(names)

    // 标记向导完成（关闭界面）
    setStep("done")
    onFinish()

    // 开始逐个安装扫描器
    const isElectronMode = typeof window !== "undefined" && !!window.vulnguard?.downloadScanner

    for (let i = 0; i < scanners.length; i++) {
      if (abortRef.current) break
      const sc = scanners[i]

      if (isElectronMode && window.vulnguard?.downloadScanner) {
        const unsub = window.vulnguard.onScannerProgress((data: InstallProgress) => {
          if (data.error) return
          _updateProgress(data.percent)
        })

        const result = await window.vulnguard.downloadScanner(sc.name)
        unsub()

        if (result?.ok) {
          _markDone(sc.displayName, true)
        } else {
          _markDone(sc.displayName, false, result?.error || "安装失败")
        }
      } else {
        // Web mode via SSE
        try {
          const res = await fetch("/api/scanners/install", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ scanner: sc.name }),
          })

          if (!res.ok) {
            _markDone(sc.displayName, false)
            continue
          }

          const reader = res.body?.getReader()
          if (!reader) {
            _markDone(sc.displayName, false)
            continue
          }

          const decoder = new TextDecoder()
          let buffer = ""
          let installOk = false

          while (true) {
            const { done, value } = await reader.read()
            if (done) break

            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split("\n")
            buffer = lines.pop() || ""

            for (const line of lines) {
              if (line.startsWith("data: ")) {
                try {
                  const data = JSON.parse(line.slice(6))
                  if (data.error) break
                  _updateProgress(data.percent)
                  if (data.done && data.ok) installOk = true
                } catch { /* skip */ }
              }
            }
          }

          _markDone(sc.displayName, installOk)
        } catch {
          _markDone(sc.displayName, false)
        }
      }
    }
  }, [selectedCategories, isElectron, saveProxySettings, startInstall, _updateProgress, _markDone, onFinish])

  const totalSize = totalSizeForCategories(selectedCategories)

  // ── Not open or already installing → nothing ──
  if (!open || installing) return null

  // ── Done step ──
  if (step === "done") {
    return null // floating ball is now managed by layout
  }

  // ── Welcome step: compact card ──
  if (step === "welcome") {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
        <div className="w-full max-w-md rounded-xl border bg-card p-6 shadow-2xl space-y-5">
          <div className="text-center space-y-3">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10">
              <Shield className="h-7 w-7 text-primary" />
            </div>
            <h2 className="text-lg font-bold">欢迎使用 VulnGuard</h2>
            <p className="text-xs text-muted-foreground">
              首次使用需要安装扫描引擎。选择您需要的扫描能力，按需安装。
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <button
              onClick={() => setStep("select")}
              className="rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              开始配置
            </button>
            <button
              onClick={() => { setStep("welcome"); onFinish() }}
              className="rounded-lg bg-secondary px-4 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              跳过，稍后配置
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ── Select step: compact card ──
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 backdrop-blur-sm overflow-y-auto py-10">
      <div className="w-full max-w-lg rounded-xl border bg-card p-5 shadow-2xl space-y-4">
        <div className="text-center">
          <h2 className="text-base font-bold">选择扫描能力</h2>
          <p className="text-xs text-muted-foreground mt-1">按分类勾选您需要的扫描器，已选约 {totalSize} MB</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {CATEGORIES.map((cat) => {
            const Icon = cat.icon
            const isSelected = selectedCategories.has(cat.key)
            const scanners = SCANNERS_BY_CATEGORY[cat.key] || []
            return (
              <button
                key={cat.key}
                onClick={() => toggleCategory(cat.key)}
                className={`w-full flex items-start gap-2 rounded-lg border p-3 text-left transition-all ${
                  isSelected
                    ? "border-primary/40 bg-primary/5"
                    : "border-border hover:border-muted-foreground/30"
                }`}
              >
                <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${cat.bgColor}`}>
                  <Icon className={`h-4 w-4 ${cat.color}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className="text-xs font-medium">{cat.label}</span>
                    <span className="text-[9px] text-muted-foreground">{scanners.length} 个</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{cat.description}</p>
                  <div className="flex flex-wrap gap-0.5 mt-1">
                    {scanners.map((s) => (
                      <span key={s.name} className="inline-flex items-center gap-0.5 rounded bg-secondary px-1 py-0.5 text-[9px] text-muted-foreground">
                        {s.displayName}
                        <span className="opacity-60">{s.size}</span>
                      </span>
                    ))}
                  </div>
                </div>
                <div className={`mt-1 h-3.5 w-3.5 shrink-0 rounded border-2 flex items-center justify-center transition-colors ${
                  isSelected ? "border-primary bg-primary" : "border-muted-foreground/40"
                }`}>
                  {isSelected && <CheckCircle2 className="h-2.5 w-2.5 text-primary-foreground" />}
                </div>
              </button>
            )
          })}
        </div>

        {/* Proxy configuration */}
        <div className="rounded-lg border border-border p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Settings className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-xs font-medium">网络代理</span>
              <span className="text-[9px] text-muted-foreground">（GitHub 无法访问时开启）</span>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" checked={proxyEnabled} onChange={(e) => setProxyEnabled(e.target.checked)} className="sr-only peer" />
              <div className="w-8 h-4 bg-muted rounded-full peer peer-checked:bg-primary after:content-[''] after:absolute after:top-[1px] after:left-[1px] after:bg-white after:rounded-full after:h-3.5 after:w-3.5 after:transition-all peer-checked:after:translate-x-4" />
            </label>
          </div>
          {proxyEnabled && (
            <div className="mt-2 space-y-1.5 pt-2 border-t border-border">
              <input type="text" value={httpProxy} onChange={(e) => setHttpProxy(e.target.value)}
                placeholder="http://127.0.0.1:7897"
                className="w-full rounded border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/30" />
              <input type="text" value={httpsProxy} onChange={(e) => setHttpsProxy(e.target.value)}
                placeholder="http://127.0.0.1:7897"
                className="w-full rounded border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/30" />
            </div>
          )}
        </div>

        <div className="flex flex-col gap-2">
          <button
            onClick={handleStartInstall}
            disabled={selectedCategories.size === 0}
            className="rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            安装已选 ({getScannersForCategories(selectedCategories).length} 个)
          </button>
          <button
            onClick={() => { setStep("welcome"); onFinish() }}
            className="rounded-lg bg-secondary px-4 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            稍后再说
          </button>
        </div>
      </div>
    </div>
  )
}
