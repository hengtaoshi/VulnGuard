"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { Shield, Search, Lock, FolderTree, Cpu, CheckCircle2, Loader2, AlertCircle, Download, ChevronRight } from "lucide-react"

interface ScannerDef {
  name: string
  displayName: string
  category: string
  description: string
  size: string
}

interface InstallProgress {
  percent: number
  done?: boolean
  ok?: boolean
  error?: string
  scanner?: string
}

const CATEGORIES = [
  {
    key: "sast",
    label: "静态代码分析 (SAST)",
    icon: Search,
    description: "深度分析源代码中的安全漏洞，如注入、XSS、路径遍历等",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
  },
  {
    key: "secret",
    label: "密钥检测",
    icon: Lock,
    description: "检测源代码中硬编码的 API 密钥、密码、Token 等敏感信息",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
  },
  {
    key: "dependency",
    label: "依赖扫描 (SCA)",
    icon: FolderTree,
    description: "检查项目依赖中的已知 CVE 漏洞，覆盖 npm、pip、Maven、Go 等多个生态",
    color: "text-amber-500",
    bgColor: "bg-amber-500/10",
  },
  {
    key: "filesystem",
    label: "文件系统扫描",
    icon: Shield,
    description: "扫描 IaC 配置、OS 包、容器镜像中的安全风险和 CVE",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
  },
  {
    key: "ai",
    label: "AI 智能分析",
    icon: Cpu,
    description: "基于 DeepSeek 大模型进行代码审计，需要配置 API Key",
    color: "text-emerald-500",
    bgColor: "bg-emerald-500/10",
  },
]

// Scanner definitions grouped by category
const SCANNERS_BY_CATEGORY: Record<string, ScannerDef[]> = {
  sast: [
    { name: "semgrep", displayName: "Semgrep", category: "sast", description: "多语言 SAST，2000+ 安全规则", size: "~100 MB" },
    { name: "bandit", displayName: "Bandit", category: "sast", description: "Python 代码安全扫描", size: "pip 包" },
    { name: "codeql", displayName: "CodeQL", category: "sast", description: "GitHub 语义代码分析引擎", size: "~200 MB" },
    { name: "scorecard", displayName: "OpenSSF Scorecard", category: "sast", description: "开源安全实践评估", size: "~15 MB" },
  ],
  secret: [
    { name: "gitleaks", displayName: "Gitleaks", category: "secret", description: "快速密钥泄露检测", size: "~10 MB" },
    { name: "trufflehog", displayName: "TruffleHog", category: "secret", description: "企业级密钥检测，800+ 检测器", size: "~20 MB" },
  ],
  dependency: [
    { name: "npm-audit", displayName: "npm audit", category: "dependency", description: "JS/TS 依赖 CVE 扫描", size: "内置" },
    { name: "pip-audit", displayName: "pip-audit", category: "dependency", description: "Python 依赖漏洞审计", size: "pip 包" },
    { name: "osv-scanner", displayName: "OSV-Scanner", category: "dependency", description: "Google 多生态依赖扫描", size: "~15 MB" },
    { name: "dependency-check", displayName: "Dependency-Check", category: "dependency", description: "OWASP SCA，需 Java", size: "~280 MB" },
  ],
  filesystem: [
    { name: "trivy", displayName: "Trivy", category: "filesystem", description: "OS 包/依赖综合 CVE 扫描", size: "~50 MB" },
    { name: "checkov", displayName: "Checkov", category: "filesystem", description: "IaC 安全配置扫描", size: "pip 包" },
    { name: "nuclei", displayName: "Nuclei", category: "filesystem", description: "模板化漏洞扫描", size: "~30 MB" },
  ],
  ai: [
    { name: "ai-scanner", displayName: "AI Scanner", category: "ai", description: "DeepSeek 代码审计，需 API Key", size: "在线服务" },
  ],
}

// Get all scanners for a set of categories
function getScannersForCategories(selected: Set<string>): ScannerDef[] {
  const result: ScannerDef[] = []
  for (const cat of selected) {
    const scanners = SCANNERS_BY_CATEGORY[cat]
    if (scanners) result.push(...scanners)
  }
  return result
}

interface WizardProps {
  open: boolean
  onFinish: () => void
}

export function SetupWizard({ open, onFinish }: WizardProps) {
  const [step, setStep] = useState<"welcome" | "select" | "installing" | "done">("welcome")
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set(["sast", "secret"]))
  const [currentScanner, setCurrentScanner] = useState<string>("")
  const [currentLabel, setCurrentLabel] = useState<string>("")
  const [progress, setProgress] = useState(0)
  const [completed, setCompleted] = useState<string[]>([])
  const [failed, setFailed] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [isElectron, setIsElectron] = useState(false)
  const abortRef = useRef(false)

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

  const startInstall = useCallback(async () => {
    setStep("installing")
    setError(null)
    setCompleted([])
    setFailed([])
    abortRef.current = false

    const scanners = getScannersForCategories(selectedCategories)
    let hasError = false

    for (let i = 0; i < scanners.length; i++) {
      if (abortRef.current) break
      const sc = scanners[i]
      setCurrentScanner(sc.name)
      setCurrentLabel(sc.displayName)
      setProgress(0)

      if (isElectron && window.vulnguard?.downloadScanner) {
        const unsub = window.vulnguard.onScannerProgress((data: InstallProgress) => {
          if (data.error) {
            setError(data.error)
            return
          }
          setProgress(data.percent)
        })

        const result = await window.vulnguard.downloadScanner(sc.name)
        unsub()

        if (result?.ok) {
          setCompleted((prev) => [...prev, sc.displayName])
        } else {
          setFailed((prev) => [...prev, sc.displayName])
          hasError = true
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
            setFailed((prev) => [...prev, sc.displayName])
            hasError = true
            continue
          }

          const reader = res.body?.getReader()
          if (!reader) {
            setFailed((prev) => [...prev, sc.displayName])
            hasError = true
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
                  setProgress(data.percent)
                  if (data.done && data.ok) {
                    installOk = true
                  }
                } catch { /* skip */ }
              }
            }
          }

          if (installOk) {
            setCompleted((prev) => [...prev, sc.displayName])
          } else {
            setFailed((prev) => [...prev, sc.displayName])
            hasError = true
          }
        } catch {
          setFailed((prev) => [...prev, sc.displayName])
          hasError = true
        }
      }
    }

    setCurrentScanner("")
    setCurrentLabel("")
    setStep("done")
  }, [selectedCategories, isElectron])

  if (!open) return null

  // ── Welcome step ──
  if (step === "welcome") {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm">
        <div className="w-full max-w-lg mx-auto p-6">
          <div className="text-center space-y-4 mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <h1 className="text-xl font-bold">欢迎使用 VulnGuard</h1>
            <p className="text-sm text-muted-foreground max-w-sm mx-auto">
              首次使用需要安装扫描引擎。选择您需要的扫描能力，按需安装，避免占用不必要的磁盘空间。
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
              onClick={onFinish}
              className="rounded-lg bg-secondary px-4 py-2.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              跳过，稍后配置
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ── Select step ──
  if (step === "select") {
    const selectedScanners = getScannersForCategories(selectedCategories)
    const totalSize = selectedScanners
      .map((s) => s.size)
      .filter((s) => s !== "内置" && s !== "pip 包" && s !== "在线服务")
      .reduce((acc, s) => {
        const match = s.match(/(\d+)/)
        return acc + (match ? parseInt(match[1]) : 0)
      }, 0)

    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm overflow-y-auto py-8">
        <div className="w-full max-w-lg mx-auto p-6">
          <div className="text-center space-y-2 mb-6">
            <h2 className="text-lg font-bold">选择扫描能力</h2>
            <p className="text-xs text-muted-foreground">按分类勾选您需要的扫描器，已选约 {totalSize} MB</p>
          </div>

          <div className="space-y-2 mb-6">
            {CATEGORIES.map((cat) => {
              const Icon = cat.icon
              const isSelected = selectedCategories.has(cat.key)
              const scanners = SCANNERS_BY_CATEGORY[cat.key] || []
              return (
                <button
                  key={cat.key}
                  onClick={() => toggleCategory(cat.key)}
                  className={`w-full flex items-start gap-3 rounded-xl border p-3 text-left transition-all ${
                    isSelected
                      ? "border-primary/40 bg-primary/5"
                      : "border-border hover:border-muted-foreground/30"
                  }`}
                >
                  <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${cat.bgColor}`}>
                    <Icon className={`h-4 w-4 ${cat.color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{cat.label}</span>
                      <span className="text-[10px] text-muted-foreground">{scanners.length} 个</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{cat.description}</p>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {scanners.map((s) => (
                        <span
                          key={s.name}
                          className="inline-flex items-center gap-1 rounded-md bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground"
                        >
                          {s.displayName}
                          <span className="text-[9px] opacity-60">{s.size}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                  <div
                    className={`mt-1 h-4 w-4 shrink-0 rounded border-2 flex items-center justify-center transition-colors ${
                      isSelected
                        ? "border-primary bg-primary"
                        : "border-muted-foreground/40"
                    }`}
                  >
                    {isSelected && <CheckCircle2 className="h-3 w-3 text-primary-foreground" />}
                  </div>
                </button>
              )
            })}
          </div>

          <div className="flex flex-col gap-2">
            <button
              onClick={startInstall}
              disabled={selectedCategories.size === 0}
              className="rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              安装已选 ({getScannersForCategories(selectedCategories).length} 个)
            </button>
            <button
              onClick={onFinish}
              className="rounded-lg bg-secondary px-4 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              稍后再说
            </button>
          </div>
        </div>
      </div>
    )
  }

  // ── Installing step ──
  if (step === "installing") {
    const allScanners = getScannersForCategories(selectedCategories)
    const total = allScanners.length
    const doneCount = completed.length + failed.length

    // 加权累计进度：已完成的算 (doneCount/total)*100%，当前的在加 (current/total)%
    const weightedPct = total > 0
      ? Math.min(100, (doneCount / total) * 100 + (progress / total))
      : 0

    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm">
        <div className="w-full max-w-md mx-auto p-6">
          <div className="text-center space-y-3 mb-6">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-primary/10">
              <Download className="h-6 w-6 text-primary animate-bounce" />
            </div>
            <h2 className="text-base font-bold">正在安装扫描器</h2>
            <p className="text-xs text-muted-foreground">
              {doneCount}/{total} — {currentLabel}
            </p>
          </div>

          {/* 加权累计进度条（只增不减，消除回退） */}
          <div className="h-2 w-full overflow-hidden rounded-full bg-secondary mb-4">
            <div
              className="h-full rounded-full bg-primary transition-all duration-500 ease-out"
              style={{ width: `${Math.max(1, weightedPct)}%` }}
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-destructive/10 p-2 text-xs text-destructive mb-3">
              <AlertCircle className="h-3 w-3 shrink-0" />
              {error}
            </div>
          )}

          {/* Completed/failed list */}
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {completed.map((name) => (
              <div key={name} className="flex items-center gap-2 text-xs text-emerald-500">
                <CheckCircle2 className="h-3 w-3" />
                {name}
              </div>
            ))}
            {failed.map((name) => (
              <div key={name} className="flex items-center gap-2 text-xs text-destructive">
                <AlertCircle className="h-3 w-3" />
                {name}
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  // ── Done step ──
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm">
      <div className="w-full max-w-sm mx-auto p-6 text-center space-y-4">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-emerald-500/10">
          <CheckCircle2 className="h-7 w-7 text-emerald-500" />
        </div>
        <h2 className="text-base font-bold">配置完成</h2>
        <div className="text-xs text-muted-foreground space-y-1">
          {completed.length > 0 && <p>✓ {completed.length} 个扫描器安装成功</p>}
          {failed.length > 0 && <p className="text-destructive">✗ {failed.length} 个安装失败，可稍后在设置中重试</p>}
        </div>
        <button
          onClick={onFinish}
          className="rounded-lg bg-primary px-6 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          开始使用
        </button>
      </div>
    </div>
  )
}
