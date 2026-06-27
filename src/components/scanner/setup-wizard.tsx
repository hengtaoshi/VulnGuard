"use client"

import { useState, useRef, useCallback, useEffect } from "react"
import { Shield, Download, CheckCircle2, AlertCircle, Search, FileSearch, Lock, Cpu, Package, Minimize2, Expand, Settings } from "lucide-react"

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

// ─── Scanner definitions for the wizard ────────────────────────────────────────
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

// ─── Circular Progress Ball Component ───────────────────────────────────────────

function CircularProgressBall({ percent, onClick, done, error }: {
  percent: number
  onClick: () => void
  done: boolean
  error: boolean
}) {
  const r = 28
  const circumference = 2 * Math.PI * r
  const offset = circumference - (Math.min(percent, 100) / 100) * circumference
  const strokeColor = done ? "#22c55e" : error ? "#ef4444" : "#3b82f6"

  return (
    <button
      onClick={onClick}
      className="fixed bottom-6 right-6 z-50 flex items-center justify-center cursor-pointer group"
      title="点击查看安装详情"
    >
      {/* Pulsing ring background */}
      <div className={`absolute inset-0 rounded-full ${done ? "bg-emerald-500/20" : error ? "bg-red-500/20" : "bg-primary/20"} animate-ping opacity-75`} />
      {/* Main circle */}
      <div className="relative flex items-center justify-center w-20 h-20 rounded-full bg-card border border-border shadow-2xl backdrop-blur-sm">
        <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 64 64">
          <circle cx="32" cy="32" r={r} fill="none" stroke="currentColor" strokeWidth="4" className="text-muted/20" />
          <circle
            cx="32" cy="32" r={r} fill="none"
            stroke={strokeColor}
            strokeWidth="4"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-500 ease-out"
          />
        </svg>
        <div className="flex flex-col items-center">
          {done ? (
            <CheckCircle2 className="h-6 w-6 text-emerald-500" />
          ) : error ? (
            <AlertCircle className="h-6 w-6 text-red-500" />
          ) : (
            <>
              <span className="text-xs font-bold tabular-nums">{Math.round(percent)}%</span>
              <Download className="h-3 w-3 text-primary animate-bounce mt-0.5" />
            </>
          )}
        </div>
      </div>
    </button>
  )
}

// ─── Component ─────────────────────────────────────────────────────────────────

interface SetupWizardProps {
  open: boolean
  onFinish: () => void
}

export function SetupWizard({ open, onFinish }: SetupWizardProps) {
  const [step, setStep] = useState<"welcome" | "select" | "proxy" | "installing" | "done">("welcome")
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set(["sast", "secret", "dependency"]))
  const [currentScanner, setCurrentScanner] = useState("")
  const [currentLabel, setCurrentLabel] = useState("")
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [completed, setCompleted] = useState<string[]>([])
  const [failed, setFailed] = useState<string[]>([])
  const [isElectron, setIsElectron] = useState(false)
  const abortRef = useRef(false)
  const [displayPct, setDisplayPct] = useState(0)
  const [expanded, setExpanded] = useState(false)

  // Proxy settings
  const [proxyEnabled, setProxyEnabled] = useState(false)
  const [httpProxy, setHttpProxy] = useState("http://127.0.0.1:7897")
  const [httpsProxy, setHttpsProxy] = useState("http://127.0.0.1:7897")

  useEffect(() => {
    setIsElectron(typeof window !== "undefined" && !!window.vulnguard?.downloadScanner)
  }, [])

  // 单调递增进度：用 functional updater 确保只涨不跌，无需额外 ref
  useEffect(() => {
    if (step === "installing") {
      const allScanners = getScannersForCategories(selectedCategories)
      const total = allScanners.length
      const doneCount = completed.length + failed.length
      const rawPct = total > 0
        ? Math.min(100, (doneCount / total) * 100 + (progress / total))
        : 0
      setDisplayPct(prev => Math.max(prev, rawPct))
    }
  }, [step, progress, completed.length, failed.length, selectedCategories])

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

  const startInstall = useCallback(async () => {
    setStep("installing")
    setExpanded(false) // 默认最小化为悬浮球
    setError(null)
    setCompleted([])
    setFailed([])
    setDisplayPct(0)
    setProgress(0)
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
          setError(result?.error || "安装失败")
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
            const errText = await res.text().catch(() => "HTTP " + res.status)
            setError(errText)
            setFailed((prev) => [...prev, sc.displayName])
            hasError = true
            continue
          }

          const reader = res.body?.getReader()
          if (!reader) {
            setError("无法读取响应流")
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
                  if (data.error) {
                    setError(data.error)
                    break
                  }
                  setProgress(data.percent)
                  if (data.done && data.ok) {
                    installOk = true
                  }
                } catch { /* skip malformed SSE */ }
              }
            }
          }

          if (installOk) {
            setCompleted((prev) => [...prev, sc.displayName])
          } else {
            setError("安装未完成")
            setFailed((prev) => [...prev, sc.displayName])
            hasError = true
          }
        } catch (e) {
          setError(e instanceof Error ? e.message : "安装请求失败")
          setFailed((prev) => [...prev, sc.displayName])
          hasError = true
        }
      }
    }

    setStep("done")
    setExpanded(false)
  }, [selectedCategories, isElectron, proxyEnabled, httpProxy, httpsProxy])

  const totalSize = totalSizeForCategories(selectedCategories)

  // ── Not open → nothing ──
  if (!open && step !== "installing") return null

  // ── Installing step: floating ball (minimized) or full overlay (expanded) ──
  if (step === "installing") {
    const allScanners = getScannersForCategories(selectedCategories)
    const total = allScanners.length
    const doneCount = completed.length + failed.length

    return (
      <>
        {/* Floating progress ball — always visible during installation */}
        <CircularProgressBall
          percent={displayPct}
          onClick={() => setExpanded((v) => !v)}
          done={doneCount === total && total > 0}
          error={failed.length > 0 && completed.length === 0}
        />

        {/* Expanded detail overlay — shown when user clicks the ball */}
        {expanded && (
          <div className="fixed inset-0 z-40 flex items-center justify-center bg-background/80 backdrop-blur-sm">
            <div className="w-full max-w-xl mx-auto p-8 relative">
              {/* Minimize button — back to floating ball */}
              <button
                onClick={() => setExpanded(false)}
                className="absolute top-4 right-4 rounded-full p-2 text-muted-foreground hover:text-foreground hover:bg-secondary transition-colors"
                title="最小化到悬浮球"
              >
                <Minimize2 className="h-4 w-4" />
              </button>

              <div className="text-center space-y-4 mb-8">
                <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10">
                  <Download className="h-7 w-7 text-primary animate-bounce" />
                </div>
                <h2 className="text-lg font-bold">正在安装扫描器</h2>
                <p className="text-sm text-muted-foreground">
                  {doneCount}/{total} — {currentLabel}
                </p>
              </div>

              {/* 单调递增进度条 */}
              <div className="h-3 w-full overflow-hidden rounded-full bg-secondary mb-5">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-500 ease-out"
                  style={{ width: `${Math.max(1, displayPct)}%` }}
                />
              </div>

              {error && (
                <div className="flex items-center gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-destructive mb-4">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  {error}
                </div>
              )}

              {/* Completed/failed list */}
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {completed.map((name) => (
                  <div key={name} className="flex items-center gap-2 text-sm text-emerald-500">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    {name}
                  </div>
                ))}
                {failed.map((name) => (
                  <div key={name} className="flex items-center gap-2 text-sm text-destructive">
                    <AlertCircle className="h-3.5 w-3.5" />
                    {name}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </>
    )
  }

  // ── Done step ──
  if (step === "done") {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm">
        <div className="w-full max-w-lg mx-auto p-8 text-center space-y-5">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-emerald-500/10">
            <CheckCircle2 className="h-8 w-8 text-emerald-500" />
          </div>
          <h2 className="text-xl font-bold">配置完成</h2>
          <div className="text-sm text-muted-foreground space-y-1">
            {completed.length > 0 && <p>✓ {completed.length} 个扫描器安装成功</p>}
            {failed.length > 0 && <p className="text-destructive">✗ {failed.length} 个安装失败，可稍后在设置中重试</p>}
          </div>
          <button
            onClick={() => { setStep("welcome"); onFinish() }}
            className="rounded-lg bg-primary px-8 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            开始使用
          </button>
        </div>
      </div>
    )
  }

  // ── Welcome step ──
  if (step === "welcome") {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-sm">
        <div className="w-full max-w-xl mx-auto p-8">
          <div className="text-center space-y-5 mb-10">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-primary/10">
              <Shield className="h-10 w-10 text-primary" />
            </div>
            <h1 className="text-2xl font-bold">欢迎使用 VulnGuard</h1>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              首次使用需要安装扫描引擎。选择您需要的扫描能力，按需安装，避免占用不必要的磁盘空间。
            </p>
          </div>

          <div className="flex flex-col gap-3 max-w-xs mx-auto">
            <button
              onClick={() => setStep("select")}
              className="rounded-lg bg-primary px-4 py-3 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              开始配置
            </button>
            <button
              onClick={() => { setStep("welcome"); onFinish() }}
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
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center bg-background/95 backdrop-blur-sm overflow-y-auto py-10">
        <div className="w-full max-w-2xl mx-auto p-8">
          <div className="text-center space-y-2 mb-8">
            <h2 className="text-xl font-bold">选择扫描能力</h2>
            <p className="text-sm text-muted-foreground">按分类勾选您需要的扫描器，已选约 {totalSize} MB</p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-8">
            {CATEGORIES.map((cat) => {
              const Icon = cat.icon
              const isSelected = selectedCategories.has(cat.key)
              const scanners = SCANNERS_BY_CATEGORY[cat.key] || []
              return (
                <button
                  key={cat.key}
                  onClick={() => toggleCategory(cat.key)}
                  className={`w-full flex items-start gap-3 rounded-xl border p-4 text-left transition-all ${
                    isSelected
                      ? "border-primary/40 bg-primary/5"
                      : "border-border hover:border-muted-foreground/30"
                  }`}
                >
                  <div className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${cat.bgColor}`}>
                    <Icon className={`h-5 w-5 ${cat.color}`} />
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

          {/* Proxy configuration toggle */}
          <div className="mb-6 rounded-xl border border-border p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Settings className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">网络代理设置</span>
                <span className="text-[10px] text-muted-foreground">（如 GitHub 无法访问请开启）</span>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={proxyEnabled}
                  onChange={(e) => setProxyEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-muted rounded-full peer peer-checked:bg-primary after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-4" />
              </label>
            </div>
            {proxyEnabled && (
              <div className="mt-3 space-y-2 pt-3 border-t border-border">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">HTTP 代理</label>
                  <input
                    type="text"
                    value={httpProxy}
                    onChange={(e) => setHttpProxy(e.target.value)}
                    placeholder="http://127.0.0.1:7897"
                    className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/30"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">HTTPS 代理</label>
                  <input
                    type="text"
                    value={httpsProxy}
                    onChange={(e) => setHttpsProxy(e.target.value)}
                    placeholder="http://127.0.0.1:7897"
                    className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/30"
                  />
                </div>
              </div>
            )}
          </div>

          <div className="flex flex-col gap-3 max-w-sm mx-auto">
            <button
              onClick={async () => {
                // 先保存代理设置，再开始安装
                await saveProxySettings()
                startInstall()
              }}
              disabled={selectedCategories.size === 0}
              className="rounded-lg bg-primary px-4 py-3 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              安装已选 ({getScannersForCategories(selectedCategories).length} 个)
            </button>
            <button
              onClick={() => { setStep("welcome"); onFinish() }}
              className="rounded-lg bg-secondary px-4 py-2.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              稍后再说
            </button>
          </div>
        </div>
      </div>
    )
  }

  return null
}
