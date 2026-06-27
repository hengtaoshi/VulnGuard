"use client"

import { useState, useRef, useCallback, useEffect } from "react"
import { Shield, Download, CheckCircle2, AlertCircle, Settings } from "lucide-react"
import { useInstallProgress } from "@/lib/install-context"

interface InstallProgress {
  percent: number
  bytes?: number
  total?: number
  error?: string
  done?: boolean
}

const BUNDLED_SCANNERS = [
  { name: "gitleaks", label: "Gitleaks", desc: "密钥泄露检测" },
  { name: "trufflehog", label: "TruffleHog", desc: "深度密钥扫描" },
  { name: "semgrep", label: "Semgrep", desc: "多语言 SAST" },
  { name: "bandit", label: "Bandit", desc: "Python SAST" },
  { name: "checkov", label: "Checkov", desc: "IaC 安全扫描" },
  { name: "trivy", label: "Trivy", desc: "OS 漏洞扫描" },
  { name: "nuclei", label: "Nuclei", desc: "模板化漏洞扫描" },
  { name: "osv-scanner", label: "OSV-Scanner", desc: "依赖漏洞扫描" },
  { name: "scorecard", label: "Scorecard", desc: "开源安全评估" },
  { name: "pip-audit", label: "pip-audit", desc: "Python 依赖审计" },
  { name: "dependency-check", label: "Dependency-Check", desc: "Java/.NET SCA" },
  { name: "codeql", label: "CodeQL", desc: "语义代码分析" },
]

interface SetupWizardProps {
  open: boolean
  onFinish: () => void
}

export function SetupWizard({ open, onFinish }: SetupWizardProps) {
  const { installing, startInstall, _updateProgress, _markDone } = useInstallProgress()
  const [isElectron, setIsElectron] = useState(false)
  const abortRef = useRef(false)

  // Proxy settings
  const [proxyEnabled, setProxyEnabled] = useState(false)
  const [httpProxy, setHttpProxy] = useState("http://127.0.0.1:7897")
  const [httpsProxy, setHttpsProxy] = useState("http://127.0.0.1:7897")

  const [step, setStep] = useState<"idle" | "installing" | "done">("idle")

  useEffect(() => {
    setIsElectron(typeof window !== "undefined" && !!window.vulnguard?.downloadScanner)
  }, [])

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

  const handleInstall = useCallback(async () => {
    await saveProxySettings()
    const names = BUNDLED_SCANNERS.map(s => s.name)
    startInstall(names)
    setStep("installing")

    // 下载第一个扫描器 → 触发归档下载
    if (isElectron && window.vulnguard?.downloadScanner) {
      const unsub = window.vulnguard.onScannerProgress((data: InstallProgress) => {
        if (data.error) return
        _updateProgress(data.percent)
      })
      const result = await window.vulnguard.downloadScanner(names[0])
      unsub()

      if (result?.ok) {
        for (const sc of BUNDLED_SCANNERS) _markDone(sc.label, true)
        _updateProgress(100)
      } else {
        for (const sc of BUNDLED_SCANNERS) _markDone(sc.label, false, result?.error)
      }
    } else {
      // Web mode: 调用 API 安装
      for (let i = 0; i < names.length; i++) {
        if (abortRef.current) break
        try {
          const res = await fetch("/api/scanners/install", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ scanner: names[i] }),
          })
          const reader = res.body?.getReader()
          if (!reader) { _markDone(BUNDLED_SCANNERS[i].label, false); continue }

          const decoder = new TextDecoder()
          let buffer = ""
          let ok = false
          while (true) {
            const { done, value } = await reader.read()
            if (done) break
            buffer += decoder.decode(value, { stream: true })
            for (const line of buffer.split("\n").filter(l => l.startsWith("data: "))) {
              try {
                const d = JSON.parse(line.slice(6))
                if (d.error) break
                _updateProgress(d.percent)
                if (d.done && d.ok) ok = true
              } catch { /* skip */ }
            }
          }
          _markDone(BUNDLED_SCANNERS[i].label, ok)
        } catch {
          _markDone(BUNDLED_SCANNERS[i].label, false)
        }
      }
    }

    setStep("done")
    onFinish()
  }, [isElectron, saveProxySettings, startInstall, _updateProgress, _markDone, onFinish])

  if (!open) return null
  if (step === "done" || installing) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border bg-card p-6 shadow-2xl space-y-5">
        {/* Header */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10">
            <Shield className="h-7 w-7 text-primary" />
          </div>
          <h2 className="text-lg font-bold">安装扫描引擎</h2>
          <p className="text-xs text-muted-foreground">
            一键下载全部 12 个扫描器（约 1.6 GB），首次安装完成后即可开始安全分析。
          </p>
        </div>

        {/* Scanner list */}
        <div className="rounded-lg border border-border divide-y divide-border">
          {BUNDLED_SCANNERS.map(sc => (
            <div key={sc.name} className="flex items-center justify-between px-3 py-1.5">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-3 w-3 text-emerald-500 opacity-40" />
                <span className="text-xs">{sc.label}</span>
                <span className="text-[10px] text-muted-foreground">{sc.desc}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Proxy */}
        <div className="rounded-lg border border-border p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Settings className="h-3.5 w-3.5 text-muted-foreground" />
              <span className="text-xs font-medium">网络代理</span>
              <span className="text-[9px] text-muted-foreground">（GitHub 下载需要时开启）</span>
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

        {/* Actions */}
        <div className="flex flex-col gap-2">
          <button
            onClick={handleInstall}
            className="rounded-lg bg-primary px-4 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            下载并安装全部扫描器
          </button>
          <button
            onClick={() => { onFinish() }}
            className="rounded-lg bg-secondary px-4 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            跳过，稍后安装
          </button>
        </div>
      </div>
    </div>
  )
}
