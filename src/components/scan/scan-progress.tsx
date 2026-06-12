"use client"

import { useEffect, useRef } from "react"
import { CheckCircle2, Loader2, AlertCircle, Brain, Activity, Clock, Shield, File } from "lucide-react"
import type { ScanProgress } from "@/lib/api/types"
import { formatTime } from "@/lib/scan-utils"

// ─── Scanner Icons ─────────────────────────────────────────────────────────────

const scannerIcons: Record<string, React.ReactNode> = {
  semgrep: <Shield className="h-3 w-3" />,
  gitleaks: <Lock className="h-3 w-3" />,
  "npm-audit": <File className="h-3 w-3" />,
  "pip-audit": <File className="h-3 w-3" />,
  "dependency-check": <File className="h-3 w-3" />,
  trivy: <File className="h-3 w-3" />,
  checkov: <Shield className="h-3 w-3" />,
  nuclei: <Activity className="h-3 w-3" />,
}

function Lock({ className }: { className?: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
}

const defaultScannerIcon = <Shield className="h-3 w-3" />

// ─── Scan Progress View ────────────────────────────────────────────────────────

export function ScanProgressView({
  progress, engine, totalFiles, skippedFiles
}: {
  progress: ScanProgress | null
  engine?: string
  totalFiles?: number
  skippedFiles?: number
}) {
  const percent = progress?.percent ?? 0
  const currentScanner = progress?.currentScanner ?? ""
  const scannerStatuses = progress?.scannerStatuses ?? []
  const eta = progress?.eta ?? 0
  const elapsed = progress?.elapsed ?? 0

  const serverTsRef = useRef(Date.now())
  useEffect(() => { serverTsRef.current = Date.now() }, [elapsed, percent])

  const now = Date.now()
  const drift = now - serverTsRef.current
  const displayElapsed = elapsed + drift
  const displayEta = Math.max(0, eta - drift)
  const showEta = percent > 0 && percent < 100 && displayEta > 0
  const isOrchestrating = !currentScanner.includes("✓") && !currentScanner.includes("⚠️") && scannerStatuses.length === 0 && currentScanner.includes("orchestrator")
  const isFallback = currentScanner.includes("⚠️")
  const isAiAggregating = currentScanner.includes("AI aggregating") || currentScanner.includes("AI 聚合") || currentScanner.includes("DeepSeek")
  const isEscalating = currentScanner.includes("Dynamic escalation") || currentScanner.includes("动态升级")
  const isCrawling = currentScanner.includes("Crawling") || currentScanner.includes("🕷️")
  const isComplete = percent >= 100 && !isAiAggregating && !isEscalating
  const isScanning = !isFallback && !isAiAggregating && !isEscalating && !isComplete && !isCrawling && !isOrchestrating && percent > 0 && percent < 100

  const scannerRunning = scannerStatuses.filter(s => s.status === "running").length
  const scannerDone = scannerStatuses.filter(s => s.status === "completed" || s.status === "failed").length
  const scannerTotal = scannerStatuses.length

  const StatusIcon = ({ status }: { status: string }) => {
    switch (status) {
      case "completed":
        return <div className="h-5 w-5 rounded-full bg-emerald-500/20 flex items-center justify-center"><CheckCircle2 className="h-3 w-3 text-emerald-500" /></div>
      case "failed":
        return <div className="h-5 w-5 rounded-full bg-red-500/20 flex items-center justify-center"><AlertCircle className="h-3 w-3 text-red-500" /></div>
      case "running":
        return <div className="h-5 w-5 rounded-full bg-primary/20 flex items-center justify-center"><Loader2 className="h-3 w-3 text-primary animate-spin" /></div>
      default:
        return <div className="h-5 w-5 rounded-full bg-muted/50 flex items-center justify-center"><div className="h-2 w-2 rounded-full bg-muted-foreground/30" /></div>
    }
  }

  const runningName = currentScanner && !currentScanner.includes("✓") && !currentScanner.includes("⚠️")
    ? currentScanner.split(",")[0].trim()
    : (isAiAggregating ? "AI 聚合分析" : isOrchestrating ? "AI 编排决策" : "")

  return (
    <div className="w-full max-w-xl mx-auto">
      <div className="relative overflow-hidden rounded-2xl border border-border/60 bg-gradient-to-br from-card/90 via-card/50 to-muted/30 backdrop-blur-xl shadow-2xl shadow-black/10">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-3/4 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
        <div className="p-6 sm:p-8 space-y-6">
          <div className="flex items-center gap-5">
            <div className="relative shrink-0">
              <div className="relative h-16 w-16 flex items-center justify-center">
                <div className="absolute inset-0 rounded-full bg-primary/5 animate-ping" style={{ animationDuration: "2s" }} />
                <div className="absolute inset-2 rounded-full bg-primary/5 animate-ping" style={{ animationDuration: "2.5s", animationDelay: "0.5s" }} />
                <div className="absolute inset-4 rounded-full bg-primary/5 animate-ping" style={{ animationDuration: "3s", animationDelay: "1s" }} />
                <svg className="absolute inset-0 w-full h-full animate-spin" style={{ animationDuration: "3s" }} viewBox="0 0 64 64">
                  <defs>
                    <linearGradient id="radarGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.3" />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
                    </linearGradient>
                  </defs>
                  <path d="M32 32 L32 0 A32 32 0 0 1 64 32 Z" fill="url(#radarGrad)" />
                </svg>
                <div className="relative z-10 h-10 w-10 rounded-full bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center ring-1 ring-primary/20">
                  {isComplete ? (
                    <CheckCircle2 className="h-5 w-5 text-emerald-500" />
                  ) : isAiAggregating ? (
                    <Brain className="h-5 w-5 text-violet-500 animate-pulse" />
                  ) : isFallback ? (
                    <AlertCircle className="h-5 w-5 text-amber-500" />
                  ) : (
                    <Activity className="h-5 w-5 text-primary" />
                  )}
                </div>
              </div>
            </div>
            <div className="min-w-0 flex-1">
              <h2 className="text-lg font-bold tracking-tight">
                {isComplete ? "扫描完成" : isAiAggregating ? "AI 聚合分析中" : isFallback ? "回退模式" : "安全扫描进行中"}
              </h2>
              <p className="text-sm text-muted-foreground mt-0.5 truncate">
                {runningName ? (
                  <span className="flex items-center gap-1.5">
                    {!isComplete && !isAiAggregating && <span className="inline-block h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />}
                    {runningName}
                  </span>
                ) : isComplete ? (
                  "所有扫描器已完成"
                ) : isOrchestrating ? (
                  "AI 正在分析目标并选择扫描方案..."
                ) : (
                  "正在初始化扫描引擎..."
                )}
              </p>
            </div>
            <div className="shrink-0 text-right">
              <div className={`text-3xl font-black tabular-nums tracking-tighter ${isComplete ? "text-emerald-500" : "text-primary"}`}>
                {percent}<span className="text-lg font-medium text-muted-foreground">%</span>
              </div>
              <div className="text-[10px] text-muted-foreground/60 mt-0.5">
                {scannerDone}/{scannerTotal} 扫描器
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="h-2.5 bg-muted/80 rounded-full overflow-hidden ring-1 ring-border/30">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out relative ${
                  isComplete ? "bg-gradient-to-r from-emerald-500 to-emerald-400" :
                  isAiAggregating ? "bg-gradient-to-r from-violet-600 to-violet-400" :
                  isFallback ? "bg-gradient-to-r from-amber-500 to-amber-400" :
                  "bg-gradient-to-r from-primary via-primary/80 to-primary/60"
                }`}
                style={{ width: `${percent}%` }}
              >
                {!isComplete && (
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" style={{ backgroundSize: "200% 100%" }} />
                )}
              </div>
            </div>
            <div className="flex justify-between text-xs text-muted-foreground/70">
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {formatTime(displayElapsed) || "0s"}
              </span>
              <span>
                {showEta ? `剩余 ~${formatTime(displayEta)}` : isComplete ? "已完成" : "估算剩余时间..."}
              </span>
            </div>
          </div>

          {scannerStatuses.length > 0 && (
            <div className="space-y-0">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-3.5 w-3.5 text-muted-foreground/60" />
                <span className="text-xs font-medium text-muted-foreground/60 uppercase tracking-wider">扫描器执行状态</span>
              </div>
              <div className="relative">
                <div className="absolute left-[9px] top-2 bottom-2 w-px bg-border/60" />
                <div className="space-y-0">
                  {scannerStatuses.map((s, i) => {
                    const catColor: Record<string, string> = {
                      sast: "text-blue-500", secret: "text-red-500", dependency: "text-amber-500",
                      filesystem: "text-purple-500", ai: "text-violet-500",
                    }
                    const catBg: Record<string, string> = {
                      sast: "bg-blue-500/10", secret: "bg-red-500/10", dependency: "bg-amber-500/10",
                      filesystem: "bg-purple-500/10", ai: "bg-violet-500/10",
                    }
                    return (
                      <div key={s.scannerName} className="relative flex items-start gap-3 py-2 group">
                        <div className="relative z-10 mt-0.5">
                          <StatusIcon status={s.status} />
                        </div>
                        <div className="flex-1 min-w-0 flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className={`inline-flex items-center justify-center h-5 w-5 rounded ${catBg[s.category] || "bg-muted"}`}>
                              {scannerIcons[s.scannerName] || defaultScannerIcon}
                            </span>
                            <span className={`text-sm font-medium truncate ${s.status === "pending" ? "text-muted-foreground/50" : s.status === "failed" ? "text-red-500" : ""}`}>
                              {s.displayName}
                            </span>
                            {s.status === "running" && (
                              <span className="flex gap-0.5">
                                <span className="h-1 w-1 rounded-full bg-primary animate-bounce" style={{ animationDelay: "0ms" }} />
                                <span className="h-1 w-1 rounded-full bg-primary animate-bounce" style={{ animationDelay: "150ms" }} />
                                <span className="h-1 w-1 rounded-full bg-primary animate-bounce" style={{ animationDelay: "300ms" }} />
                              </span>
                            )}
                          </div>
                          <span className={`text-xs shrink-0 ${
                            s.status === "completed" ? "text-emerald-500 font-medium" :
                            s.status === "running" ? "text-primary" :
                            s.status === "failed" ? "text-red-500" :
                            "text-muted-foreground/40"
                          }`}>
                            {s.status === "completed" ? `${s.count} issues` :
                             s.status === "running" ? "扫描中..." :
                             s.status === "failed" ? "失败" :
                             "等待中"}
                          </span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {totalFiles && skippedFiles ? (
            <div className="flex items-center justify-center gap-1.5 text-[11px] text-muted-foreground/50 pt-1 border-t border-border/30">
              <File className="h-3 w-3" />
              {totalFiles} 个文件 · 过滤 {skippedFiles} 个非源码
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
