"use client"

import { createContext, useContext, useState, useCallback, useRef, useEffect, type ReactNode } from "react"
import { Download, CheckCircle2, AlertCircle } from "lucide-react"

// ─── Types ─────────────────────────────────────────────────────────────────

interface InstallProgress {
  percent: number
  bytes?: number
  total?: number
  error?: string
  done?: boolean
}

interface InstallContextValue {
  /** Whether installation is currently in progress */
  installing: boolean
  /** Monotonic display percentage (0-100) */
  displayPct: number
  /** Completed scanner names */
  completed: string[]
  /** Failed scanner names */
  failed: string[]
  /** Whether the detail overlay is expanded */
  expanded: boolean
  /** Start installation for a set of scanner names */
  startInstall: (scannerNames: string[]) => void
  /** Toggle expanded/collapsed state */
  setExpanded: (v: boolean) => void
  /** Reset back to idle */
  reset: () => void
  /** Update installation progress (called by SetupWizard) */
  _updateProgress: (pct: number) => void
  /** Mark a scanner as completed/failed */
  _markDone: (name: string, ok: boolean, errorMsg?: string) => void
  /** Error details per failed scanner */
  failedErrors: Record<string, string>
}

const InstallContext = createContext<InstallContextValue | null>(null)

export function useInstallProgress() {
  const ctx = useContext(InstallContext)
  if (!ctx) throw new Error("useInstallProgress must be used within InstallProgressProvider")
  return ctx
}

// ─── Floating Ball Component ───────────────────────────────────────────────

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
      <div className={`absolute inset-0 rounded-full ${done ? "bg-emerald-500/20" : error ? "bg-red-500/20" : "bg-primary/20"} animate-ping opacity-75`} />
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

// ─── Expanded Detail Overlay ───────────────────────────────────────────────

function InstallDetailOverlay({
  displayPct, currentLabel, doneCount, total,
  error, completed, failed, failedErrors, onMinimize, onFinish,
}: {
  displayPct: number
  currentLabel: string
  doneCount: number
  total: number
  error: string | null
  completed: string[]
  failed: string[]
  failedErrors: Record<string, string>
  onMinimize: () => void
  onFinish: () => void
}) {
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <div className="w-full max-w-xl mx-auto p-8 relative">
        <div className="absolute top-4 right-4 flex gap-2">
          <button
            onClick={onMinimize}
            className="rounded-full p-2 text-muted-foreground hover:text-foreground hover:bg-secondary transition-colors"
            title="最小化到悬浮球"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          <button
            onClick={onFinish}
            className="rounded-full p-2 text-muted-foreground hover:text-foreground hover:bg-secondary transition-colors"
            title="关闭"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="text-center space-y-4 mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-primary/10">
            <Download className="h-7 w-7 text-primary animate-bounce" />
          </div>
          <h2 className="text-lg font-bold">正在安装扫描器</h2>
          <p className="text-sm text-muted-foreground">
            {doneCount}/{total} — {currentLabel}
          </p>
        </div>

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

        <div className="space-y-1.5 max-h-40 overflow-y-auto">
          {completed.map((name) => (
            <div key={name} className="flex items-center gap-2 text-sm text-emerald-500">
              <CheckCircle2 className="h-3.5 w-3.5" />
              {name}
            </div>
          ))}
          {failed.map((name) => (
            <div key={name} className="flex items-start gap-2 text-sm text-destructive">
              <AlertCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              <div>
                <span>{name}</span>
                {failedErrors[name] && (
                  <p className="text-[10px] text-destructive/70 mt-0.5">{failedErrors[name]}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Provider ──────────────────────────────────────────────────────────────

export function InstallProgressProvider({ children }: { children: ReactNode }) {
  const [installing, setInstalling] = useState(false)
  const [displayPct, setDisplayPct] = useState(0)
  const [completed, setCompleted] = useState<string[]>([])
  const [failed, setFailed] = useState<string[]>([])
  const [failedErrors, setFailedErrors] = useState<Record<string, string>>({})
  const [expanded, setExpanded] = useState(false)
  const [currentLabel, setCurrentLabel] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [totalScanners, setTotalScanners] = useState(0)
  const [doneRef, setDoneRef] = useState(0)

  const _updateProgress = useCallback((pct: number) => {
    setDisplayPct(prev => Math.max(prev, pct))
  }, [])

  const _markDone = useCallback((name: string, ok: boolean, errorMsg?: string) => {
    if (ok) {
      setCompleted(prev => [...prev, name])
    } else {
      setFailed(prev => [...prev, name])
      if (errorMsg) setFailedErrors(prev => ({ ...prev, [name]: errorMsg }))
    }
  }, [])

  const startInstall = useCallback((scannerNames: string[]) => {
    setInstalling(true)
    setExpanded(false)
    setDisplayPct(0)
    setCompleted([])
    setFailed([])
    setFailedErrors({})
    setError(null)
    setCurrentLabel("准备中...")
    setTotalScanners(scannerNames.length)
    setDoneRef(0)
  }, [])

  const reset = useCallback(() => {
    setInstalling(false)
    setDisplayPct(0)
    setCompleted([])
    setFailed([])
    setFailedErrors({})
    setExpanded(false)
    setError(null)
    setTotalScanners(0)
  }, [])

  // Track done count for detail overlay
  useEffect(() => {
    setDoneRef(completed.length + failed.length)
  }, [completed.length, failed.length])

  const done = totalScanners > 0 && doneRef === totalScanners
  const hasError = failed.length > 0 && completed.length === 0

  return (
    <InstallContext.Provider value={{
      installing, displayPct, completed, failed, expanded,
      startInstall, setExpanded, reset,
      _updateProgress, _markDone, failedErrors,
    }}>
      {children}

      {/* Floating progress ball — always rendered at layout level */}
      {installing && (
        <>
          <CircularProgressBall
            percent={displayPct}
            onClick={() => setExpanded(v => !v)}
            done={done}
            error={hasError}
          />
          {expanded && (
            <InstallDetailOverlay
              displayPct={displayPct}
              currentLabel={currentLabel}
              doneCount={doneRef}
              total={totalScanners}
              error={error}
              completed={completed}
              failed={failed}
              failedErrors={failedErrors}
              onMinimize={() => setExpanded(false)}
              onFinish={reset}
            />
          )}
        </>
      )}
    </InstallContext.Provider>
  )
}
