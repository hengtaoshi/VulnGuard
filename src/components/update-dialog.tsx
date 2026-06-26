"use client"

import { useEffect, useState, useCallback, useRef } from "react"
import { Download, Loader2, CheckCircle2, X, AlertTriangle } from "lucide-react"

interface UpdateInfo {
  version: string
  currentVersion: string
}

interface UpdateDialogProps {
  open: boolean
  onClose: () => void
  info: UpdateInfo | null
  error?: string | null
  onRetry?: () => void
}

export function UpdateDialog({ open, onClose, info, error, onRetry }: UpdateDialogProps) {
  const [downloading, setDownloading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [done, setDone] = useState(false)
  const [dlError, setDlError] = useState<string | null>(null)

  // 用 ref 记录历史最大进度，防止 electron-updater 的 progress.percent 因重定向/断点续传回退
  const maxProgressRef = useRef(0)

  useEffect(() => {
    if (!open) {
      setDownloading(false)
      setProgress(0)
      setDone(false)
      setDlError(null)
      maxProgressRef.current = 0
    }
  }, [open])

  useEffect(() => {
    const vg = window.vulnguard
    if (!vg || !open) return

    const unsubProgress = vg.onUpdateProgress((p) => {
      // 只进不退：用 ref 确保历史的最高值不被覆盖
      if (p.percent > maxProgressRef.current) {
        maxProgressRef.current = p.percent
        setProgress(p.percent)
      }
    })
    const unsubDone = vg.onUpdateDownloaded(() => {
      maxProgressRef.current = 100
      setProgress(100)
      setDone(true)
      setDownloading(false)
    })

    return () => {
      unsubProgress()
      unsubDone()
    }
  }, [open])

  const handleUpdate = useCallback(async () => {
    if (!window.vulnguard) return
    setDownloading(true)
    setDlError(null)
    try {
      const res = await window.vulnguard.startUpdate()
      if (!res.ok) {
        setDlError(res.error || "下载失败")
        setDownloading(false)
      }
    } catch {
      setDlError("下载失败")
      setDownloading(false)
    }
  }, [])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />

      {/* Dialog */}
      <div className="relative bg-card border border-border rounded-xl shadow-2xl max-w-sm w-full mx-4 p-6 space-y-4 animate-in fade-in zoom-in-95 duration-200">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 text-muted-foreground hover:text-foreground transition-colors"
        >
          <X className="h-4 w-4" />
        </button>

        {error ? (
          <>
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-destructive/10 p-2">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>
              <div>
                <h3 className="font-semibold text-sm">检查更新失败</h3>
                <p className="text-xs text-muted-foreground mt-0.5">{error}</p>
              </div>
            </div>
            {onRetry && (
              <button
                onClick={onRetry}
                className="w-full rounded-lg bg-primary/10 py-2 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
              >
                重试
              </button>
            )}
          </>
        ) : done ? (
          <>
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-emerald-500/10 p-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
              </div>
              <div>
                <h3 className="font-semibold text-sm">更新已就绪</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  应用即将重启安装 <strong>v{info?.version}</strong>
                </p>
              </div>
            </div>
          </>
        ) : downloading ? (
          <>
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-primary/10 p-2">
                <Loader2 className="h-5 w-5 text-primary animate-spin" />
              </div>
              <div>
                <h3 className="font-semibold text-sm">正在下载更新</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  <strong>v{info?.version}</strong> — {progress}%
                </p>
              </div>
            </div>
            {/* Progress bar */}
            <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all duration-300 ease-out"
                style={{ width: `${progress}%` }}
              />
            </div>
            {dlError && (
              <p className="text-xs text-destructive">{dlError}</p>
            )}
          </>
        ) : info ? (
          <>
            <div className="flex items-center gap-3">
              <div className="rounded-full bg-primary/10 p-2">
                <Download className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold text-sm">发现新版本</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  v{info.currentVersion} → <strong className="text-foreground">v{info.version}</strong>
                </p>
              </div>
            </div>
            <div className="flex gap-2 pt-1">
              <button
                onClick={handleUpdate}
                className="flex-1 rounded-lg bg-primary px-3 py-2 text-xs font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
              >
                立即更新
              </button>
              <button
                onClick={onClose}
                className="flex-1 rounded-lg border border-border px-3 py-2 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                稍后再说
              </button>
            </div>
          </>
        ) : null}
      </div>
    </div>
  )
}
