"use client"

import { useState, useEffect } from "react"
import { Download, Loader2, CheckCircle2 } from "lucide-react"

interface UpdateInfo {
  version: string
}

declare global {
  interface Window {
    vulnguard?: {
      checkForUpdates: () => Promise<{ ok: boolean; canUpdate?: boolean; version?: string; error?: string }>
      startUpdate: () => Promise<{ ok: boolean; error?: string }>
      onUpdateAvailable: (cb: (info: UpdateInfo) => void) => () => void
      onUpdateProgress: (cb: (p: { percent: number }) => void) => () => void
      onUpdateDownloaded: (cb: () => void) => () => void
    }
  }
}

export function UpdateBanner() {
  const [update, setUpdate] = useState<UpdateInfo | null>(null)
  const [dismissed, setDismissed] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const vg = window.vulnguard
    if (!vg) return

    const unsubAvailable = vg.onUpdateAvailable((info) => {
      setUpdate(info)
    })

    return () => {
      unsubAvailable()
    }
  }, [])

  useEffect(() => {
    const vg = window.vulnguard
    if (!vg) return

    const unsubProgress = vg.onUpdateProgress((p) => setProgress(p.percent))
    const unsubDone = vg.onUpdateDownloaded(() => {
      setDone(true)
      setDownloading(false)
    })

    return () => {
      unsubProgress()
      unsubDone()
    }
  }, [])

  if (!update || dismissed || done) return null

  const handleUpdate = async () => {
    setDownloading(true)
    setError(null)
    try {
      const res = await window.vulnguard!.startUpdate()
      if (!res.ok) {
        setError(res.error || "下载失败")
        setDownloading(false)
      }
    } catch {
      setError("下载失败")
      setDownloading(false)
    }
  }

  return (
    <div className="flex items-center justify-between gap-4 border-b border-primary/20 bg-primary/5 px-4 py-2 text-sm md:px-6">
      <div className="flex items-center gap-2">
        {done ? (
          <CheckCircle2 className="h-4 w-4 text-emerald-500" />
        ) : (
          <Download className="h-4 w-4 text-primary" />
        )}
        {done ? (
          <span>
            已就绪，即将重启安装 <strong>v{update.version}</strong>
          </span>
        ) : downloading ? (
          <span>
            正在下载 <strong>v{update.version}</strong>… {progress}%
          </span>
        ) : (
          <span>
            新版本 <strong>v{update.version}</strong> 可用
          </span>
        )}
        {error && <span className="text-destructive text-xs">{error}</span>}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {downloading ? (
          <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
        ) : (
          <>
            <button
              onClick={handleUpdate}
              className="rounded-md bg-primary px-3 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90"
            >
              立即更新
            </button>
            <button
              onClick={() => setDismissed(true)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              暂不更新
            </button>
          </>
        )}
      </div>
    </div>
  )
}
