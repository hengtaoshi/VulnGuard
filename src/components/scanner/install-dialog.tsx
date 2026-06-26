"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { Loader2, CheckCircle2, AlertCircle, Download, X, WifiOff } from "lucide-react"

interface InstallProgress {
  percent: number
  bytes?: number
  total?: number
  done?: boolean
  ok?: boolean
  error?: string
  scanner?: string
}

interface Props {
  scannerName: string
  scannerLabel: string
  open: boolean
  onClose: () => void
  onComplete: (ok: boolean) => void
}

type InstallState = "idle" | "installing" | "done" | "error"

export function InstallDialog({ scannerName, scannerLabel, open, onClose, onComplete }: Props) {
  const [state, setState] = useState<InstallState>("idle")
  const [progress, setProgress] = useState(0)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [isElectron, setIsElectron] = useState(false)
  const unsubRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    setIsElectron(typeof window !== "undefined" && !!window.vulnguard?.downloadScanner)
  }, [])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      unsubRef.current?.()
    }
  }, [])

  const startInstall = useCallback(async () => {
    setState("installing")
    setProgress(0)
    setErrorMsg(null)

    if (isElectron && window.vulnguard?.downloadScanner) {
      // Electron 模式：通过 IPC
      unsubRef.current = window.vulnguard.onScannerProgress((data: InstallProgress) => {
        if (data.error) {
          setErrorMsg(data.error)
          setState("error")
          return
        }
        setProgress(data.percent)
        if (data.done) {
          setState("done")
          onComplete(true)
        }
      })

      const result = await window.vulnguard.downloadScanner(scannerName)
      if (!result?.ok) {
        setErrorMsg(result?.error || "安装失败")
        setState("error")
      }
    } else {
      // Web 模式：通过 SSE API
      try {
        const res = await fetch("/api/scanners/install", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ scanner: scannerName }),
        })

        if (!res.ok) {
          const err = await res.json().catch(() => ({ error: "HTTP " + res.status }))
          throw new Error(err.error || "安装失败")
        }

        const reader = res.body?.getReader()
        if (!reader) throw new Error("无法读取响应流")

        const decoder = new TextDecoder()
        let buffer = ""

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split("\n")
          buffer = lines.pop() || ""

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6)) as InstallProgress
                if (data.error) {
                  setErrorMsg(data.error)
                  setState("error")
                  return
                }
                setProgress(data.percent)
                if (data.done) {
                  if (data.ok) {
                    setState("done")
                    onComplete(true)
                  } else {
                    setErrorMsg(data.error || "安装失败")
                    setState("error")
                  }
                  return
                }
              } catch { /* skip malformed SSE */ }
            }
          }
        }
      } catch (err: any) {
        setErrorMsg(err.message || "安装失败")
        setState("error")
      }
    }
  }, [scannerName, isElectron, onComplete])

  // Auto-start when dialog opens
  useEffect(() => {
    if (open && state === "idle") {
      startInstall()
    }
    if (!open) {
      setState("idle")
      setProgress(0)
      setErrorMsg(null)
      unsubRef.current?.()
    }
  }, [open, state, startInstall])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border bg-card p-6 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            {state === "installing" && <Download className="h-4 w-4 text-primary animate-bounce" />}
            {state === "done" && <CheckCircle2 className="h-4 w-4 text-emerald-500" />}
            {state === "error" && <AlertCircle className="h-4 w-4 text-destructive" />}
            <h3 className="text-sm font-semibold">
              {state === "idle" && `准备安装 ${scannerLabel}`}
              {state === "installing" && `正在安装 ${scannerLabel}`}
              {state === "done" && `${scannerLabel} 安装完成`}
              {state === "error" && `${scannerLabel} 安装失败`}
            </h3>
          </div>
          {state === "done" && (
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {/* Progress bar */}
        {state === "installing" && (
          <div className="space-y-2">
            <div className="h-2 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-primary transition-all duration-300 ease-out"
                style={{ width: `${Math.max(1, progress)}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>{progress}%</span>
              {!isElectron && <WifiOff className="h-3 w-3" />}
            </div>
          </div>
        )}

        {/* Error state */}
        {state === "error" && (
          <div className="space-y-3">
            <p className="text-xs text-destructive">{errorMsg}</p>
            <div className="flex gap-2">
              <button
                onClick={startInstall}
                className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
              >
                重试
              </button>
              <button
                onClick={onClose}
                className="rounded-md bg-secondary px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground"
              >
                关闭
              </button>
            </div>
          </div>
        )}

        {/* Done state */}
        {state === "done" && (
          <p className="text-xs text-muted-foreground">扫描器已就绪，可以开始使用</p>
        )}
      </div>
    </div>
  )
}
