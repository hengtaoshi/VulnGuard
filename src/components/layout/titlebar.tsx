"use client"

import { useState, useEffect } from "react"
import { Shield } from "lucide-react"

const DRAG = { WebkitAppRegion: "drag" } as React.CSSProperties
const NO_DRAG = { WebkitAppRegion: "no-drag" } as React.CSSProperties

export function TitleBar() {
  const [maximized, setMaximized] = useState(false)
  const [isElectron, setIsElectron] = useState(false)

  useEffect(() => {
    if (typeof window === "undefined") return
    const wc = window.vulnguard?.windowControls
    if (!wc) return
    setIsElectron(true)
    wc.isMaximized().then(setMaximized)
    const unsub = wc.onMaximizeChange(setMaximized)
    return unsub
  }, [])

  const handleDoubleClick = () => {
    window.vulnguard?.windowControls.maximize()
  }

  if (!isElectron) return null

  return (
    <header
      className="flex h-9 shrink-0 items-center justify-between bg-background border-b select-none"
      style={DRAG}
      onDoubleClick={handleDoubleClick}
    >
      <div className="flex items-center gap-2 px-3 min-w-0">
        <Shield className="h-4 w-4 shrink-0 text-primary" />
        <span className="text-xs font-medium truncate">VulnGuard Security Scanner</span>
      </div>

      <div className="flex h-full" style={NO_DRAG}>
        <button
          onClick={() => window.vulnguard?.windowControls.minimize()}
          className="flex items-center justify-center w-11 h-full text-muted-foreground hover:bg-secondary/80 active:bg-secondary transition-colors"
          aria-label="最小化"
        >
          <svg width="10" height="10" viewBox="0 0 10 10"><path d="M1 5h8" stroke="currentColor" strokeWidth="1.2" fill="none" /></svg>
        </button>

        <button
          onClick={() => window.vulnguard?.windowControls.maximize()}
          className="flex items-center justify-center w-11 h-full text-muted-foreground hover:bg-secondary/80 active:bg-secondary transition-colors"
          aria-label={maximized ? "还原" : "最大化"}
        >
          {maximized ? (
            <svg width="10" height="10" viewBox="0 0 10 10">
              <rect x="1.5" y="3.5" width="6" height="6" rx="0.5" stroke="currentColor" strokeWidth="1" fill="none" />
              <path d="M2.5 3.5V2a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 .5.5v5a.5.5 0 0 1-.5.5H7" stroke="currentColor" strokeWidth="1" fill="none" />
            </svg>
          ) : (
            <svg width="10" height="10" viewBox="0 0 10 10">
              <rect x="1" y="1" width="8" height="8" rx="0.5" stroke="currentColor" strokeWidth="1" fill="none" />
            </svg>
          )}
        </button>

        <button
          onClick={() => window.vulnguard?.windowControls.close()}
          className="flex items-center justify-center w-11 h-full text-muted-foreground hover:bg-destructive hover:text-destructive-foreground active:bg-destructive/90 transition-colors"
          aria-label="关闭"
        >
          <svg width="10" height="10" viewBox="0 0 10 10">
            <path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" strokeWidth="1.2" fill="none" />
          </svg>
        </button>
      </div>
    </header>
  )
}
