"use client"

import { useState, useEffect } from "react"
import { FileDown, Loader2, AlertCircle, Download } from "lucide-react"
import { generateReportHtml, openHtmlReport } from "@/lib/report-html"
import type { ReportData } from "@/lib/report-html"

interface Props {
  scanId: string
  variant?: "nav" | "prominent"
}

/** 从 scan data 生成默认文件名 */
function makePdfName(data: ReportData): string {
  const name = data.projectName || data.target?.split(/[/\\]/).filter(Boolean).pop() || "VulnGuard"
  const date = data.createdAt
    ? (() => {
        const d = new Date(data.createdAt!)
        const pad = (n: number) => String(n).padStart(2, "0")
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
      })()
    : new Date().toISOString().slice(0, 10)
  return `${name}_${date}_安全扫描报告.pdf`
}

export function DownloadPdfButton({ scanId, variant = "nav" }: Props) {
  const [state, setState] = useState<"idle" | "loading" | "error">("idle")
  const [isElectron, setIsElectron] = useState(false)

  useEffect(() => {
    setIsElectron(typeof window !== "undefined" && !!window.vulnguard?.downloadPdf)
  }, [])

  const handleDownload = async () => {
    if (state === "loading") return
    setState("loading")

    try {
      const res = await fetch(`/api/scans/${scanId}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: ReportData = await res.json()

      if (isElectron && window.vulnguard?.downloadPdf) {
        // ── Electron: 直出 PDF，无需弹窗 ──
        const html = generateReportHtml(data)
        const filename = makePdfName(data)
        const result = await window.vulnguard.downloadPdf(html, filename)
        if (!result?.ok && !result?.cancelled) throw new Error(result?.error || "导出失败")
      } else {
        // ── Web fallback: 开新标签 → 浏览器打印 → 另存 PDF ──
        openHtmlReport(data)
      }

      setState("idle")
    } catch (err) {
      console.error("Report generation failed:", err)
      setState("error")
      setTimeout(() => setState("idle"), 4000)
    }
  }

  // ─── Prominent variant ─────────────────────────────────────────────────
  if (variant === "prominent") {
    return (
      <div className="relative overflow-hidden rounded-xl border border-violet-500/20 bg-gradient-to-br from-violet-500/[0.03] via-violet-500/[0.01] to-background">
        <div className="h-1 w-full bg-gradient-to-r from-violet-600/50 via-violet-500/30 to-violet-400/10" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 sm:p-6">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-violet-500/5 flex items-center justify-center ring-1 ring-violet-500/20 shrink-0">
              {state === "loading" ? (
                <Loader2 className="h-6 w-6 text-violet-500 animate-spin" />
              ) : (
                <FileDown className="h-6 w-6 text-violet-500" />
              )}
            </div>
            <div>
              <h3 className="font-semibold text-base text-foreground">
                {state === "loading" ? "正在生成 PDF..." : "导出 PDF 报告"}
              </h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                {isElectron ? "直接保存 PDF，无需浏览器弹窗" : "生成独立 HTML → 浏览器打印 → 另存为 PDF"}
              </p>
            </div>
          </div>
          <button
            onClick={handleDownload}
            disabled={state === "loading"}
            className="relative inline-flex items-center justify-center gap-2.5 px-6 py-2.5 rounded-xl shrink-0
              bg-gradient-to-r from-violet-600 to-violet-500
              hover:from-violet-500 hover:to-violet-400
              text-white font-semibold text-sm
              shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40
              transition-all duration-200 active:scale-[0.97]
              disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100
              disabled:hover:from-violet-600 disabled:hover:to-violet-500"
          >
            {state === "loading" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                生成中...
              </>
            ) : (
              <>
                <Download className="h-4 w-4" />
                下载报告
              </>
            )}
          </button>
        </div>
        {state === "error" && (
          <div className="mx-5 mb-4 sm:mx-6 sm:mb-5 flex items-center gap-2.5 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-xs rounded-lg">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            <span>报告生成失败，请稍后重试</span>
          </div>
        )}
      </div>
    )
  }

  // ─── Nav variant ───────────────────────────────────────────────────────
  return (
    <div className="relative">
      <button
        onClick={handleDownload}
        disabled={state === "loading"}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-full hover:bg-accent transition-colors disabled:opacity-50"
      >
        {state === "loading" ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <FileDown className="h-3 w-3" />
        )}
        {state === "loading" ? "生成中..." : "PDF"}
      </button>

      {state === "error" && (
        <div className="absolute top-full right-0 mt-2 z-50 flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-xs rounded-lg shadow-lg whitespace-nowrap">
          <AlertCircle className="h-3 w-3 shrink-0" />
          <span>导出失败，请稍后重试</span>
        </div>
      )}
    </div>
  )
}
