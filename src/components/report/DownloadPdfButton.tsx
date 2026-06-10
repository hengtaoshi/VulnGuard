"use client"

import { useState, useRef } from "react"
import { FileDown, Loader2, AlertCircle, Download } from "lucide-react"

interface Props {
  scanId: string
  variant?: "nav" | "prominent"
}

/**
 * PDF-optimized section capture.
 * Captures each report section individually so we can insert clean page breaks
 * between them, preventing charts/tables from being split mid-section.
 */
const SECTION_IDS = ["summary", "methodology", "crawl", "scanners", "aggregation", "findings", "analysis"]

export function DownloadPdfButton({ scanId, variant = "nav" }: Props) {
  const [state, setState] = useState<"idle" | "generating" | "error">("idle")
  const [progress, setProgress] = useState("")
  const errorTimerRef = useRef<ReturnType<typeof setTimeout>>()

  function expandAll(container: HTMLElement) {
    container.querySelectorAll<HTMLDetailsElement>("details").forEach(d => (d.open = true))
    container.querySelectorAll<HTMLButtonElement>("button[aria-expanded='false']").forEach(b => b.click())
  }

  function collapseAll(container: HTMLElement) {
    container.querySelectorAll<HTMLDetailsElement>("details").forEach(d => (d.open = false))
  }

  const handleDownload = async () => {
    if (state === "generating") return
    setState("generating")
    setProgress("准备报告中...")

    const stickyNav = document.querySelector<HTMLElement>('[class*="sticky top-0 z-10"]')
    try {
      const [html2canvasModule, jsPDFModule] = await Promise.all([
        import("html2canvas"),
        import("jspdf"),
      ])
      const html2canvas = html2canvasModule.default
      const { default: jsPDF } = jsPDFModule

      const reportEl = document.getElementById("security-report")
      if (!reportEl) throw new Error("报告元素未找到")

      // ── 1. Prepare: expand all collapsible content ─────────────
      expandAll(reportEl)
      await new Promise(r => setTimeout(r, 500))

      // ── 2. Hide the sticky nav bar ────────────────────────────
      const navOrigDisplay = stickyNav?.style.display
      if (stickyNav) stickyNav.style.display = "none"

      // ── 3. Wait for fonts to settle before capture ──────────
      await document.fonts.ready
      // Give layout one extra frame to stabilize after fonts load
      await new Promise(r => requestAnimationFrame(() => setTimeout(r, 100)))

      // ── 4. Capture sections individually ──────────────────────
      const pdf = new jsPDF("p", "mm", "a4")
      const pw = pdf.internal.pageSize.getWidth()
      const ph = pdf.internal.pageSize.getHeight()
      const margin = 8
      const pageContentH = ph - 2 * margin
      const sectionGap = 8

      let lastPageRemaining = 0
      let sectionCount = 0

      for (const sectionId of SECTION_IDS) {
        const el = document.getElementById(sectionId)
        if (!el) continue // skip if section doesn't exist (e.g. conditional sections)
        if (el.offsetHeight === 0) continue // skip empty/not-visible sections

        sectionCount++
        setProgress(`处理第 ${sectionCount} 个部分: ${sectionId}...`)

        // Small pause between sections so browser can repaint
        await new Promise(r => setTimeout(r, 150))

        // Capture at 4x scale for crisp text on A4 — the higher the scale,
        // the more detail survives when downscaled to PDF dimensions.
        // We use PNG (lossless) so text edges stay razor-sharp.
        const canvas = await html2canvas(el, {
          scale: 4,
          useCORS: true,
          logging: false,
          allowTaint: false,
          width: el.scrollWidth,
          height: el.scrollHeight,
          windowWidth: el.scrollWidth,
          windowHeight: el.scrollHeight,
        })

        const imgData = canvas.toDataURL("image/png")
        const imgW = pw - 2 * margin
        const imgH = (canvas.height * imgW) / canvas.width

        // Check if this section fits on the current page
        const needsPageBreak = lastPageRemaining > 0 && (imgH + sectionGap) > lastPageRemaining

        if (needsPageBreak) {
          pdf.addPage()
          lastPageRemaining = pageContentH
        }

        // Calculate y position: if we're starting a new page, start at margin;
        // otherwise, continue from where we left off (after the previous section + gap)
        const yPos = lastPageRemaining === pageContentH || lastPageRemaining === 0
          ? margin
          : ph - margin - lastPageRemaining + sectionGap

        pdf.addImage(imgData, "PNG", margin, yPos, imgW, imgH)

        // Update remaining space after this section
        const sectionHeight = yPos + imgH
        lastPageRemaining = Math.max(0, ph - margin - sectionHeight)
      }

      // ── 5. Restore UI ──────────────────────────────────────────
      if (stickyNav) stickyNav.style.display = navOrigDisplay || ""
      collapseAll(reportEl)

      pdf.save(`vuln-guard-report-${scanId}.pdf`)
      setState("idle")
      setProgress("")
    } catch (err) {
      console.error("PDF generation failed:", err)
      if (stickyNav) stickyNav.style.display = "" // restore nav even on error
      setState("error")
      clearTimeout(errorTimerRef.current)
      errorTimerRef.current = setTimeout(() => setState("idle"), 4000)
    }
  }

  // ─── Prominent variant ─────────────────────────────────────────────────
  if (variant === "prominent") {
    return (
      <div className="relative overflow-hidden rounded-xl border border-violet-500/20 bg-gradient-to-br from-violet-500/[0.03] via-violet-500/[0.01] to-background">
        {/* Decorative top bar */}
        <div className="h-1 w-full bg-gradient-to-r from-violet-600/50 via-violet-500/30 to-violet-400/10" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 sm:p-6">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-violet-500/5 flex items-center justify-center ring-1 ring-violet-500/20 shrink-0">
              {state === "generating" ? (
                <Loader2 className="h-6 w-6 text-violet-500 animate-spin" />
              ) : (
                <FileDown className="h-6 w-6 text-violet-500" />
              )}
            </div>
            <div>
              <h3 className="font-semibold text-base text-foreground">
                {state === "generating" ? "正在生成 PDF..." : "导出 PDF 报告"}
              </h3>
              <p className="text-xs text-muted-foreground mt-0.5">
                {state === "generating"
                  ? (progress || "正在逐节处理报告内容...")
                  : "安全扫描报告 · 逐节捕捉 · 自动分页 · " + SECTION_IDS.length + " 个章节"}
              </p>
            </div>
          </div>
          <button
            onClick={handleDownload}
            disabled={state === "generating"}
            className="relative inline-flex items-center justify-center gap-2.5 px-6 py-2.5 rounded-xl shrink-0
              bg-gradient-to-r from-violet-600 to-violet-500
              hover:from-violet-500 hover:to-violet-400
              text-white font-semibold text-sm
              shadow-lg shadow-violet-500/25 hover:shadow-violet-500/40
              transition-all duration-200 active:scale-[0.97]
              disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100
              disabled:hover:from-violet-600 disabled:hover:to-violet-500"
          >
            {state === "generating" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                {progress || "处理中..."}
              </>
            ) : (
              <>
                <Download className="h-4 w-4" />
                下载报告
              </>
            )}
          </button>
        </div>
        {/* Error state */}
        {state === "error" && (
          <div className="mx-5 mb-4 sm:mx-6 sm:mb-5 flex items-center gap-2.5 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-xs rounded-lg">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            <span>PDF 生成失败，请使用页面顶部的「Print → 另存为 PDF」</span>
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
        disabled={state === "generating"}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-full hover:bg-accent transition-colors disabled:opacity-50"
      >
        {state === "generating" ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <FileDown className="h-3 w-3" />
        )}
        {state === "generating" ? (progress ? progress : "生成 PDF...") : "PDF"}
      </button>

      {state === "error" && (
        <div className="absolute top-full right-0 mt-2 z-50 flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-xs rounded-lg shadow-lg whitespace-nowrap">
          <AlertCircle className="h-3 w-3 shrink-0" />
          <span>PDF 生成失败，请使用「Print → 另存为 PDF」</span>
        </div>
      )}
    </div>
  )
}
