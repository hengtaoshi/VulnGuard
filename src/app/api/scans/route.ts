import { NextResponse } from "next/server"
import { getAllSessions, toScanSummary, createSession, updateSession, clearSessions, clearAllUploads, deleteSession } from "@/lib/scanner/scan-store"
import type { ScannerEngine } from "@/lib/scanner/composite"
import { requireAuth } from "@/lib/api/auth"
import { getSettings } from "@/lib/settings-store"

/** 根据 retentionDays 设置清理过期扫描 */
function cleanExpiredScans() {
  const { retentionDays } = getSettings()
  if (retentionDays <= 0) return
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000
  const sessions = getAllSessions()
  for (const s of sessions) {
    const created = new Date(s.createdAt).getTime()
    if (!isNaN(created) && created < cutoff) {
      deleteSession(s.id)
    }
  }
}

export async function GET(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  cleanExpiredScans()
  const scans = getAllSessions().map(toScanSummary)
  await new Promise(r => setTimeout(r, 200))
  return NextResponse.json(scans)
}

export async function POST(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  try {
    const body = await request.json()

    // Validate target
    const targetRaw = (body.target || body.url || "").trim()
    const target = targetRaw.slice(0, 1000) || "unknown"

    // Validate engine
    const VALID_ENGINES = new Set(["ai", "all"])
    const engineRaw = (body.engine || "ai").toLowerCase()
    const engine: ScannerEngine = VALID_ENGINES.has(engineRaw) ? (engineRaw as ScannerEngine) : "ai"

    // Validate mode
    const mode = body.mode === "url" ? "url" : "source"

    // Validate numeric fields
    const totalFiles = typeof body.totalFiles === "number" && body.totalFiles >= 0 ? body.totalFiles : undefined
    const skippedFiles = typeof body.skippedFiles === "number" && body.skippedFiles >= 0 ? body.skippedFiles : undefined

    // Validate project name (max 200 chars, no path separators)
    const projectName = body.projectName
      ? String(body.projectName).replace(/[/\\:]/g, "").slice(0, 200)
      : undefined

    // Create scan session (scan starts when detail page loads)
    const session = createSession(mode, target, { totalFiles, skippedFiles, projectName })
    updateSession(session.id, { status: "pending", scannerEngine: engine })

    // Return immediately with the session ID
    return NextResponse.json(
      { id: session.id, status: "pending", target: session.target, type: session.type, engine },
      { status: 201 },
    )
  } catch (err) {
    console.error("Create scan error:", err)
    return NextResponse.json({ error: "Failed to create scan" }, { status: 500 })
  }
}

export async function DELETE(request: Request) {
  clearSessions()
  clearAllUploads()
  return NextResponse.json({ success: true })
}
