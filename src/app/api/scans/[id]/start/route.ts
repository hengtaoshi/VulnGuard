import { NextResponse } from "next/server"
import { getSession, updateSession, cleanupUploadDir } from "@/lib/scanner/scan-store"
import { runCompositeScan } from "@/lib/scanner/composite"
import type { ScannerEngine } from "@/lib/scanner/composite"
import { requireAuth } from "@/lib/api/auth"

export async function POST(
  request: Request,
  { params }: { params: { id: string } },
) {
  const auth = requireAuth(request)
  if (auth) return auth

  const session = getSession(params.id)
  if (!session) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  if (session.status !== "pending") {
    return NextResponse.json({ error: "Scan already started or completed" }, { status: 400 })
  }

  // Mark as scanning immediately
  updateSession(params.id, { status: "scanning" })

  const target = session.target
  const engine: ScannerEngine = session.scannerEngine || "ai"

  // Run composite scan in the background (don't await)
  runCompositeScan(target, "source", params.id, engine)
    .then(result => {
      const { vulnerabilities, totalChecks, scannerResults } = result
      const critical = vulnerabilities.filter(v => v.severity === "Critical").length
      const high = vulnerabilities.filter(v => v.severity === "High").length
      const medium = vulnerabilities.filter(v => v.severity === "Medium").length
      const low = vulnerabilities.filter(v => v.severity === "Low").length

      const totalVulns = vulnerabilities.length
      let riskScore = "A"
      if (critical > 0) riskScore = "F"
      else if (high > 2) riskScore = "D"
      else if (high > 0) riskScore = "C"
      else if (medium > 3) riskScore = "B"

      updateSession(params.id, {
        status: "completed",
        riskScore,
        totalChecks,
        summary: { critical, high, medium, low, passed: Math.max(0, totalChecks - totalVulns) },
        vulnerabilities,
        scanners: scannerResults,
        progress: undefined,
      })
      cleanupUploadDir(target)
    })
    .catch(scanErr => {
      updateSession(params.id, { status: "failed", error: (scanErr as Error).message })
      cleanupUploadDir(target)
    })

  return NextResponse.json({ status: "scanning" })
}
