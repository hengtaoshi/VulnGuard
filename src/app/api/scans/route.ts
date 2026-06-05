import { NextResponse } from "next/server"
import { getAllSessions, toScanSummary, createSession, updateSession } from "@/lib/scanner/scan-store"
import { runCompositeScan } from "@/lib/scanner/composite"

export async function GET() {
  const scans = getAllSessions().map(toScanSummary)
  await new Promise(r => setTimeout(r, 200))
  return NextResponse.json(scans)
}

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const mode = body.mode || "source"
    const target = body.target || body.url || "unknown"

    // Create scan session
    const session = createSession(mode, target)
    updateSession(session.id, { status: "pending" })

    // Run composite scan in the background (don't await)
    runCompositeScan(target, mode, session.id)
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

        updateSession(session.id, {
          status: "completed",
          riskScore,
          totalChecks,
          summary: { critical, high, medium, low, passed: Math.max(0, totalChecks - totalVulns) },
          vulnerabilities,
          scanners: scannerResults,
          progress: undefined,
        })
      })
      .catch(scanErr => {
        updateSession(session.id, { status: "failed", error: (scanErr as Error).message })
      })

    // Return immediately with the session ID
    return NextResponse.json(
      { id: session.id, status: "pending", target: session.target, type: session.type },
      { status: 201 },
    )
  } catch (err) {
    console.error("Create scan error:", err)
    return NextResponse.json({ error: "Failed to create scan" }, { status: 500 })
  }
}
