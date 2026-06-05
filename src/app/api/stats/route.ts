import { NextResponse } from "next/server"
import { getAllSessions } from "@/lib/scanner/scan-store"

export async function GET() {
  await new Promise(r => setTimeout(r, 200))

  const sessions = getAllSessions()
  const completedScans = sessions.filter(s => s.status === "completed")
  const totalScans = sessions.length
  const totalVulnerabilities = completedScans.reduce((sum, s) => sum + s.vulnerabilities.length, 0)
  const secure = completedScans.filter(s => s.riskScore === "A" || s.riskScore === "B").length

  // Calculate weighted risk score across all completed scans
  const riskValues: Record<string, number> = { A: 95, B: 80, C: 65, D: 45, F: 25 }
  const avgRisk = completedScans.length > 0
    ? Math.round(completedScans.reduce((sum, s) => sum + (riskValues[s.riskScore] || 50), 0) / completedScans.length)
    : 85
  const avgRiskLetter = avgRisk >= 90 ? "A" : avgRisk >= 75 ? "B" : avgRisk >= 60 ? "C" : avgRisk >= 45 ? "D" : "F"

  return NextResponse.json({
    totalScans,
    totalVulnerabilities,
    secure,
    riskScore: `${avgRiskLetter}+${completedScans.length > 0 ? "" : ""}`,
    scanChange: totalScans > 0 ? "活跃" : "无数据",
    vulnChange: totalVulnerabilities > 0 ? `+${totalVulnerabilities}` : "0",
    secureChange: totalScans > 0 ? `${Math.round((secure / Math.max(1, completedScans.length)) * 100)}%` : "—",
    riskChange: avgRiskLetter === "A" || avgRiskLetter === "B" ? "低风险" : avgRiskLetter === "C" ? "中等风险" : "高风险",
  })
}
