import { NextResponse } from "next/server"
import { getSession } from "@/lib/scanner/scan-store"
import { compareWithBaseline } from "@/lib/scanner/baseline"
import { requireAuth } from "@/lib/api/auth"

/**
 * GET /api/scans/[id]/compare
 * 对比当前扫描与前一次扫描，识别新增/已修复/回归漏洞
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params
  const auth = requireAuth(request)
  if (auth) return auth

  const session = getSession(id)
  if (!session) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  if (session.status !== "completed") {
    return NextResponse.json({ error: "Scan not yet completed" }, { status: 400 })
  }

  const result = compareWithBaseline(
    id,
    session.target,
    session.vulnerabilities,
  )

  return NextResponse.json(result)
}
