import { NextResponse } from "next/server"
import { addIgnoreRule, removeIgnoreRule, getAllIgnoreRules, getVulnKey } from "@/lib/ignore-rules"
import { getSession } from "@/lib/scanner/scan-store"
import { requireAuth } from "@/lib/api/auth"

/**
 * POST /api/scans/[id]/suppress
 * 标记某个漏洞为误报
 * Body: { scanner?: string, cve?: string, id?: string, comment?: string }
 */
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

  try {
    const body = await request.json()
    const { scanner, cve, id: vulnId, comment } = body

    // 构建忽略规则: scanner:value
    let pattern = ""
    if (cve && cve !== "—" && cve !== "CVE-Pending") {
      pattern = `${scanner || "*"}:${cve}`
    } else if (vulnId) {
      pattern = `${scanner || "*"}:${vulnId}`
    } else {
      return NextResponse.json({ error: "Missing cve or id in request body" }, { status: 400 })
    }

    const rules = addIgnoreRule(pattern, comment || `Marked false positive in scan ${params.id}`)

    return NextResponse.json({
      success: true,
      pattern,
      rules: rules.length,
    })
  } catch (err) {
    return NextResponse.json({ error: "Failed to add ignore rule" }, { status: 500 })
  }
}

/**
 * DELETE /api/scans/[id]/suppress?pattern=trivy:CVE-2024-12345
 * 移除某个忽略规则
 */
export async function DELETE(
  request: Request,
  { params }: { params: { id: string } },
) {
  const auth = requireAuth(request)
  if (auth) return auth

  const pattern = new URL(request.url).searchParams.get("pattern")
  if (!pattern) {
    return NextResponse.json({ error: "Missing pattern query parameter" }, { status: 400 })
  }

  const rules = removeIgnoreRule(pattern)
  return NextResponse.json({ success: true, rules: rules.length })
}

/**
 * GET /api/scans/[id]/suppress
 * 获取当前所有忽略规则
 */
export async function GET(
  request: Request,
  { params }: { params: { id: string } },
) {
  const auth = requireAuth(request)
  if (auth) return auth

  const rules = getAllIgnoreRules()
  return NextResponse.json({ rules })
}
