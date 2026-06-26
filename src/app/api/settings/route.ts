import { NextResponse } from "next/server"
import { getSettings, updateSettings, DEFAULT_SETTINGS } from "@/lib/settings-store"
import type { AppSettings } from "@/lib/settings-store"
import { requireAuth } from "@/lib/api/auth"

function validateSettings(body: Record<string, unknown>): Partial<AppSettings> {
  const valid: Partial<AppSettings> = {}
  const d = DEFAULT_SETTINGS

  if (typeof body.maxDuration === "number") valid.maxDuration = Math.max(5, Math.min(120, body.maxDuration))
  if (typeof body.autoReport === "boolean") valid.autoReport = body.autoReport
  if (body.defaultEngine === "ai" || body.defaultEngine === "all") valid.defaultEngine = body.defaultEngine
  if (typeof body.aiAggregation === "boolean") valid.aiAggregation = body.aiAggregation
  if (typeof body.concurrentScanners === "number") valid.concurrentScanners = Math.max(1, Math.min(16, body.concurrentScanners))
  if (typeof body.retentionDays === "number") valid.retentionDays = Math.max(0, Math.min(365, body.retentionDays))
  if (typeof body.deepseekApiKey === "string") valid.deepseekApiKey = body.deepseekApiKey
  if (typeof body.deepseekBaseUrl === "string") valid.deepseekBaseUrl = body.deepseekBaseUrl
  if (typeof body.deepseekModel === "string") valid.deepseekModel = body.deepseekModel
  if (typeof body.proxyEnabled === "boolean") valid.proxyEnabled = body.proxyEnabled
  if (typeof body.httpProxy === "string") valid.httpProxy = body.httpProxy
  if (typeof body.httpsProxy === "string") valid.httpsProxy = body.httpsProxy
  if (typeof body.webhookEnabled === "boolean") valid.webhookEnabled = body.webhookEnabled
  if (typeof body.webhookUrl === "string") valid.webhookUrl = body.webhookUrl
  if (Array.isArray(body.disabledScanners)) valid.disabledScanners = body.disabledScanners.filter(s => typeof s === "string")

  return valid
}

export async function GET(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  await new Promise(r => setTimeout(r, 100))
  return NextResponse.json(getSettings())
}

export async function PUT(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  try {
    const body = await request.json()
    const validated = validateSettings(body)
    const updated = updateSettings(validated)
    await new Promise(r => setTimeout(r, 100))
    return NextResponse.json(updated)
  } catch {
    return NextResponse.json(
      { error: "无效的设置数据" },
      { status: 400 },
    )
  }
}
