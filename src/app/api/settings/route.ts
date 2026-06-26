import { NextResponse } from "next/server"
import { getSettings, updateSettings, DEFAULT_SETTINGS, maskApiKey, isMaskedKey } from "@/lib/settings-store"
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

  // API Key: 如果是掩码值则保留原值，否则更新
  if (typeof body.deepseekApiKey === "string") {
    if (isMaskedKey(body.deepseekApiKey)) {
      // 前端发回掩码值 → 保持现有 key 不变（下面从 current 补全）
    } else {
      valid.deepseekApiKey = body.deepseekApiKey
    }
  }

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
  const settings = getSettings()

  // 返回给前端时掩码 API Key
  const masked = {
    ...settings,
    deepseekApiKey: settings.deepseekApiKey ? maskApiKey(settings.deepseekApiKey) : "",
  }

  return NextResponse.json(masked)
}

export async function PUT(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  try {
    const body = await request.json()
    const validated = validateSettings(body)
    const current = getSettings()

    // 如果前端送了掩码 key，用现有的真实 key 覆盖
    if (isMaskedKey(body.deepseekApiKey as string)) {
      validated.deepseekApiKey = current.deepseekApiKey
    }

    const updated = updateSettings(validated)
    await new Promise(r => setTimeout(r, 100))

    // 返回时也掩码
    const masked = {
      ...updated,
      deepseekApiKey: updated.deepseekApiKey ? maskApiKey(updated.deepseekApiKey) : "",
    }

    return NextResponse.json(masked)
  } catch {
    return NextResponse.json(
      { error: "无效的设置数据" },
      { status: 400 },
    )
  }
}
