import { NextResponse } from "next/server"
import { getSettings } from "@/lib/settings-store"

export async function POST(request: Request) {
  try {
    const body = await request.json()
    let apiKey = body.apiKey || ""
    const baseUrl = (body.baseUrl || "https://api.deepseek.com").replace(/\/+$/, "")
    const model = body.model || "deepseek-v4-flash"

    // 如果前端传的是掩码值，从服务端 settings 读取真实 Key
    if (!apiKey || apiKey.startsWith("__MASKED__")) {
      apiKey = process.env.DEEPSEEK_API_KEY || getSettings().deepseekApiKey || ""
    }

    if (!apiKey) {
      return NextResponse.json({ ok: false, error: "API Key 未填写" })
    }

    const url = `${baseUrl}/v1/chat/completions`
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: "hello" }],
        max_tokens: 10,
      }),
    })

    if (!res.ok) {
      const text = await res.text().catch(() => "")
      let detail = text
      try { detail = JSON.parse(text).error?.message || JSON.parse(text).error || text } catch { /* ignore */ }
      if (res.status === 401) {
        return NextResponse.json({ ok: false, error: `API Key 认证失败 (401)，请检查密钥是否正确` })
      }
      if (res.status === 404) {
        return NextResponse.json({ ok: false, error: `API 地址不正确 (404)，请检查 Base URL` })
      }
      return NextResponse.json({ ok: false, error: `请求失败 (${res.status}): ${String(detail).slice(0, 200)}` })
    }

    const json = await res.json()
    if (!json?.choices?.[0]?.message) {
      return NextResponse.json({ ok: false, error: "API 返回格式异常，无法解析" })
    }

    return NextResponse.json({ ok: true, model: json.model })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    // 网络错误给更友好的提示
    if (msg.includes("fetch")) {
      return NextResponse.json({ ok: false, error: `无法连接到 API 服务器，请检查网络或代理设置: ${msg.slice(0, 100)}` })
    }
    return NextResponse.json({ ok: false, error: msg.slice(0, 200) })
  }
}
