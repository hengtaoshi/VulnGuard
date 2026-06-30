import { NextResponse } from "next/server"
import type { LLMAnalysisRequest, LLMAnalysisResponse } from "@/lib/api/llm"
import { getDeepseekModel, getDeepseekApiUrl } from "@/lib/api/llm"
import { getSettings } from "@/lib/settings-store"

export async function POST(request: Request) {
  try {
    const data: LLMAnalysisRequest = await request.json()
    const apiKey = process.env.DEEPSEEK_API_KEY || getSettings().deepseekApiKey

    if (!apiKey) {
      return NextResponse.json({ error: "DeepSeek API key not configured" }, { status: 500 })
    }

    // ── Input validation ──────────────────────────────────────────────
    // Sanitize target: truncate, remove control chars (prevent prompt injection)
    const safeTarget = (data.target || "")
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "") // remove control chars except \t\n
      .slice(0, 200)

    // Validate riskScore format
    const safeRisk = typeof data.riskScore === "string" ? data.riskScore.slice(0, 10) : "—"

    // Validate summary fields
    const safeSummary = {
      critical: Math.max(0, Math.min(9999, Number(data.summary?.critical) || 0)),
      high: Math.max(0, Math.min(9999, Number(data.summary?.high) || 0)),
      medium: Math.max(0, Math.min(9999, Number(data.summary?.medium) || 0)),
      low: Math.max(0, Math.min(9999, Number(data.summary?.low) || 0)),
      passed: Math.max(0, Math.min(9999, Number(data.summary?.passed) || 0)),
    }

    // Validate & serialize vulnerabilities (limit to 200, sanitize each field)
    const vulns = (data.vulnerabilities || []).slice(0, 200)
    const vulnContext = vulns
      .map(v => {
        const sev = ["Critical", "High", "Medium", "Low"].includes(v.severity) ? v.severity : "Low"
        const name = (v.name || "").replace(/[\x00-\x1F]/g, "").slice(0, 100)
        const loc = (v.location || "").replace(/[\x00-\x1F]/g, "").slice(0, 200)
        const desc = (v.description || "").replace(/[\x00-\x1F]/g, "").slice(0, 500)
        return `- [${sev}] ${name} (${loc}): ${desc}`
      })
      .join("\n")

    const prompt = `你是一个专业安全审计专家。分析以下安全扫描结果，给出中文分析报告。

## 扫描目标
${safeTarget}

## 风险评分
${safeRisk}

## 漏洞汇总
- 严重: ${safeSummary.critical}
- 高危: ${safeSummary.high}
- 中危: ${safeSummary.medium}
- 低危: ${safeSummary.low}
- 通过: ${safeSummary.passed}

## 漏洞详情
${vulnContext || "无漏洞发现"}

请返回严格的 JSON 格式（不要 markdown 代码块），包含以下字段：
{
  "riskAssessment": "整体风险评估（100-200字）",
  "priorityFixes": ["最紧急的修复建议1", "建议2", "建议3"],
  "architectureRisks": ["架构层面的风险1", "风险2"],
  "complianceNotes": ["合规相关说明1", "说明2"],
  "overallAdvice": "综合安全建议（100字以内）"
}`

    const res = await fetch(getDeepseekApiUrl(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: getDeepseekModel(),
        messages: [{ role: "user", content: prompt }],
        temperature: 0.3,
        max_tokens: 2048,
      }),
    })

    if (!res.ok) {
      const errBody = await res.text()
      console.error("DeepSeek API error:", res.status, errBody)
      return NextResponse.json({ error: `DeepSeek API error: ${res.status}` }, { status: 502 })
    }

    const json = await res.json()
    const content = json.choices?.[0]?.message?.content || ""

    let analysis: LLMAnalysisResponse
    try {
      const cleaned = content.replace(/```json\s*/g, "").replace(/```\s*/g, "").trim()
      analysis = JSON.parse(cleaned)
    } catch {
      return NextResponse.json({ error: "Failed to parse LLM response", raw: content }, { status: 502 })
    }

    return NextResponse.json(analysis)
  } catch (err) {
    console.error("LLM analyze error:", err)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
