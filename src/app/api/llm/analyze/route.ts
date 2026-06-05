import { NextResponse } from "next/server"
import type { LLMAnalysisRequest, LLMAnalysisResponse } from "@/lib/api/llm"
import { DEEPSEEK_MODEL, DEEPSEEK_API_URL } from "@/lib/api/llm"

export async function POST(request: Request) {
  try {
    const data: LLMAnalysisRequest = await request.json()
    const apiKey = process.env.DEEPSEEK_API_KEY

    if (!apiKey) {
      return NextResponse.json({ error: "DeepSeek API key not configured" }, { status: 500 })
    }

    const vulnContext = data.vulnerabilities
      .map(v => `- [${v.severity}] ${v.name} (${v.location}): ${v.description}`)
      .join("\n")

    const prompt = `你是一个专业安全审计专家。分析以下安全扫描结果，给出中文分析报告。

## 扫描目标
${data.target}

## 风险评分
${data.riskScore}

## 漏洞汇总
- 严重: ${data.summary.critical}
- 高危: ${data.summary.high}
- 中危: ${data.summary.medium}
- 低危: ${data.summary.low}
- 通过: ${data.summary.passed}

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

    const res = await fetch(DEEPSEEK_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: DEEPSEEK_MODEL,
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
