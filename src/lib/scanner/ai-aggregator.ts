import type { ScanResult } from "./types"
import type { AggregationReport, AggregatedFinding, Confidence } from "./types"

const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || "deepseek-v4-flash"
const DEEPSEEK_API_URL = process.env.DEEPSEEK_BASE_URL
  ? process.env.DEEPSEEK_BASE_URL + "/v1/chat/completions"
  : "https://api.deepseek.com/v1/chat/completions"

export interface AggregatorInput {
  target: string
  mode: "url" | "source"
  scannerResults: ScanResult[]
  scannerNames: string[]
}

async function callDeepSeek(systemPrompt: string, userPrompt: string): Promise<string> {
  const apiKey = process.env.DEEPSEEK_API_KEY
  if (!apiKey) {
    throw new Error("DEEPSEEK_API_KEY not configured")
  }

  const res = await fetch(DEEPSEEK_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + apiKey,
    },
    body: JSON.stringify({
      model: DEEPSEEK_MODEL,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
      temperature: 0.1,
      max_tokens: 4096,
    }),
  })

  if (!res.ok) {
    const errBody = await res.text().catch(() => "unknown")
    throw new Error("DeepSeek API error " + res.status + ": " + errBody.slice(0, 200))
  }

  const json = await res.json()
  return json.choices?.[0]?.message?.content || ""
}

function buildPrompt(input: AggregatorInput): { system: string; user: string } {
  const findingsByScanner = input.scannerResults
    .filter(r => r.vulnerabilities.length > 0)
    .map(
      r =>
        `[${r.scannerName}] (${r.vulnerabilities.length} findings)\n` +
        r.vulnerabilities
          .map(
            (v, i) =>
              `  ${i + 1}. [${v.severity}] ${v.name}\n` +
              `     Location: ${v.location}\n` +
              `     CVE: ${v.cve}\n` +
              `     Description: ${v.description}\n` +
              `     Recommendation: ${v.recommendation}`,
          )
          .join("\n"),
    )
    .join("\n\n")

  const system = `你是一个安全扫描结果聚合分析专家。你的任务是对多个安全扫描引擎的检测结果进行交叉关联分析，生成统一的、去重后的、带优先级排序的报告。

**重要：所有文本输出必须使用中文**，包括 name、description、recommendation、summary、priorityActions、falsePositiveReason 等字段。CVE编号、文件路径、代码片段保持原文。

## 规则

1. **跨引擎关联**: 当同一漏洞被多个扫描器检测到（如 semgrep 发现 SQL 注入且 sqlmap 也验证成功），合并为一条高置信度发现，在 detectedBy 中列出所有扫描器名称。

2. **误报检测**: 标记疑似误报的发现，常见误报模式：
   - 测试/示例代码中的硬编码凭据（如 "password123"、测试 key）
   - 第三方/供应商代码中的漏洞
   - 无实际利用路径的过度泛化模式匹配
   设置 isFalsePositive: true 并提供理由。

3. **严重度调整**: 被多个扫描器确认的漏洞可考虑提升严重等级；若基于上下文判断实际影响较低（如不可达代码），可考虑降低。

4. **置信度评分**:
   - \`high\`: 被多个扫描器确认，或单个扫描器发出高确定性信号（如 sqlmap 成功注入）
   - \`medium\`: 单个扫描器有明确证据但无交叉验证
   - \`low\`: 单个扫描器基于启发式/模式匹配的发现

5. **去重**: 同一位置、同一根因的多个发现，只保留一条合并后的记录。

## 输出格式
只返回 JSON，不要 markdown 代码块，不要额外说明。

{
  "findings": [
    {
      "name": "漏洞名称（中文）",
      "severity": "Critical|High|Medium|Low",
      "location": "文件路径或URL",
      "cve": "CVE-ID 或 —",
      "description": "详细描述（中文）",
      "recommendation": "修复建议（中文）",
      "code": "代码片段（可选）",
      "confidence": "high|medium|low",
      "isFalsePositive": false,
      "falsePositiveReason": null,
      "detectedBy": ["scanner1", "scanner2"],
      "isCorrelated": true
    }
  ],
  "falsePositivesRemoved": 0,
  "summary": "整体评估摘要（中文，2-3句话）",
  "priorityActions": ["优先处理项1（中文）", "优先处理项2"]
}`

  const user =
    `Target: ${input.target}\n` +
    `Mode: ${input.mode}\n` +
    `Scanners that ran: ${input.scannerNames.join(", ")}\n\n` +
    `## Raw Findings by Scanner\n\n` +
    (findingsByScanner || "No findings from any scanner.")

  return { system, user }
}

function parseResponse(content: string): AggregationReport {
  const cleaned = content
    .replace(/```json\s*/gi, "")
    .replace(/```\s*/g, "")
    .trim()

  let parsed: any
  try {
    parsed = JSON.parse(cleaned)
  } catch {
    throw new Error("Failed to parse aggregator response as JSON")
  }

  if (!Array.isArray(parsed.findings)) {
    throw new Error("Aggregator response missing 'findings' array")
  }

  const validSeverities = ["Critical", "High", "Medium", "Low"]
  const validConfidences: Confidence[] = ["high", "medium", "low"]

  const findings: AggregatedFinding[] = parsed.findings.map((f: any, i: number) => ({
    id: "AGG-" + (i + 1),
    name: typeof f.name === "string" ? f.name : "Unknown finding",
    severity: validSeverities.includes(f.severity) ? f.severity : "Medium",
    location: typeof f.location === "string" ? f.location : "",
    cve: typeof f.cve === "string" ? f.cve : "—",
    description: typeof f.description === "string" ? f.description : "",
    recommendation: typeof f.recommendation === "string" ? f.recommendation : "",
    code: typeof f.code === "string" ? f.code : undefined,
    confidence: validConfidences.includes(f.confidence) ? f.confidence : "medium",
    isFalsePositive: f.isFalsePositive === true,
    falsePositiveReason:
      f.isFalsePositive === true && typeof f.falsePositiveReason === "string"
        ? f.falsePositiveReason
        : undefined,
    detectedBy: Array.isArray(f.detectedBy) ? f.detectedBy.filter((s: any) => typeof s === "string") : [],
    isCorrelated: f.isCorrelated === true,
  }))

  return {
    findings,
    falsePositivesRemoved:
      typeof parsed.falsePositivesRemoved === "number" ? parsed.falsePositivesRemoved : 0,
    summary: typeof parsed.summary === "string" ? parsed.summary : "",
    priorityActions: Array.isArray(parsed.priorityActions)
      ? parsed.priorityActions.filter((a: any) => typeof a === "string")
      : [],
    target: "",
    createdAt: new Date().toISOString(),
  }
}

export async function aggregateScanResults(input: AggregatorInput): Promise<AggregationReport> {
  const { system, user } = buildPrompt(input)
  const content = await callDeepSeek(system, user)
  const report = parseResponse(content)
  report.target = input.target
  return report
}
