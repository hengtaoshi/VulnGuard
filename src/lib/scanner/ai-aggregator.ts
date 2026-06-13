/**
 * ai-aggregator.ts — AI 驱动扫描结果聚合器
 *
 * 接收所有扫描器的原始结果，调用 DeepSeek 做:
 * 1. 跨引擎关联 — 不同扫描器发现的同一漏洞合并
 * 2. 假阳性检测 — AI 判断哪些是误报
 * 3. 置信度评分 — 高/中/低三档
 * 4. 优先级排序 — 生成修复建议排序
 *
 * 当 DeepSeek 不可用时回退到确定性去重。
 */

import type { Vulnerability } from "@/lib/api/types"
import type { AggregationReport, AggregatedFinding, Confidence } from "./types"
import { isLlmAvailable, callLlmJson } from "./llm-client"
import { addIgnoreRule } from "../ignore-rules"

/**
 * 确定性去重 — 按 name:location:description(80chars) 去重
 */
function deterministicDedup(vulnerabilities: Vulnerability[]): Vulnerability[] {
  const seen = new Map<string, Vulnerability>()
  for (const v of vulnerabilities) {
    const key = `${v.name}:${v.location}:${v.description.slice(0, 80)}`
    if (!seen.has(key)) {
      seen.set(key, v)
    }
  }
  return Array.from(seen.values())
}

/**
 * 构建 AI 聚合用的系统提示词
 */
function buildSystemPrompt(): string {
  return `你是 VulnGuard 的安全分析专家。你的任务是对多个安全扫描器的检测结果进行智能聚合。

你需要:
1. 识别不同扫描器报告同一漏洞的情况（跨引擎关联）
2. 标记明显的误报（false positive）
3. 对剩余发现分配置信度（high/medium/low）
4. 生成优先级修复建议
5. 输出中文总结

置信度规则:
- high: 多个扫描器交叉确认，或单一扫描器但证据确凿（清晰的 CVE、明确的注入点）
- medium: 单一扫描器报告，有合理怀疑但缺乏交叉验证
- low: 仅模式匹配/启发式告警，可能是误报但需要人工核实

输出严格的 JSON 格式（不要 markdown 代码块）。`
}

/**
 * 构建 AI 聚合用的用户提示词
 */
function buildUserPrompt(
  vulnerabilities: Vulnerability[],
  scannerResults: { scannerName: string; count: number }[],
  target: string,
  existingIgnoreRules: string[] = [],
): string {
  const scannerSummary = scannerResults
    .map(s => `${s.scannerName}: ${s.count} findings`)
    .join("\n")

  const vulnList = vulnerabilities
    .map((v, i) => `[${i + 1}] [${v.severity}] ${v.name}
   Location: ${v.location}
   CVE: ${v.cve}
   Source: ${v.source || "unknown"}
   Desc: ${v.description.slice(0, 200)}
`)
    .join("\n")

  const ignoreContext = existingIgnoreRules.length > 0
    ? `\n## 用户已标记的忽略规则（不要再次报告）\n${existingIgnoreRules.map(r => `- ${r}`).join("\n")}\n`
    : ""

  return `## 扫描结果汇总

**扫描目标:** ${target}
**扫描器:** 
${scannerSummary}

**总发现数:** ${vulnerabilities.length}
${ignoreContext}
## 原始漏洞列表
${vulnList || "（无发现）"}

请分析以上结果，输出 JSON。`
}

/**
 * 生成简单的聚合报告（AI 不可用时的回退）
 */
function createFallbackReport(
  vulnerabilities: Vulnerability[],
  target: string,
): AggregationReport {
  const critical = vulnerabilities.filter(v => v.severity === "Critical").length
  const high = vulnerabilities.filter(v => v.severity === "High").length
  const medium = vulnerabilities.filter(v => v.severity === "Medium").length
  const low = vulnerabilities.filter(v => v.severity === "Low").length

  const priorityActions: string[] = []
  if (critical > 0) priorityActions.push(`立即修复 ${critical} 个严重漏洞`)
  if (high > 0) priorityActions.push(`优先处理 ${high} 个高危漏洞`)
  if (medium > 0) priorityActions.push(`计划修复 ${medium} 个中危漏洞`)
  if (low > 0) priorityActions.push(`酌情处理 ${low} 个低危漏洞`)
  if (priorityActions.length === 0) priorityActions.push("未发现安全漏洞")

  const findings: AggregatedFinding[] = vulnerabilities.map((v, i) => ({
    id: `finding-${i + 1}`,
    name: v.name,
    severity: v.severity,
    location: v.location,
    cve: v.cve,
    description: v.description,
    recommendation: v.recommendation,
    code: v.code,
    confidence: v.cve && v.cve !== "CVE-Pending" ? "high" : "medium",
    isFalsePositive: false,
    detectedBy: v.source ? [v.source] : ["unknown"],
    isCorrelated: false,
  }))

  return {
    findings,
    falsePositivesRemoved: 0,
    summary: `基础聚合：${vulnerabilities.length} 个发现（严重: ${critical}, 高危: ${high}, 中危: ${medium}, 低危: ${low}）`,
    priorityActions,
    target,
    createdAt: new Date().toISOString(),
  }
}

/**
 * AI 聚合扫描结果
 *
 * @param vulnerabilities 所有扫描器的原始漏洞列表（去重前）
 * @param scannerResults 各扫描器的统计信息
 * @param target 扫描目标路径
 * @returns AggregationReport
 */
export async function aggregateScanResults(
  vulnerabilities: Vulnerability[],
  scannerResults: { scannerName: string; count: number }[],
  target: string,
  existingIgnorePatterns: string[] = [],
): Promise<AggregationReport> {
  if (!isLlmAvailable()) {
    return createFallbackReport(deterministicDedup(vulnerabilities), target)
  }

  // 如果漏洞太多，只发前 80 条给 AI（token 限制），剩余的用规则处理
  const AI_BATCH_LIMIT = 80
  const aiBatch = vulnerabilities.slice(0, AI_BATCH_LIMIT)
  const remaining = vulnerabilities.slice(AI_BATCH_LIMIT)

  const aiResult = await callLlmJson<{
    findings: Array<{
      name: string
      severity: "Critical" | "High" | "Medium" | "Low"
      location: string
      cve: string
      description: string
      recommendation: string
      confidence: Confidence
      isFalsePositive: boolean
      falsePositiveReason?: string
      detectedBy: string[]
    }>
    falsePositivesRemoved: number
    summary: string
    priorityActions: string[]
  }>(
    buildSystemPrompt(),
    buildUserPrompt(aiBatch, scannerResults, target, existingIgnorePatterns),
    { temperature: 0.2, maxTokens: 4096, timeoutMs: 60000 },
  )

  if (!aiResult || !aiResult.findings) {
    return createFallbackReport(deterministicDedup(vulnerabilities), target)
  }

  // 归一化 AI 返回字段 —— DeepSeek 有时把 summary 返回成对象而不是字符串
  const aggSummary = typeof aiResult.summary === "string"
    ? aiResult.summary
    : `AI 聚合完成：${aiResult.findings.filter(f => !f.isFalsePositive).length} 个发现，${(aiResult.falsePositivesRemoved || 0) + aiResult.findings.filter(f => f.isFalsePositive).length} 个误报已移除`
  const aggPriorityActions = Array.isArray(aiResult.priorityActions) ? aiResult.priorityActions : []

  // 整理 AI 分析的结果
  const aiFindings: AggregatedFinding[] = aiResult.findings
    .filter(f => !f.isFalsePositive)
    .map((f, i) => ({
      id: `finding-${i + 1}`,
      name: f.name,
      severity: f.severity,
      location: f.location,
      cve: f.cve,
      description: f.description,
      recommendation: f.recommendation,
      confidence: f.confidence,
      isFalsePositive: false,
      detectedBy: f.detectedBy || ["unknown"],
      isCorrelated: (f.detectedBy?.length || 0) > 1,
    }))

  // 规则处理剩余漏洞（超出 AI batch 的）
  const remainingDeduped = deterministicDedup(remaining)
  for (const v of remainingDeduped) {
    aiFindings.push({
      id: `finding-rules-${aiFindings.length + 1}`,
      name: v.name,
      severity: v.severity,
      location: v.location,
      cve: v.cve,
      description: v.description,
      recommendation: v.recommendation,
      code: v.code,
      confidence: v.cve && v.cve !== "CVE-Pending" ? "high" : "medium",
      isFalsePositive: false,
      detectedBy: v.source ? [v.source] : ["unknown"],
      isCorrelated: false,
    })
  }

  // 自动将 AI 检测到的误报写入忽略规则库（反馈闭环）
  const aiFalsePositives = aiResult.findings.filter(f => f.isFalsePositive)
  for (const fp of aiFalsePositives) {
    // 构建 pattern: scanner:cve 或 scanner:name
    const pattern = fp.cve && fp.cve !== "CVE-Pending" && fp.cve !== "AI-Finding"
      ? `${(fp.detectedBy[0] || "*")}:${fp.cve}`
      : `${(fp.detectedBy[0] || "*")}:${fp.name.slice(0, 80)}`
    addIgnoreRule(pattern, `AI auto-suppressed: ${fp.falsePositiveReason || "false positive"}`)
  }

  const falsePositivesRemoved = (aiResult.falsePositivesRemoved || 0) + aiFalsePositives.length

  return {
    findings: aiFindings,
    falsePositivesRemoved,
    summary: aggSummary,
    priorityActions: aggPriorityActions,
    target,
    createdAt: new Date().toISOString(),
  }
}
