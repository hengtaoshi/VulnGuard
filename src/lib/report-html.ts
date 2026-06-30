/**
 * report-html.ts — 生成独立 HTML 报告（可用于打印/PDF导出）
 *
 * 生成一个自包含的 HTML 字符串，嵌入全部样式，
 * 用户可以通过浏览器打印 → 另存为 PDF 导出。
 *
 * 替代旧的 html2canvas + jsPDF 截图方案，生成的 PDF 字体清晰、
 * 可选中文字、文件体积小。
 */

// ─── 颜色映射 ──────────────────────────────────────────────────────────────

function sColor(sev: string): string {
  const m: Record<string, string> = { Critical: "#ef4444", High: "#f59e0b", Medium: "#3b82f6", Low: "#22c55e" }
  return m[sev] || "#666"
}

function formatDate(d: string | undefined): string {
  if (!d) return ""
  const dt = new Date(d)
  return dt.toLocaleDateString("zh-CN") + " " + dt.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" as const })
}

// ─── 扫描器分类映射 ─────────────────────────────────────────────────────────

const CATEGORY_LABELS: Record<string, string> = {
  sast: "静态代码分析",
  secret: "密钥检测",
  dependency: "依赖扫描",
  filesystem: "文件系统",
  ai: "AI 分析",
}

// ─── Helper: 生成 Severity 统计区域 ─────────────────────────────────────────

function severitySummaryHTML(summary: { critical: number; high: number; medium: number; low: number; passed?: number }): string {
  const total = summary.critical + summary.high + summary.medium + summary.low + (summary.passed || 0)
  return `
    <div class="mg">
      <div class="mi"><div class="l">风险评分</div><div class="v" style="font-size:20px">${summary.critical > 0 ? "🔴" : summary.high > 0 ? "🟡" : "🟢"} ${summary.critical + summary.high + summary.medium + summary.low > 0 ? "有风险" : "安全"}</div></div>
      <div class="mi"><div class="l">严重</div><div class="v" style="color:${sColor("Critical")}">${summary.critical}</div></div>
      <div class="mi"><div class="l">高危</div><div class="v" style="color:${sColor("High")}">${summary.high}</div></div>
      <div class="mi"><div class="l">中危</div><div class="v" style="color:${sColor("Medium")}">${summary.medium}</div></div>
      <div class="mi"><div class="l">低危</div><div class="v" style="color:${sColor("Low")}">${summary.low}</div></div>
      <div class="mi"><div class="l">检测总数</div><div class="v">${total}</div></div>
    </div>`
}

// ─── Helper: 漏洞详情区域 ──────────────────────────────────────────────────

function vulnerabilitiesHTML(vulns: Array<{ severity: string; name: string; location?: string; description?: string; recommendation?: string; cve?: string; source?: string; code?: string }>): string {
  if (!vulns || vulns.length === 0) {
    return '<div class="no">✅ 未发现安全漏洞</div>'
  }

  let html = ""
  let vi = 0
  for (const sev of ["Critical", "High", "Medium", "Low"]) {
    const items = vulns.filter(v => v.severity === sev)
    if (!items.length) continue
    html += `<div class="sg"><div class="sh" style="background:${sColor(sev)}"><span>${sev}</span><span>${items.length} 项</span></div>`
    for (const v of items) {
      vi++
      html += `<div class="vi"><div class="vt">#${vi} ${v.name}</div>`
      if (v.location) html += `<div class="vf"><span>位置</span><span>${v.location}</span></div>`
      if (v.description) html += `<div class="vf"><span>描述</span><p>${v.description}</p></div>`
      if (v.recommendation) html += `<div class="vf"><span>修复建议</span><p>${v.recommendation}</p></div>`
      if (v.cve && v.cve !== "—") html += `<div class="vf"><span>CVE</span><span>${v.cve}</span></div>`
      html += "</div>"
    }
    html += "</div>"
  }
  return html
}

// ─── Helper: AI 编排决策区域 ──────────────────────────────────────────────

function orchestratorHTML(plan?: {
  reasoning?: string
  selectedScanners?: string[]
  parallelGroups?: string[][]
  scanPriority?: string
  aiReview?: boolean
}): string {
  if (!plan) return ""

  const priorityLabel: Record<string, string> = { speed: "⚡ 速度优先", depth: "🔍 深度优先", balanced: "⚖️ 均衡策略" }

  let html = '<div class="sec"><h2>📋 AI 扫描编排方案</h2>'

  // 优先级和数量
  html += `<div class="mg" style="grid-template-columns:repeat(auto-fill,minmax(140px,1fr))">`
  html += `<div class="mi"><div class="l">扫描策略</div><div class="v">${priorityLabel[plan.scanPriority || ""] || plan.scanPriority || "—"}</div></div>`
  html += `<div class="mi"><div class="l">选定扫描器</div><div class="v">${(plan.selectedScanners || []).length} 个</div></div>`
  html += `<div class="mi"><div class="l">执行阶段</div><div class="v">${(plan.parallelGroups || []).length} 个</div></div>`
  if (plan.aiReview) {
    html += `<div class="mi"><div class="l">AI 代码审查</div><div class="v" style="color:#22c55e">已启用</div></div>`
  }
  html += `</div>`

  // 执行阶段
  if (plan.parallelGroups && plan.parallelGroups.length > 0) {
    html += '<div class="osp"><div class="osp-title">执行阶段</div>'
    for (let gi = 0; gi < plan.parallelGroups.length; gi++) {
      const group = plan.parallelGroups[gi]
      const phaseNames = ["快速检测", "深度分析", "AI 分析"]
      html += `<div class="osp-item"><div class="osp-h">Phase ${gi + 1}${phaseNames[gi] ? " — " + phaseNames[gi] : ""}</div>`
      html += `<div class="osp-tags">${group.map(n => `<span class="osp-tag">${n}</span>`).join("")}</div>`
      html += `</div>`
    }
    html += '</div>'
  }

  // 推理过程
  if (plan.reasoning) {
    html += '<details class="ord"><summary class="ord-summary">📖 查看完整推理过程</summary>'
    html += `<div class="ord-body"><pre>${plan.reasoning}</pre></div></details>`
  }

  html += '</div>'
  return html
}

// ─── Helper: 扫描器执行结果 ───────────────────────────────────────────────

function scannerResultsHTML(scanners?: Array<{
  scannerName?: string
  displayName?: string
  category?: string
  count?: number
  status?: string
  errors?: string[]
}>): string {
  if (!scanners || scanners.length === 0) return ""

  let html = '<div class="sec"><h2>🔬 扫描器执行结果</h2><div class="sr-grid">'

  for (const s of scanners) {
    const catLabel = CATEGORY_LABELS[s.category || ""] || s.category || ""
    // 持久化的 scanner 数据没有 status 字段，通过 errors 判断
    const hasErrors = (s.errors?.length || 0) > 0
    const icon = hasErrors ? "⚠️" : "✅"
    const statusLabel = hasErrors ? "失败" : "完成"
    const statusClass = hasErrors ? "sr-fail" : "sr-ok"

    html += `<div class="sr-card">`
    html += `<div class="sr-h">${icon} ${s.displayName || s.scannerName || ""}</div>`
    html += `<div class="sr-meta"><span class="sr-cat">${catLabel}</span><span class="sr-status ${statusClass}">${statusLabel}</span></div>`
    if (s.count !== undefined && s.count > 0) {
      html += `<div class="sr-count">发现 ${s.count} 个问题</div>`
    }
    if (s.errors && s.errors.length > 0) {
      const err = s.errors.join("; ")
      html += `<div class="sr-err">${err.length > 200 ? err.slice(0, 200) + "…" : err}</div>`
    }
    html += `</div>`
  }

  html += '</div></div>'
  return html
}

// ─── 主函数：生成完整 HTML ────────────────────────────────────────────────

export interface ReportData {
  id?: string
  target?: string
  status?: string
  riskScore?: string
  totalChecks?: number
  engine?: string
  summary?: {
    critical: number
    high: number
    medium: number
    low: number
    passed?: number
  }
  vulnerabilities?: Array<{
    severity: string
    name: string
    location?: string
    description?: string
    recommendation?: string
    cve?: string
    source?: string
    code?: string
  }>
  projectName?: string
  scanners?: Array<{
    scannerName?: string
    displayName?: string
    category?: string
    count?: number
    status?: string
    errors?: string[]
  }>
  orchestratorPlan?: {
    reasoning?: string
    selectedScanners?: string[]
    parallelGroups?: string[][]
    scanPriority?: string
    aiReview?: boolean
  }
  aiAggregation?: {
    summary?: string
    priorityActions?: string[]
    falsePositivesRemoved?: number
  }
  createdAt?: string
}

export function generateReportHtml(scan: ReportData): string {
  const s = scan.summary || { critical: 0, high: 0, medium: 0, low: 0, passed: 0 }
  const vulns = scan.vulnerabilities || []
  const tgt = scan.target || ""
  const id = scan.id || ""

  // 提取项目名称用于 PDF 文件名 — 优先使用上传时记录的项目名
  const projectName = scan.projectName || tgt.split(/[/\\]/).filter(Boolean).pop() || "Unknown"
  // 格式化时间戳：YYYY-MM-DD HHmm
  const dateStr = scan.createdAt
    ? (() => {
        const d = new Date(scan.createdAt!)
        const pad = (n: number) => String(n).padStart(2, "0")
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}${pad(d.getMinutes())}`
      })()
    : new Date().toISOString().slice(0, 16).replace("T", " ")

  let aiHtml = ""
  if (scan.aiAggregation) {
    aiHtml = '<div class="sec"><h2>🤖 AI 聚合分析</h2>'
    if (scan.aiAggregation.falsePositivesRemoved && scan.aiAggregation.falsePositivesRemoved > 0) {
      aiHtml += `<div class="ai-badge">已排除 ${scan.aiAggregation.falsePositivesRemoved} 个误报</div>`
    }
    if (scan.aiAggregation.summary) {
      aiHtml += `<div class="ais">${scan.aiAggregation.summary}</div>`
    }
    if (scan.aiAggregation.priorityActions && scan.aiAggregation.priorityActions.length > 0) {
      aiHtml += '<div class="pa"><div class="pa-title">优先处理建议</div><ul>'
      for (const a of scan.aiAggregation.priorityActions) {
        aiHtml += `<li>${a}</li>`
      }
      aiHtml += '</ul></div>'
    }
    aiHtml += '</div>'
  }

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${projectName} ${dateStr} VulnGuard 安全扫描报告</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:#0a0e17;color:#e0e6f0;line-height:1.7;padding:40px 24px}
.c{max-width:960px;margin:0 auto}
.tb{position:sticky;top:16px;z-index:100;display:flex;gap:10px;justify-content:flex-end;margin-bottom:24px}
.tb button{padding:8px 20px;border:1px solid rgba(79,195,247,.3);border-radius:8px;background:rgba(15,23,42,.9);color:#4fc3f7;font-size:13px;cursor:pointer;font-family:inherit}
.tb button:hover{background:rgba(79,195,247,.15)}
h1{font-size:26px;font-weight:800;color:#4fc3f7;margin-bottom:4px}
.sub{font-size:13px;color:#667899;margin-bottom:24px}
.mg{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:24px}
.mi{background:#111b2e;border:1px solid rgba(79,195,247,.1);border-radius:8px;padding:10px 14px;word-break:break-all;overflow-wrap:break-word}
.mi .l{font-size:12px;color:#4a5568;font-weight:600}
.mi .v{font-size:15px;font-weight:700;color:#e0e6f0;margin-top:2px;word-break:break-all;overflow-wrap:break-word}
.sec{margin-bottom:28px}
.sec h2{font-size:16px;font-weight:700;color:#fff;margin-bottom:12px}
.sg{margin-bottom:16px}
.sh{display:flex;align-items:center;justify-content:space-between;padding:6px 14px;border-radius:6px;margin-bottom:8px;color:#fff;font-weight:700;font-size:14px}
.vi{background:#111b2e;border:1px solid rgba(79,195,247,.08);border-radius:8px;padding:12px 14px;margin-bottom:8px}
.vt{font-size:14px;font-weight:600;color:#fff;margin-bottom:6px}
.vf{margin-top:4px;font-size:13px;display:flex;gap:6px}
.vf>span:first-child{color:#667899;white-space:nowrap;font-size:12px;min-width:56px}
.vf p{color:#c8d0e0;flex:1}
.ais{background:rgba(79,195,247,.05);border:1px solid rgba(79,195,247,.15);border-radius:8px;padding:12px 16px;font-size:13px;color:#c8d0e0}
.ai-badge{display:inline-block;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.25);color:#4ade80;padding:3px 10px;border-radius:12px;font-size:12px;margin-bottom:10px}
.pa{margin-top:12px;background:#111b2e;border:1px solid rgba(79,195,247,.08);border-radius:8px;padding:12px 14px}
.pa-title{font-size:13px;font-weight:600;color:#f59e0b;margin-bottom:6px}
.pa ul{list-style:none;padding:0}
.pa li{font-size:12px;color:#c8d0e0;padding:4px 0;padding-left:16px;position:relative}
.pa li::before{content:"•";position:absolute;left:4px;color:#f59e0b}
.no{background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:20px;text-align:center;color:#4ade80;font-size:14px}
.ft{text-align:center;font-size:11px;color:#445;margin-top:40px}
/* 编排方案 */
.osp{margin-bottom:16px}
.osp-title{font-size:13px;font-weight:600;color:#a78bfa;margin-bottom:8px}
.osp-item{background:#111b2e;border:1px solid rgba(167,139,250,.15);border-radius:8px;padding:10px 14px;margin-bottom:6px}
.osp-h{font-size:12px;color:#a78bfa;font-weight:600;margin-bottom:6px}
.osp-tags{display:flex;flex-wrap:wrap;gap:4px}
.osp-tag{background:rgba(167,139,250,.1);border:1px solid rgba(167,139,250,.2);border-radius:4px;padding:2px 8px;font-size:11px;color:#c4b5fd}
/* 推理 details */
.ord{margin-top:8px}
.ord-summary{font-size:12px;color:#667899;cursor:pointer}
.ord-body{margin-top:8px;background:rgba(0,0,0,.2);border:1px solid rgba(79,195,247,.08);border-radius:6px;padding:10px 14px}
.ord-body pre{font-size:11px;color:#94a3b8;line-height:1.6;white-space:pre-wrap;font-family:'SF Mono','Fira Code','Consolas',monospace}
/* 扫描器结果 */
.sr-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.sr-card{background:#111b2e;border:1px solid rgba(79,195,247,.08);border-radius:8px;padding:10px 14px}
.sr-h{font-size:13px;font-weight:600;color:#e0e6f0;margin-bottom:4px}
.sr-meta{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.sr-cat{font-size:10px;color:#667899;background:rgba(79,195,247,.08);padding:1px 6px;border-radius:3px}
.sr-status{font-size:10px;padding:1px 6px;border-radius:3px;font-weight:600}
.sr-ok{background:rgba(34,197,94,.1);color:#4ade80}
.sr-fail{background:rgba(239,68,68,.1);color:#ef4444}
.sr-count{font-size:12px;color:#f59e0b;margin-top:4px}
.sr-err{font-size:11px;color:#ef4444;margin-top:4px;word-break:break-all;overflow-wrap:break-word}
@media print{
  .tb{display:none!important}
  body{background:#fff!important;color:#222!important;padding:15px 25px!important;font-size:12px!important;line-height:1.6!important;orphans:3;widows:3;print-color-adjust:exact!important;-webkit-print-color-adjust:exact!important}
  h1{color:#1a56db!important;font-size:24px!important}
  .mi,.vi,.ais,.sr-card,.osp-item,.ord-body{background:#eef3ff!important;border-color:#b0c8e8!important;box-shadow:none!important}
  .mi{padding:8px 12px!important;word-break:break-all!important}
  .mi .v{font-size:15px!important;color:#111!important;font-weight:700!important;word-break:break-all!important}
  .mi .l{font-size:12px!important;color:#222!important;font-weight:600!important}
  .sec{margin-bottom:18px!important}.sec h2{color:#111!important;font-size:16px!important;margin-bottom:8px!important}
  .sg{margin-bottom:12px!important}.sh{font-size:13px!important;padding:5px 12px!important;margin-bottom:5px!important;print-color-adjust:exact!important;-webkit-print-color-adjust:exact!important}
  .vi{background:#fafcff!important;border:1px solid #d0d8e8!important;border-radius:6px!important;padding:8px 12px!important;margin-bottom:6px!important;page-break-inside:avoid!important}
  .vt{color:#111!important;font-size:13px!important;margin-bottom:3px!important;page-break-after:avoid!important}
  .vf{margin-top:3px!important;font-size:12px!important}.vf p{color:#333!important;font-size:12px!important}
  .vf>span:first-child{font-size:11px!important;min-width:48px!important;color:#444!important}
  .ais{font-size:12px!important;padding:10px 16px!important;color:#222!important}
  .no{padding:14px!important}.ft{font-size:10px!important;color:#888!important;margin-top:24px!important}
  .sh,.sec h2{page-break-after:avoid!important}
  .sr-grid{grid-template-columns:repeat(auto-fill,minmax(170px,1fr))!important}
  .sr-card{background:#f0f4ff!important;border-color:#c0d0e8!important;page-break-inside:avoid!important}
  .sr-h{color:#1a202c!important;font-size:12px!important}
  .sr-ok{background:#e6f7e6!important;color:#2d7d2d!important;print-color-adjust:exact!important;-webkit-print-color-adjust:exact!important}
  .sr-fail{background:#fde8e8!important;color:#c53030!important;print-color-adjust:exact!important;-webkit-print-color-adjust:exact!important}
  .sr-count{color:#b7791f!important}
  .sr-err{color:#c53030!important;word-break:break-all!important;overflow-wrap:break-word!important}
  .ord-body pre{color:#444!important;font-size:10px!important}
  .pa{background:#f0f4ff!important;border-color:#c0d0e8!important}
  .pa li{color:#333!important}
}
@media (max-width:600px){.mg{grid-template-columns:1fr 1fr}.sr-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="c">

<div class="tb">
  <button onclick="window.print()">🖨️ 打印 / PDF</button>
</div>

<h1>VulnGuard 安全扫描报告</h1>
<p class="sub">${formatDate(scan.createdAt)}${scan.engine ? ` · 引擎: ${scan.engine === "ai" ? "AI 智能" : "全量扫描"}` : ""}</p>

<div class="mg">
  <div class="mi"><div class="l">扫描目标</div><div class="v">${tgt}</div></div>
  <div class="mi"><div class="l">扫描 ID</div><div class="v" style="font-size:12px;font-family:'SF Mono','Fira Code','Consolas','Courier New',monospace;word-break:break-all">${id}</div></div>
  <div class="mi"><div class="l">风险评分</div><div class="v" style="color:${scan.riskScore === "Critical" || scan.riskScore === "F" ? "#ef4444" : scan.riskScore === "Secure" || scan.riskScore === "A" || !scan.riskScore ? "#22c55e" : "#f59e0b"}">${scan.riskScore || "—"}</div></div>
  <div class="mi"><div class="l">文件检测数</div><div class="v">${scan.totalChecks || 0}</div></div>
  <div class="mi"><div class="l">漏洞总数</div><div class="v">${s.critical + s.high + s.medium + s.low}</div></div>
  <div class="mi"><div class="l">扫描日期</div><div class="v">${scan.createdAt ? formatDate(scan.createdAt) : "—"}</div></div>
</div>

${severitySummaryHTML(s)}

${orchestratorHTML(scan.orchestratorPlan)}

${scannerResultsHTML(scan.scanners)}

${aiHtml}

<div class="sec"><h2>📄 漏洞发现详情 (${(vulns || []).length})</h2>${vulnerabilitiesHTML(vulns)}</div>

<div class="ft">VulnGuard Security Scan Report · Generated by AI-Orchestrated Scanner Engine</div>

</div>
</body>
</html>`
}

/**
 * 在新建标签页中打开报告并触发打印
 */
export function openHtmlReport(scan: ReportData): void {
  const html = generateReportHtml(scan)
  const w = window.open("", "_blank")
  if (!w) {
    alert("浏览器阻止了新标签页，请允许弹出窗口")
    return
  }
  w.document.write(html)
  w.document.close()
}
