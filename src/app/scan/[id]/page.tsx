"use client"

import dynamic from "next/dynamic"
import { useEffect, useState, useCallback, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ChevronDown, Loader2, AlertCircle, Sparkles, Brain, AlertTriangle, CheckCircle2, Lightbulb, Shield, Search, Eye, Lock, Package, File, FileDown, FileScan, Globe, FolderOpen, Clock, Target, Layers, GitBranch, Server, Zap, Wifi, Database, Cpu, Flag, TrendingUp, BarChart3, Download, Printer, Archive, Info, Upload, Activity, ExternalLink } from "lucide-react"
import { useParams } from "next/navigation"
import { useI18n } from "@/lib/i18n/context"
import { useLLMAnalysis } from "@/lib/api/hooks"
import { ScanProgressView } from "@/components/scan/scan-progress"
import { formatTime, formatDate } from "@/lib/scan-utils"
import type { AggregationSummary } from "@/lib/api/types"
import type { ScanDetail, ScanProgress } from "@/lib/api/types"

const DownloadPdfButton = dynamic(
  () => import("@/components/report/DownloadPdfButton").then(m => ({ default: m.DownloadPdfButton })),
  { ssr: false }
)

const POLL_INTERVAL = 1000

// ─── Icons Map ──────────────────────────────────────────────────────────────────

const scannerIcons: Record<string, React.ReactNode> = {
  semgrep: <Search className="h-3 w-3" />,
  gitleaks: <Lock className="h-3 w-3" />,
  "npm-audit": <Package className="h-3 w-3" />,
  "pip-audit": <Package className="h-3 w-3" />,
  "dependency-check": <Package className="h-3 w-3" />,
  trivy: <FileScan className="h-3 w-3" />,

  bandit: <Shield className="h-3 w-3" />,
  checkov: <Server className="h-3 w-3" />,
  nuclei: <Zap className="h-3 w-3" />,


}

const defaultScannerIcon = <Shield className="h-3 w-3" />

const scannerCategoryLabels: Record<string, string> = {
  sast: "SAST",
  secret: "密钥",
  dependency: "依赖",
  filesystem: "文件系统",
  dns: "DNS",
  network: "网络",
  web: "Web",
  osint: "OSINT",
  ai: "AI",
}

const categoryThemes: Record<string, { color: string; bg: string; border: string }> = {
  sast: { color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/20" },
  secret: { color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/20" },
  dependency: { color: "text-amber-500", bg: "bg-amber-500/10", border: "border-amber-500/20" },
  filesystem: { color: "text-purple-500", bg: "bg-purple-500/10", border: "border-purple-500/20" },
  dns: { color: "text-cyan-500", bg: "bg-cyan-500/10", border: "border-cyan-500/20" },
  network: { color: "text-sky-500", bg: "bg-sky-500/10", border: "border-sky-500/20" },
  web: { color: "text-orange-500", bg: "bg-orange-500/10", border: "border-orange-500/20" },
  osint: { color: "text-teal-500", bg: "bg-teal-500/10", border: "border-teal-500/20" },
  ai: { color: "text-violet-500", bg: "bg-violet-500/10", border: "border-violet-500/20" },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────

function SeverityBadge({ severity, size = "sm" }: { severity: string; size?: "sm" | "lg" }) {
  const variantMap: Record<string, "destructive" | "warning" | "info" | "success"> = {
    Critical: "destructive",
    High: "warning",
    Medium: "info",
    Low: "success",
  }
  const sizeClass = size === "lg" ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs"
  return <Badge variant={variantMap[severity] || "outline"} className={sizeClass}>{severity}</Badge>
}

function riskScoreLabel(score: string): { label: string; color: string; desc: string } {
  switch (score) {
    case "F": return { label: "极高风险", color: "text-destructive border-destructive/30 bg-destructive/10", desc: "存在严重安全漏洞，需立即修复" }
    case "D": return { label: "高风险", color: "text-red-500 border-red-500/30 bg-red-500/10", desc: "存在多个高危漏洞，建议尽快修复" }
    case "C": return { label: "中高风险", color: "text-amber-500 border-amber-500/30 bg-amber-500/10", desc: "存在高危漏洞，需优先处理" }
    case "B": return { label: "中风险", color: "text-yellow-500 border-yellow-500/30 bg-yellow-500/10", desc: "存在中等风险漏洞，建议修复" }
    case "A": return { label: "低风险", color: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10", desc: "未发现严重漏洞" }
    default: return { label: score || "—", color: "text-muted-foreground border-border/50 bg-muted/30", desc: "" }
  }
}

// ─── Progress View (keeping as-is) ──────────────────────────────────────────────




// ─── Report Section: Header ─────────────────────────────────────────────────────

function ReportHeader({ scan, duration }: { scan: ScanDetail; duration: string }) {
  const risk = riskScoreLabel(scan.riskScore)
  return (
    <div className="relative overflow-hidden rounded-xl border border-border/60 bg-gradient-to-br from-card to-muted/30">
      {/* Decorative top bar */}
      <div className="h-1.5 w-full bg-gradient-to-r from-destructive via-amber-500 to-emerald-500" />
      <div className="p-6 sm:p-8">
        <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
          {/* Left: Title & Meta */}
          <div className="space-y-4 flex-1">
            <div className="flex items-center gap-3">
              <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-violet-500/20 to-primary/20 flex items-center justify-center ring-1 ring-violet-500/20">
                <Shield className="h-6 w-6 text-violet-500" />
              </div>
              <div>
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">安全扫描报告</h1>
                <p className="text-sm text-muted-foreground">Security Scan Report</p>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border border-border/40 sm:col-span-2 lg:col-span-2">
                <Target className="h-4 w-4 text-muted-foreground shrink-0" />
                <div className="min-w-0">
                  <p className="text-xs text-foreground/70 uppercase tracking-wide">Target</p>
                  <p className="text-xs font-medium break-all leading-relaxed">{scan.target}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border border-border/40">
                <Clock className="h-4 w-4 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-xs text-foreground/70 uppercase tracking-wide">Date</p>
                  <p className="text-sm font-medium">{formatDate(scan.createdAt || "")}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border border-border/40">
                <BarChart3 className="h-4 w-4 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-xs text-foreground/70 uppercase tracking-wide">Duration</p>
                  <p className="text-sm font-medium">{duration}</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border border-border/40">
                {scan.engine === "ai" ? <Brain className="h-4 w-4 text-violet-500 shrink-0" /> : <Cpu className="h-4 w-4 text-emerald-500 shrink-0" />}
                <div>
                  <p className="text-xs text-foreground/70 uppercase tracking-wide">Engine</p>
                  <p className="text-sm font-medium">{scan.engine === "ai" ? "AI 自主调度" : "全量扫描"}</p>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <code className="px-1.5 py-0.5 rounded bg-muted border border-border/50">{scan.id}</code>
              <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
              <span>{scan.totalChecks} 项检查</span>
              <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
              <span>{scan.vulnerabilities?.length ?? 0} 个安全发现</span>
            </div>
            {scan.totalFiles && scan.skippedFiles ? (
              <p className="text-xs text-muted-foreground/60 mt-1.5 flex items-center gap-1.5">
                <File className="h-3 w-3" />
                原始目录共 {scan.totalFiles} 个文件，系统自动过滤了 {scan.skippedFiles} 个非源码目录文件（node_modules、.git 等），实际参与扫描 {scan.totalFiles - scan.skippedFiles} 个文件
              </p>
            ) : null}
          </div>
          {/* Right: Risk Score */}
          <div className="flex flex-col items-center gap-2 p-5 rounded-xl border border-border/50 bg-card/50 shrink-0">
            <div className={`text-5xl font-black tracking-tighter ${risk.color}`}>{scan.riskScore}</div>
            <div className={`px-3 py-1 rounded-full text-xs font-semibold ${risk.color} bg-current/10 border ${risk.color} border-current/10`}>
              {risk.label}
            </div>
            <p className="text-[10px] text-muted-foreground text-center max-w-[140px] leading-relaxed">{risk.desc}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Report Section: Executive Summary ──────────────────────────────────────────

function ExecutiveSummary({ scan, aggregation }: { scan: ScanDetail; aggregation: AggregationSummary | null }) {
  const summary = scan.summary ?? { critical: 0, high: 0, medium: 0, low: 0, passed: 0 }
  const items = [
    { label: "紧急 (Critical)", count: summary.critical, color: "text-destructive", bg: "bg-destructive/10", border: "border-destructive/30" },
    { label: "高危 (High)", count: summary.high, color: "text-red-500", bg: "bg-red-500/10", border: "border-red-500/30" },
    { label: "中危 (Medium)", count: summary.medium, color: "text-blue-500", bg: "bg-blue-500/10", border: "border-blue-500/30" },
    { label: "低危 (Low)", count: summary.low, color: "text-emerald-500", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
    { label: "通过 (Passed)", count: summary.passed, color: "text-emerald-500", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
  ]

  // Scanner execution summary
  const scanners = scan.scanners
  const scannerTotal = scanners?.length ?? 0
  const scannerSuccess = scanners?.filter(s => s.errors.length === 0).length ?? 0
  const scannerFailed = scannerTotal - scannerSuccess

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center">
          <BarChart3 className="h-4 w-4 text-primary" />
        </div>
        <div>
          <h2 className="text-lg font-bold">执行摘要</h2>
          <p className="text-xs text-muted-foreground">Executive Summary</p>
        </div>
      </div>

      {/* Scanner health bar */}
      {scannerTotal > 0 && (
        <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${
          scannerFailed > 0 ? "bg-red-500/10 border border-red-500/20" : "bg-emerald-500/10 border border-emerald-500/20"
        }`}>
          {scannerFailed > 0 ? (
            <AlertCircle className="h-3.5 w-3.5 text-red-500 shrink-0" />
          ) : (
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
          )}
          <span className="text-muted-foreground">
            扫描引擎：
            <span className={scannerSuccess > 0 ? "text-emerald-500 font-medium" : ""}>{scannerSuccess} 成功</span>
            {scannerFailed > 0 && (
              <span className="text-red-500 font-medium">，{scannerFailed} 失败</span>
            )}
            <span className="text-muted-foreground">／共 {scannerTotal} 个</span>
          </span>
        </div>
      )}

      <div className="grid gap-3 grid-cols-2 sm:grid-cols-5">
        {items.map(item => (
          <Card key={item.label} className={`${item.bg} ${item.border}`}>
            <CardContent className="p-4 text-center">
              <div className={`text-3xl font-black ${item.color}`}>{item.count}</div>
              <div className="text-[11px] text-muted-foreground mt-1">{item.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {aggregation?.summary && (
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 mt-0.5">
                <Shield className="h-4 w-4 text-primary" />
              </div>
              <div>
                <h3 className="text-sm font-semibold mb-1">AI 总体评估</h3>
                <p className="text-sm text-muted-foreground leading-relaxed">{aggregation.summary}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Report Section: Scan Methodology (编排计划) ─────────────────────────────────

/** 从 AI reasoning 文本中解析出每个扫描器的匹配/不匹配判断 */
function parseScannerDecisions(reasoning: string): { name: string; matched: boolean; rationale: string }[] {
  const decisions: { name: string; matched: boolean; rationale: string }[] = []
  // 匹配形如: "- scannerName：匹配|跳过|不匹配。原因..."
  const scannerNames = ["semgrep", "gitleaks", "bandit", "npm-audit", "pip-audit",
    "dependency-check", "trivy", "checkov", "nuclei"]
  const lines = reasoning.split("\n")
  for (const line of lines) {
    const trimmed = line.replace(/^-\s*/, "").trim()
    for (const name of scannerNames) {
      // 匹配 "name：匹配..." 或 "name：跳过..." 或 "name：不匹配..."
      const match = trimmed.match(new RegExp(`^${name}[：:]\\s*(匹配|跳过|不匹配)[。，]?\\s*([(（]?)(.*)`))
      if (match) {
        decisions.push({
          name,
          matched: match[1] === "匹配",
          rationale: match[3].trim().replace(/[)）]$/, "").trim(),
        })
        break
      }
    }
  }
  return decisions
}

function ScanMethodology({ plan }: {
  plan: NonNullable<ScanDetail["orchestratorPlan"]>
}) {
  const priorityLabel: Record<string, string> = { speed: "⚡ 速度优先", depth: "🔍 深度优先", balanced: "⚖️ 均衡策略" }
  const phaseDescriptions = [
    "Phase 1 — 快速检测组（并行）\n密钥/凭证泄露检测、npm/pip 依赖项安全审计、Python 代码安全扫描",
    "Phase 2 — 深度分析组（并行）\n多语言 SAST 静态代码分析、综合文件系统 CVE 扫描、IaC 安全配置审查、模板化漏洞扫描",
    "Phase 3 — AI 深度分析\nAI 辅助代码审计与逻辑漏洞分析",
  ]

  // 解析 AI 推理中的扫描器匹配判断
  const scannerDecisions = parseScannerDecisions(plan.reasoning)

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-violet-500/10 flex items-center justify-center">
          <Brain className="h-4 w-4 text-violet-500" />
        </div>
        <div>
          <h2 className="text-lg font-bold">扫描方案与方法论</h2>
          <p className="text-xs text-muted-foreground">Scan Methodology — AI-Orchestrated</p>
        </div>
      </div>

      {/* AI Reasoning — 结构化推理过程 */}
      <Card className="border-violet-500/20">
        <CardContent className="p-4 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <Brain className="h-4 w-4 text-violet-500" />
              <span className="text-sm font-semibold">AI 编排决策</span>
              <Badge variant="outline" className="border-violet-500/30 text-violet-500 text-[10px]">
                DeepSeek
              </Badge>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <Badge variant="outline" className="border-violet-500/30 text-violet-500 text-[10px]">
                {plan.selectedScanners.length} 个扫描器
              </Badge>
              <Badge variant="outline" className="text-[10px]">{priorityLabel[plan.scanPriority] || plan.scanPriority}</Badge>
              {plan.aiReview && (
                <Badge variant="outline" className="border-emerald-500/30 text-emerald-500 text-[10px]">
                  + AI 代码审查
                </Badge>
              )}
            </div>
          </div>

          {/* 扫描器匹配判断 —— 可视化的证据链表格 */}
          {scannerDecisions.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-semibold text-muted-foreground">扫描器匹配判断（证据链）</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {scannerDecisions.map(d => (
                  <div key={d.name}
                    className={`flex items-start gap-2.5 rounded-lg border p-2.5 transition-colors ${
                      d.matched
                        ? "border-emerald-500/20 bg-emerald-500/[0.03]"
                        : "border-red-500/10 bg-red-500/[0.02] opacity-70"
                    }`}
                  >
                    <div className={`mt-0.5 h-5 w-5 rounded-full flex items-center justify-center shrink-0 ${
                      d.matched ? "bg-emerald-500/10" : "bg-red-500/10"
                    }`}>
                      {d.matched
                        ? <span className="text-emerald-500 text-xs font-bold">✓</span>
                        : <span className="text-red-400 text-xs font-bold">✗</span>
                      }
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-xs font-semibold ${d.matched ? "text-emerald-600 dark:text-emerald-400" : "text-red-500 dark:text-red-400"}`}>
                          {d.matched ? "匹配" : "不匹配"}
                        </span>
                        <span className="text-xs font-medium text-foreground/80">{d.name}</span>
                      </div>
                      {d.rationale && (
                        <p className="text-[11px] text-muted-foreground/70 mt-0.5 leading-relaxed">
                          {d.rationale}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 完整推理原文 —— 保留格式 */}
          <details className="group">
            <summary className="text-xs text-muted-foreground/60 cursor-pointer hover:text-foreground/80 transition-colors list-none flex items-center gap-1">
              <ChevronDown className="h-3 w-3 group-open:rotate-180 transition-transform" />
              查看完整推理过程
            </summary>
            <div className="mt-2 rounded-lg bg-muted/30 border border-border/40 p-3 overflow-x-auto">
              <pre className="text-xs text-muted-foreground/80 leading-relaxed whitespace-pre-wrap font-mono">
                {plan.reasoning}
              </pre>
            </div>
          </details>
        </CardContent>
      </Card>

      {/* Parallel Execution Phases */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">执行阶段划分（{plan.parallelGroups.length} 个阶段，{plan.selectedScanners.length} 个扫描器）</span>
        </div>
        <div className="relative space-y-3 before:absolute before:left-[19px] before:top-3 before:bottom-3 before:w-[2px] before:bg-gradient-to-b before:from-violet-500/30 before:via-primary/20 before:to-emerald-500/20">
          {plan.parallelGroups.map((group, gi) => {
            const phaseColor = [
              "border-violet-500/30 bg-violet-500/[0.03]",
              "border-blue-500/30 bg-blue-500/[0.03]",
              "border-amber-500/30 bg-amber-500/[0.03]",
              "border-red-500/30 bg-red-500/[0.03]",
              "border-emerald-500/30 bg-emerald-500/[0.03]",
            ][gi % 5]
            const dotColor = [
              "bg-violet-500", "bg-blue-500", "bg-amber-500", "bg-red-500", "bg-emerald-500"
            ][gi % 5]
            return (
              <div key={gi} className={`relative rounded-lg border ${phaseColor} p-3 ml-8`}>
                {/* Timeline dot */}
                <div className={`absolute -left-8 top-3.5 h-3.5 w-3.5 rounded-full ${dotColor} ring-2 ring-background flex items-center justify-center`}>
                  <div className="h-1.5 w-1.5 rounded-full bg-white" />
                </div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-semibold text-muted-foreground">Phase {gi + 1}</span>
                  {group.length > 1 && (
                    <Badge variant="outline" className="text-[10px] border-border/50 text-muted-foreground">
                      ⚡ 并行 ({group.length} 个)
                    </Badge>
                  )}
                  {group.length === 1 && (
                    <Badge variant="outline" className="text-[10px] border-border/50 text-muted-foreground">
                      → 串行
                    </Badge>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {group.map(name => (
                    <Badge key={name} variant="secondary" className="text-xs gap-1 py-1">
                      {scannerIcons[name] || defaultScannerIcon}
                      {name}
                    </Badge>
                  ))}
                </div>
                <p className="text-[10px] text-muted-foreground/60 mt-1.5 leading-relaxed">{phaseDescriptions[gi] || ""}</p>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ─── Report Section: Scanner Results ────────────────────────────────────────────

function ScannerResultsTable({ scanners, vulnerabilities }: { scanners: ScanDetail["scanners"]; vulnerabilities: ScanDetail["vulnerabilities"] }) {
  if (!scanners || scanners.length === 0) return null

  // Count vulnerabilities per scanner
  const vulnCountByScanner: Record<string, number> = {}
  for (const v of vulnerabilities) {
    const src = v.source || "unknown"
    vulnCountByScanner[src] = (vulnCountByScanner[src] || 0) + 1
  }

  // Count by severity per scanner
  const sevByScanner: Record<string, Record<string, number>> = {}
  for (const v of vulnerabilities) {
    const src = v.source || "unknown"
    if (!sevByScanner[src]) sevByScanner[src] = { Critical: 0, High: 0, Medium: 0, Low: 0 }
    sevByScanner[src][v.severity] = (sevByScanner[src][v.severity] || 0) + 1
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-orange-500/10 flex items-center justify-center">
          <Shield className="h-4 w-4 text-orange-500" />
        </div>
        <div>
          <h2 className="text-lg font-bold">扫描引擎执行结果</h2>
          <p className="text-xs text-muted-foreground">Scanner Execution Results</p>
        </div>
      </div>

      {/* Summary bar */}
      <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/30 border border-border/40 text-sm text-muted-foreground">
        <span>共 <strong className="text-foreground">{scanners.length}</strong> 个扫描器</span>
        <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
        <span>成功 <strong className="text-emerald-500">{scanners.filter(s => s.errors.length === 0 || s.errors[0]?.includes("timed out")).length}</strong> 个</span>
        <span className="w-1 h-1 rounded-full bg-muted-foreground/30" />
        <span>发现 <strong className="text-foreground">{vulnerabilities.length}</strong> 个安全问题</span>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {scanners.map(s => {
          const theme = categoryThemes[s.category] || categoryThemes.web
          const scVulnCount = vulnCountByScanner[s.scannerName] || s.count
          const sevCounts = sevByScanner[s.scannerName] || {}
          const isSuccess = s.errors.length === 0
          const isWarning = s.errors.length > 0 && s.errors[0]?.includes("timed out")
          return (
            <Card key={s.scannerName} className={`border ${isSuccess ? theme.border : "border-destructive/20"} overflow-hidden`}>
              <div className={`h-1 w-full ${isSuccess ? "bg-gradient-to-r from-transparent via-current to-transparent opacity-20" : "bg-destructive/50"}`} />
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 min-w-0 flex-1">
                    <span className={`inline-flex items-center justify-center h-7 w-7 rounded-lg ${theme.bg} ${theme.color} shrink-0`}>
                      {scannerIcons[s.scannerName] || defaultScannerIcon}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold truncate">{s.displayName}</p>
                      <p className="text-[10px] text-muted-foreground">{scannerCategoryLabels[s.category] || s.category}</p>
                    </div>
                  </div>
                  <div className="shrink-0">
                    {isSuccess ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    ) : isWarning ? (
                      <AlertCircle className="h-4 w-4 text-amber-500" />
                    ) : (
                      <AlertCircle className="h-4 w-4 text-destructive" />
                    )}
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    {[{s:"Critical",c:"text-destructive"},{s:"High",c:"text-red-500"},{s:"Medium",c:"text-blue-500"},{s:"Low",c:"text-emerald-500"}].map(({s:sev, c:clr}) => {
                      const cnt = sevCounts[sev] || 0
                      return cnt > 0 ? <span key={sev} className={`text-[10px] font-medium ${clr}`}>{cnt}{sev[0]}</span> : null
                    })}
                    {scVulnCount > 0 ? (
                      <span className="text-lg font-bold ml-1">{scVulnCount}</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">✅ 通过</span>
                    )}
                  </div>
                  <span className="text-[10px] text-muted-foreground">
                    {isSuccess ? (scVulnCount > 0 ? `${scVulnCount} 个问题` : "无问题") : isWarning ? "超时" : "失败"}
                  </span>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}

// ─── Report Section: AI Aggregation (Professional) ──────────────────────────────

function AIAggregationReport({ aggregation, vulnerabilities }: { aggregation: AggregationSummary; vulnerabilities: ScanDetail["vulnerabilities"] }) {
  const confidenceItems = [
    { label: "高置信度", count: aggregation.highConfidence, color: "text-emerald-500", bg: "bg-emerald-500/10", border: "border-emerald-500/30" },
    { label: "中置信度", count: aggregation.mediumConfidence, color: "text-amber-500", bg: "bg-amber-500/10", border: "border-amber-500/30" },
    { label: "低置信度", count: aggregation.lowConfidence, color: "text-muted-foreground", bg: "bg-muted/30", border: "border-border/50" },
  ]

  // Count by severity from aggregation perspective
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const v of vulnerabilities) {
    if (sevCounts[v.severity] !== undefined) sevCounts[v.severity]++
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-violet-500/10 flex items-center justify-center">
          <Brain className="h-4 w-4 text-violet-500" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold">AI 聚合分析报告</h2>
            <Badge variant="outline" className="border-violet-500/30 text-violet-500 text-[10px]">DeepSeek</Badge>
          </div>
          <p className="text-xs text-muted-foreground">AI Aggregation & Correlation Report — 跨扫描器交叉关联分析</p>
        </div>
        {aggregation.falsePositivesRemoved > 0 && (
          <Badge variant="outline" className="border-emerald-500/30 text-emerald-500 text-sm px-3 py-1.5 shrink-0">
            -{aggregation.falsePositivesRemoved} 误报已过滤
          </Badge>
        )}
      </div>

      {/* Confidence & Correlation Metrics */}
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
        {confidenceItems.map(item => (
          <Card key={item.label} className={`${item.bg} ${item.border}`}>
            <CardContent className="p-4 text-center">
              <div className={`text-2xl font-black ${item.color}`}>{item.count}</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">{item.label}</div>
            </CardContent>
          </Card>
        ))}
        <Card className="border-violet-500/30 bg-violet-500/5">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-black text-violet-500">{aggregation.correlatedFindings}</div>
            <div className="text-[10px] text-muted-foreground mt-0.5">交叉关联</div>
          </CardContent>
        </Card>
      </div>

      {/* Severity distribution bar */}
      <Card className="border-border/50">
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground">严重度分布</span>
            <span className="text-[10px] text-muted-foreground">共 {vulnerabilities.length} 个发现</span>
          </div>
          <div className="h-4 rounded-full overflow-hidden flex bg-muted/50">
            {[{s:"Critical",c:"bg-destructive",cnt:sevCounts.Critical},{s:"High",c:"bg-red-500",cnt:sevCounts.High},{s:"Medium",c:"bg-blue-500",cnt:sevCounts.Medium},{s:"Low",c:"bg-emerald-500",cnt:sevCounts.Low}].map(({s:sev,c:clr,cnt}) => {
              if (cnt === 0) return null
              const pct = Math.max(3, (cnt / Math.max(1, vulnerabilities.length)) * 100)
              return (
                <div key={sev} className={`${clr} h-full flex items-center justify-center text-[8px] text-white font-bold`}
                  style={{ width: `${pct}%`, minWidth: cnt > 0 ? "16px" : "0" }}>
                  {cnt}
                </div>
              )
            })}
          </div>
          <div className="flex items-center justify-between mt-1.5">
            {[{s:"Critical",c:"text-destructive"},{s:"High",c:"text-red-500"},{s:"Medium",c:"text-blue-500"},{s:"Low",c:"text-emerald-500"}].map(({s:sev,c}) => (
              <span key={sev} className={`text-[10px] ${c}`}>{sevCounts[sev as keyof typeof sevCounts] || 0} {sev}</span>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Priority Actions */}
      {aggregation.priorityActions.length > 0 && (
        <Card className="border-amber-500/20 bg-amber-500/[0.02]">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              <CardTitle className="text-sm font-semibold">优先修复建议</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {aggregation.priorityActions.map((action, i) => (
                <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg hover:bg-muted/50 transition-colors">
                  <div className="h-5 w-5 rounded-full bg-amber-500/10 flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-xs font-bold text-amber-500">{i + 1}</span>
                  </div>
                  <p className="text-sm leading-relaxed">{action}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Report Section: Scan Activity Log ──────────────────────────────────────

function ScanLogViewer({ logs }: { logs?: import("@/lib/api/types").LogEntry[] }) {
  const [filter, setFilter] = useState<string>("all")
  const [expanded, setExpanded] = useState(false)

  if (!logs || logs.length === 0) return null

  const filtered = filter === "all" ? logs : logs.filter(l => l.level === filter)
  const phaseIcon: Record<string, string> = {
    orchestrator: "🧠",
    scanner: "🔍",
    aggregation: "🤖",
    system: "⚙️",
  }
  const levelColor: Record<string, string> = {
    info: "text-blue-400",
    warn: "text-amber-400",
    error: "text-destructive",
    debug: "text-muted-foreground",
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
          <FileScan className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold">扫描活动日志</h2>
            <Badge variant="outline" className="text-xs">{logs.length} 条</Badge>
          </div>
          <p className="text-xs text-muted-foreground">Scan Activity Log — 完整的 AI 编排与扫描器调用记录</p>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border/50 text-xs font-medium hover:bg-accent transition-colors"
        >
          {expanded ? "收起日志" : "展开日志"}
          <ChevronDown className={`h-3 w-3 transition-transform ${expanded ? "rotate-180" : ""}`} />
        </button>
      </div>

      {expanded && (
        <Card className="border-border/50">
          <CardContent className="p-0">
            {/* Filter bar */}
            <div className="flex items-center gap-1.5 px-4 py-2 border-b border-border/50 bg-muted/20">
              {["all", "info", "warn", "error"].map(l => (
                <button
                  key={l}
                  onClick={() => setFilter(l)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                    filter === l ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {l === "all" ? "全部" : l === "info" ? "ℹ️ 信息" : l === "warn" ? "⚠️ 警告" : "❌ 错误"}
                </button>
              ))}
            </div>
            {/* Log entries */}
            <div className="max-h-80 overflow-y-auto font-mono text-[11px] leading-relaxed">
              {filtered.length === 0 ? (
                <div className="p-6 text-center text-muted-foreground">无匹配日志</div>
              ) : (
                filtered.map((log, i) => {
                  const time = new Date(log.timestamp).toLocaleTimeString("zh-CN", { hour12: false })
                  return (
                    <div key={i} className={`flex items-start gap-2 px-4 py-1.5 border-b border-border/20 last:border-0 hover:bg-accent/30 transition-colors`}>
                      <span className="shrink-0 text-muted-foreground w-16">{time}</span>
                      <span className="shrink-0">{phaseIcon[log.phase] || "•"}</span>
                      <span className={`shrink-0 font-bold ${levelColor[log.level] || ""}`}>
                        {log.level.toUpperCase().padEnd(5)}
                      </span>
                      <span className="flex-1 text-foreground/80">
                        {log.message}
                        {log.scannerName && <span className="text-muted-foreground ml-1">[{log.scannerName}]</span>}
                      </span>
                      {log.details && (
                        <span className="text-muted-foreground/60 max-w-[200px] truncate" title={log.details}>
                          {log.details}
                        </span>
                      )}
                    </div>
                  )
                })
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Report Section: Vulnerability Findings (by severity) ──────────────────

const SeveritySection = ({ severity, vulnerabilities, scanId }: { severity: string; vulnerabilities: ScanDetail["vulnerabilities"]; scanId: string }) => {
  const [expanded, setExpanded] = useState(false)
  const theme: Record<string, { icon: React.ReactNode; border: string; header: string; text: string }> = {
    Critical: { icon: <AlertTriangle className="h-4 w-4" />, border: "border-destructive/20", header: "bg-destructive/10 text-destructive border-b border-destructive/20", text: "text-destructive" },
    High: { icon: <AlertTriangle className="h-4 w-4" />, border: "border-red-500/20", header: "bg-red-500/10 text-red-500 border-b border-red-500/20", text: "text-red-500" },
    Medium: { icon: <AlertCircle className="h-4 w-4" />, border: "border-blue-500/20", header: "bg-blue-500/10 text-blue-500 border-b border-blue-500/20", text: "text-blue-500" },
    Low: { icon: <Info className="h-4 w-4" />, border: "border-emerald-500/20", header: "bg-emerald-500/10 text-emerald-500 border-b border-emerald-500/20", text: "text-emerald-500" },
  }
  const t = theme[severity] || theme.Low
  if (vulnerabilities.length === 0) return null

  return (
    <div className={`rounded-lg border ${t.border} overflow-hidden`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className={`w-full flex items-center justify-between px-4 py-3 ${t.header} transition-colors hover:opacity-90`}
      >
        <div className="flex items-center gap-2">
          {t.icon}
          <span className="text-sm font-bold">{severity}</span>
          <Badge variant="outline" className={`text-[10px] border-current/30`}>{vulnerabilities.length} 个</Badge>
        </div>
        <ChevronDown className={`h-4 w-4 transition-transform ${expanded ? "rotate-180" : ""}`} />
      </button>
      {expanded && (
        <div className="divide-y divide-border/50">
          {vulnerabilities.map((vuln, vi) => (
            <details key={vuln.id} className="group">
              <summary className="flex items-center gap-3 p-3 cursor-pointer hover:bg-accent/50 transition-colors list-none">
                <ChevronDown className="h-3.5 w-3.5 text-muted-foreground group-open:rotate-180 transition-transform shrink-0" />
                <SeverityBadge severity={vuln.severity} />
                <span className="text-sm font-medium flex-1">{vuln.name}</span>
                {vuln.source && (
                  <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${categoryThemes[scannerCategoryToKey(vuln.source)]?.border || "border-border/50"}`}>
                    {scannerIcons[vuln.source] || defaultScannerIcon}
                    {vuln.source}
                  </span>
                )}
                {vuln.cve !== "—" && vuln.isRealCve ? (
                  <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`} target="_blank" rel="noopener noreferrer" className="inline-flex">
                    <Badge variant="default" className="text-[10px] bg-red-900/30 text-red-400 hover:bg-red-900/50 border-red-800/50 gap-1">
                      <ExternalLink className="h-3 w-3" />
                      {vuln.cve}
                    </Badge>
                  </a>
                ) : vuln.cve !== "—" ? (
                  <Badge variant="outline" className="text-[10px] text-muted-foreground">{vuln.cve}</Badge>
                ) : null}
              </summary>
              <div className="px-4 pb-4 border-t border-border pt-3 space-y-3">
                <div className="grid sm:grid-cols-2 gap-3">
                  <div>
                    <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">位置</h4>
                    <code className="text-xs bg-muted px-2 py-1 rounded block truncate">{vuln.location}</code>
                  </div>
                  <div>
                    <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">严重度</h4>
                    <SeverityBadge severity={vuln.severity} />
                  </div>
                </div>
                <div>
                  <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">漏洞描述</h4>
                  <p className="text-sm">{vuln.description}</p>
                </div>
                {vuln.recommendation && (
                  <div>
                    <h4 className="text-[10px] font-medium text-emerald-500 uppercase tracking-wider mb-1">修复建议</h4>
                    <p className="text-sm text-muted-foreground bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-3">{vuln.recommendation}</p>
                  </div>
                )}
                <div className="flex items-center gap-2 pt-2">
                  <button
                    onClick={async () => {
                      try {
                        await fetch(`/api/scans/${scanId}/suppress`, {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify({
                            scanner: vuln.source,
                            cve: vuln.cve,
                            id: vuln.id,
                            comment: `False positive: ${vuln.name}`,
                          }),
                        })
                        // 刷新页面
                        window.location.reload()
                      } catch {}
                    }}
                    className="text-[10px] text-muted-foreground/50 hover:text-red-400 transition-colors underline underline-offset-2"
                  >
                    标记为误报
                  </button>
                </div>
                {vuln.code && (
                  <div>
                    <h4 className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-1">相关代码</h4>
                    <pre className="bg-black/40 rounded-lg p-3 overflow-x-auto text-sm"><code className="text-xs">{vuln.code}</code></pre>
                  </div>
                )}
                {vuln.codeFix && (
                  <div>
                    <h4 className="text-[10px] font-medium text-emerald-500 uppercase tracking-wider mb-1">修复代码</h4>
                    <pre className="bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3 overflow-x-auto text-sm"><code className="text-xs">{vuln.codeFix}</code></pre>
                  </div>
                )}
              </div>
            </details>
          ))}
        </div>
      )}
    </div>
  )
}

function scannerCategoryToKey(source: string): string {
  const map: Record<string, string> = {
    semgrep: "sast", bandit: "sast",
    gitleaks: "secret",
    "npm-audit": "dependency", "pip-audit": "dependency",
    trivy: "filesystem", checkov: "filesystem", nuclei: "filesystem", wapiti: "filesystem", sqlmap: "filesystem",
    subfinder: "dns", assetfinder: "dns", shuffledns: "dns", amass: "dns",
    nmap: "network", "tls-analyzer": "network",
    ffuf: "web", gobuster: "web", kiterunner: "web", httpx: "web", wafw00f: "web", gitdumper: "web",
    "http-headers": "web", "cors-detector": "web", "form-analyzer": "web", "error-analyzer": "web",
    "favicon-analyzer": "web", "third-party-deps": "web",
    gau: "osint", waybackurls: "osint",
  }
  return map[source] || "web"
}

function VulnerabilityDetails({ vulnerabilities, scanId }: { vulnerabilities: ScanDetail["vulnerabilities"]; scanId: string }) {
  const groups: Record<string, ScanDetail["vulnerabilities"]> = { Critical: [], High: [], Medium: [], Low: [] }
  for (const v of vulnerabilities) {
    if (groups[v.severity]) groups[v.severity].push(v)
  }

  const total = vulnerabilities.length

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-destructive/10 flex items-center justify-center">
          <AlertTriangle className="h-4 w-4 text-destructive" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold">漏洞发现详情</h2>
            <Badge variant="outline" className="text-xs">{total} 个发现</Badge>
          </div>
          <p className="text-xs text-muted-foreground">Vulnerability Findings — 按严重度分类</p>
        </div>
      </div>

      {total === 0 && (
        <Card className="border-emerald-500/20 bg-emerald-500/[0.02]">
          <CardContent className="flex items-center gap-3 p-6">
            <CheckCircle2 className="h-8 w-8 text-emerald-500" />
            <div>
              <p className="font-semibold text-emerald-500">未发现安全漏洞</p>
              <p className="text-sm text-muted-foreground">所有扫描检查均通过，目标安全状况良好</p>
            </div>
          </CardContent>
        </Card>
      )}

      {["Critical", "High", "Medium", "Low"].map(sev => (
        <SeveritySection key={sev} severity={sev} vulnerabilities={groups[sev] || []} scanId={scanId} />
      ))}
    </div>
  )
}

// ─── Report Section: AI Deep Analysis ──────────────────────────────────────────

function AIDeepAnalysis({ scan }: { scan: ScanDetail }) {
  const { t } = useI18n()
  const llm = useLLMAnalysis()

  const handleAnalyze = () => {
    const vulnPayload = (scan.vulnerabilities || []).map(v => ({
      name: v.name,
      severity: v.severity,
      location: v.location,
      description: v.description,
    }))
    llm.mutate({
      target: scan.target,
      riskScore: scan.riskScore,
      summary: scan.summary,
      vulnerabilities: vulnPayload,
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-violet-500/10 flex items-center justify-center">
          <Sparkles className="h-4 w-4 text-violet-500" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold">AI 深度安全分析</h2>
            <Badge variant="outline" className="border-violet-500/30 text-violet-500 text-[10px]">DeepSeek</Badge>
          </div>
          <p className="text-xs text-muted-foreground">AI Deep Security Analysis — 风险评估 · 架构审查 · 合规建议</p>
        </div>
        {!llm.data && !llm.isPending && (
          <button
            onClick={handleAnalyze}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-500/10 hover:bg-violet-500/20 text-violet-500 text-sm font-medium transition-colors shrink-0"
          >
            <Sparkles className="h-4 w-4" />
            {t("ai.analyze")}
          </button>
        )}
      </div>

      <div className="space-y-4">
        {/* Waiting state */}
        {llm.isPending && (
          <Card className="border-violet-500/20">
            <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="h-8 w-8 animate-spin mb-3" />
              <p className="font-medium">{t("ai.analyzing")}</p>
              <p className="text-sm mt-1">DeepSeek 正在分析扫描结果...</p>
            </CardContent>
          </Card>
        )}

        {/* Error state */}
        {llm.error && (
          <Card className="border-destructive/20">
            <CardContent className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <AlertCircle className="h-10 w-10 mb-3 text-destructive" />
              <p className="font-medium">{t("ai.error")}</p>
              <p className="text-sm mt-1">{t("ai.errorDesc")}</p>
              <p className="text-xs mt-2 text-destructive/70 font-mono">{(llm.error as Error)?.message || "未知错误"}</p>
              <button
                onClick={handleAnalyze}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-sm font-medium hover:bg-accent transition-colors"
              >
                {t("ai.retry")}
              </button>
            </CardContent>
          </Card>
        )}

        {/* Analysis results */}
        {llm.data && (
          <>
            <Card className="border-violet-500/20">
              <CardContent className="p-5 space-y-4">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <Shield className="h-4 w-4 text-violet-500" />
                  风险评估
                </h3>
                <p className="text-sm text-muted-foreground leading-relaxed bg-muted/30 rounded-lg p-4 border border-border/40">{llm.data.riskAssessment}</p>
              </CardContent>
            </Card>

            <div className="grid gap-4 sm:grid-cols-2">
              <Card className="border-amber-500/20">
                <CardContent className="p-5 space-y-3">
                  <h3 className="flex items-center gap-2 text-sm font-semibold">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    优先修复项
                  </h3>
                  <ul className="space-y-2">
                    {llm.data.priorityFixes.map((fix, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" />
                        <span>{fix}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>

              <Card className="border-destructive/20">
                <CardContent className="p-5 space-y-3">
                  <h3 className="flex items-center gap-2 text-sm font-semibold">
                    <AlertCircle className="h-4 w-4 text-destructive" />
                    架构风险
                  </h3>
                  <ul className="space-y-2">
                    {llm.data.architectureRisks.map((risk, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <span className="text-destructive mt-0.5 shrink-0">•</span>
                        <span>{risk}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            </div>

            {llm.data.complianceNotes.length > 0 && (
              <Card className="border-blue-500/20">
                <CardContent className="p-5 space-y-3">
                  <h3 className="flex items-center gap-2 text-sm font-semibold">
                    <Shield className="h-4 w-4 text-blue-500" />
                    合规审查
                  </h3>
                  <ul className="space-y-1.5">
                    {llm.data.complianceNotes.map((note, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <span className="text-blue-500 mt-0.5 shrink-0">•</span>
                        <span>{note}</span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            <Card className="border-amber-500/20 bg-amber-500/[0.02]">
              <CardContent className="p-5 space-y-3">
                <h3 className="flex items-center gap-2 text-sm font-semibold">
                  <Lightbulb className="h-4 w-4 text-amber-500" />
                  综合建议
                </h3>
                <p className="text-sm text-muted-foreground leading-relaxed bg-amber-500/5 border border-amber-500/10 rounded-lg p-4">{llm.data.overallAdvice}</p>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </div>
  )
}

// ─── SARIF Download Button ──────────────────────────────────────────────────────

function SarifDownloadButton({ scan }: { scan: ScanDetail }) {
  const [state, setState] = useState<"idle" | "loading" | "error">("idle")

  const handleDownload = async () => {
    if (state === "loading") return
    setState("loading")

    try {
      const { convertToSarif, getSarifFilename } = await import("@/lib/sarif-converter")
      const sarifJson = convertToSarif(scan)
      const blob = new Blob([sarifJson], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = getSarifFilename(scan.id)
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setState("idle")
    } catch (err) {
      console.error("SARIF export failed:", err)
      setState("error")
      setTimeout(() => setState("idle"), 4000)
    }
  }

  return (
    <div className="relative">
      <button
        onClick={handleDownload}
        disabled={state === "loading"}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-full hover:bg-accent transition-colors disabled:opacity-50"
        title="导出 SARIF 格式（GitHub/VSCode 兼容）"
      >
        {state === "loading" ? (
          <Loader2 className="h-3 w-3 animate-spin" />
        ) : (
          <FileDown className="h-3 w-3" />
        )}
        {state === "loading" ? "..." : "SARIF"}
      </button>

      {state === "error" && (
        <div className="absolute top-full right-0 mt-2 z-50 flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/20 text-destructive text-xs rounded-lg shadow-lg whitespace-nowrap">
          <AlertCircle className="h-3 w-3 shrink-0" />
          <span>导出失败，请稍后重试</span>
        </div>
      )}
    </div>
  )
}

// ─── Main Report Template ───────────────────────────────────────────────────────

function SecurityReport({ scan }: { scan: ScanDetail }) {
  const vulnerabilities = scan.vulnerabilities ?? []
  const aggregation: AggregationSummary | null = scan.aiAggregation || null
  const plan = scan.orchestratorPlan
  const createdAt = scan.createdAt || new Date().toISOString()

  // Compute duration from progress data
  const duration = (scan.progress?.elapsed)
    ? formatTime(scan.progress.elapsed)
    : (scan.progress?.percent === 100 && scan.progress?.elapsed)
      ? formatTime(scan.progress.elapsed)
      : "—"

  const sectionStyle = "scroll-mt-20"

  return (
    <div id="security-report" className="max-w-5xl mx-auto space-y-10 pb-20">
      {/* Sticky section nav */}
      <div className="sticky top-0 z-10 -mx-4 px-4 py-2 bg-background/80 backdrop-blur-md border-b border-border/40 mb-2 print:hidden">
        <div className="flex items-center gap-1 overflow-x-auto text-xs text-muted-foreground scrollbar-none">
          {[
            { id: "summary", label: "摘要", icon: BarChart3 },
            { id: "methodology", label: "方案", icon: Brain },
            { id: "scanners", label: "执行", icon: Shield },

            { id: "aggregation", label: "聚合", icon: Brain },
            { id: "findings", label: "漏洞", icon: AlertTriangle },
            { id: "analysis", label: "分析", icon: Sparkles },
          ].map(s => (
            <a key={s.id} href={`#${s.id}`}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-full hover:bg-accent transition-colors whitespace-nowrap">
              <s.icon className="h-3 w-3" />
              {s.label}
            </a>
          ))}
          {/* Download SARIF */}
          <SarifDownloadButton scan={scan} />
          {/* Download PDF */}
          <DownloadPdfButton scanId={scan.id} />
          {/* Print */}
          <button onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full hover:bg-accent transition-colors">
            <Printer className="h-3 w-3" />
            Print
          </button>
        </div>
      </div>

      {/* Report Header */}
      <div id="summary">
        <ReportHeader scan={scan} duration={duration} />
      </div>

      {/* PDF Download Action */}
      <DownloadPdfButton scanId={scan.id} variant="prominent" />

      {/* Executive Summary */}
      <ExecutiveSummary scan={scan} aggregation={aggregation} />

      {/* Divider */}
      <div className="border-t border-border/50" />

      {/* Section 1: Scan Methodology (编排计划) */}
      <div id="methodology" className={sectionStyle}>
        {plan ? (
          <ScanMethodology plan={plan} />
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
                <Brain className="h-4 w-4 text-muted-foreground" />
              </div>
              <div>
                <h2 className="text-lg font-bold">扫描方案与方法论</h2>
                <p className="text-xs text-muted-foreground">Scan Methodology</p>
              </div>
            </div>
            <Card className="border-border/50">
              <CardContent className="p-4">
                <p className="text-sm text-muted-foreground">
                  此扫描未使用 AI 编排（fallback 模式），使用传统逻辑直接选择扫描器。
                </p>
              </CardContent>
            </Card>
          </div>
        )}
      </div>

      {/* Divider */}
      <div className="border-t border-border/50" />



      {/* Section 2: Scanner Results */}
      <div id="scanners" className={sectionStyle}>
        <ScannerResultsTable scanners={scan.scanners} vulnerabilities={vulnerabilities} />
      </div>

      {/* Divider */}
      <div className="border-t border-border/50" />

      {/* Section 3: AI Aggregation Report */}
      {aggregation && (
        <>
          <div id="aggregation" className={sectionStyle}>
            <AIAggregationReport aggregation={aggregation} vulnerabilities={vulnerabilities} />
          </div>
          <div className="border-t border-border/50" />
        </>
      )}

      {/* Section 4: Vulnerability Details */}
      <div id="findings" className={sectionStyle}>
        <VulnerabilityDetails vulnerabilities={vulnerabilities} scanId={scan?.id || ""} />
      </div>

      {/* Divider */}
      <div className="border-t border-border/50" />

      {/* Section 5: AI Deep Analysis */}
      <div id="analysis" className={sectionStyle}>
        <AIDeepAnalysis scan={scan} />
      </div>

      {/* Divider */}
      <div className="border-t border-border/50" />

      {/* Section 6: Scan Activity Log (debug) */}
      <ScanLogViewer logs={scan.logs} />

      {/* Report Footer */}
      <div className="border-t border-border/40 pt-6 text-center text-[10px] text-muted-foreground/50 space-y-1">
        <p>VulnGuard Security Scan Report · Generated by DeepSeek AI Orchestrator</p>
        <p>Scan ID: {scan.id} · Generated at {formatDate(new Date().toISOString())}</p>
        <p className="text-[9px]">This report is automatically generated. Findings should be reviewed by a security professional before taking action.</p>
      </div>
    </div>
  )
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function ScanDetailPage() {
  const params = useParams() as { id: string }
  const { t } = useI18n()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const sseRef = useRef<EventSource | null>(null)

  useEffect(() => {
    const id = params.id
    if (!id) return

    setLoading(true)
    setError("")

    // 自动触发扫描：如果 session 状态是 pending，调 start 启动
    const startScan = async () => {
      try {
        const res = await fetch(`/api/scans/${id}/start`, { method: "POST" })
        if (!res.ok) console.warn("Scan auto-start failed:", res.status)
      } catch (e) {
        console.warn("Scan auto-start error:", e)
      }
    }
    startScan()

    // 优先使用 SSE 实时推送，降级到轮询
    let fallbackTimer: ReturnType<typeof setInterval> | null = null

    function startSSE() {
      const es = new EventSource(`/api/scan-progress/${id}`)
      sseRef.current = es

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as ScanDetail
          setScan(data)
          setLoading(false)
          if (data.status === "completed" || data.status === "failed") {
            es.close()
            sseRef.current = null
          }
        } catch { /* ignore parse errors */ }
      }

      es.addEventListener("done", () => {
        es.close()
        sseRef.current = null
      })

      es.addEventListener("error", () => {
        es.close()
        sseRef.current = null
        // SSE 不可用，降级到轮询
        if (!fallbackTimer) {
          const poll = () => {
            fetch(`/api/scans/${id}`)
              .then(r => r.json() as Promise<ScanDetail>)
              .then(data => {
                setScan(data)
                setLoading(false)
                if (data.status === "completed" || data.status === "failed") {
                  if (fallbackTimer) clearInterval(fallbackTimer)
                  fallbackTimer = null
                }
              })
              .catch(() => {})
          }
          poll()
          fallbackTimer = setInterval(poll, POLL_INTERVAL)
        }
      })
    }

    startSSE()

    return () => {
      if (sseRef.current) {
        sseRef.current.close()
        sseRef.current = null
      }
      if (fallbackTimer) {
        clearInterval(fallbackTimer)
        fallbackTimer = null
      }
    }
  }, [params.id])

  const isInProgress = !scan || scan.status === "pending" || scan.status === "scanning"

  if (isInProgress) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <ScanProgressView progress={scan?.progress ?? null} engine={scan?.engine} totalFiles={scan?.totalFiles} skippedFiles={scan?.skippedFiles} />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
        <AlertCircle className="h-10 w-10 mb-3 text-destructive" />
        <p className="font-medium">{t("common.failedToLoad")}</p>
        <p className="text-sm mt-1">{error}</p>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin mr-3" />
        <span>{t("common.loading")}</span>
      </div>
    )
  }

  return <SecurityReport scan={scan} />
}
