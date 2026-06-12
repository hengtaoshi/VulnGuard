import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult, Scanner } from "./types"
import { getAvailableScanners, getAllScanners } from "./registry"
import { updateSession } from "./scan-store"
import { addLog } from "./scan-log"
import { analyzeTarget } from "./target-analyzer"
import type { TargetAnalysis } from "./target-analyzer"
import { createOrchestratorPlan, createFallbackPlan } from "./orchestrator"
import type { OrchestratorPlan } from "./orchestrator"
import { aggregateScanResults } from "./ai-aggregator"
import { isLlmAvailable } from "./llm-client"
import { filterIgnored, getAllIgnoreRules } from "../ignore-rules"
import { execSync } from "child_process"
import { join } from "path"
import { writeFileSync, existsSync, mkdirSync } from "fs"

export type ScannerEngine = "ai" | "all"

export interface CompositeResult {
  vulnerabilities: Vulnerability[]
  totalChecks: number
  scannerResults: {
    scannerName: string
    displayName: string
    category: string
    count: number
    errors: string[]
  }[]
}

interface ScannerStatus {
  scannerName: string
  displayName: string
  category: string
  count: number
  errors: string[]
  status: "pending" | "running" | "completed" | "failed"
}

function makeScannerStatuses(scanners: { name: string; displayName: string; category: string }[]) {
  return scanners.map(s => ({
    scannerName: s.name,
    displayName: s.displayName,
    category: s.category,
    count: 0,
    errors: [] as string[],
    status: "pending" as ScannerStatus["status"],
  }))
}

// ─── 规则驱动的扫描器选择 ─────────────────────────────────────────────────

function selectScannersByRules(
  analysis: TargetAnalysis,
  engine: ScannerEngine,
  availableNames: string[],
): string[] {
  const selected: string[] = []
  const configNames = new Set(analysis.configDetails.map(c => c.name))
  const langs = new Set(Object.keys(analysis.languages)) // language names: "python", "javascript", etc.
  const hasSource = analysis.hasSourceCode || analysis.totalFiles > 0

  if (!hasSource) return []

  // ── 总是选中的扫描器 ──────────────────────────────────────────────
  selected.push("semgrep", "gitleaks")

  // ── 语言/框架匹配 ──────────────────────────────────────────────────
  // 注意：target-analyzer.ts 中语言 key 是名称（如 "python"），
  // config 名称是标识符（如 "hasRequirementsTxt"）

  // Python
  if (langs.has("python") || analysis.hasPython || configNames.has("hasRequirementsTxt") || configNames.has("hasPipfile") || configNames.has("hasSetupPy")) {
    selected.push("bandit", "pip-audit")
  }

  // JS/TS
  if (configNames.has("hasPackageLock") || configNames.has("hasPackageJson")) {
    selected.push("npm-audit")
  }

  // IaC
  if (analysis.hasIaC || configNames.has("hasDockerfile") || configNames.has("hasTerraform")) {
    selected.push("checkov")
  }

  // Java
  if (configNames.has("hasMavenPom") || configNames.has("hasGradle")) {
    selected.push("dependency-check")
  }

  // Go
  if (configNames.has("hasGoMod")) {
    selected.push("dependency-check")
  }

  // Rust
  if (configNames.has("hasCargoToml")) {
    selected.push("dependency-check")
  }

  // C/C++
  if (langs.has("c") || langs.has("cpp") || configNames.has("hasConanfile") || configNames.has("hasVcpkg")) {
    selected.push("cve-cpp")
  }

  // Swift
  if (langs.has("swift") || configNames.has("hasSwiftPackage")) {
    selected.push("swift")
  }

  // .NET
  if (langs.has("csharp") || configNames.has("hasCsproj")) {
    selected.push("dependency-check")
  }

  // ── CodeQL（语义 SAST，覆盖多语言） ──────────────────────────────────
  const codeqlLangs = ["javascript", "typescript", "python", "java", "go", "c", "cpp", "csharp", "swift", "ruby"]
  if (langs.size > 0 && codeqlLangs.some(l => langs.has(l))) {
    selected.push("codeql")
  }

  // ── 综合性扫描器 ─────────────────────────────────────────────────
  // trivy: comprehensive, always useful
  selected.push("trivy")

  // nuclei: medium+ projects
  if (analysis.totalFiles > 20) {
    selected.push("nuclei")
  }

  // Filter by availability and deduplicate
  const result = selected.filter((n, i, a) => a.indexOf(n) === i).filter(n => availableNames.includes(n))

  // "all" engine: add every available scanner
  if (engine === "all") {
    return availableNames
  }

  return result
}

function buildParallelGroups(scannerNames: string[], allScanners: Scanner[]): string[][] {
  const groups: string[][] = []
  const fast: string[] = []
  const medium: string[] = []
  const slow: string[] = []

  const scannerMap = new Map(allScanners.map(s => [s.name, s]))

  for (const name of scannerNames) {
    const s = scannerMap.get(name)
    if (!s) continue
    // Categorize by scanner type
    if (s.category === "secret" || s.name === "semgrep") {
      fast.push(name)
    } else if (s.name === "codeql") {
      // CodeQL: db create + analyze is significantly slower than pattern-based SAST
      slow.push(name)
    } else if (s.category === "dependency" || s.category === "sast" || s.name === "checkov") {
      medium.push(name)
    } else {
      slow.push(name)
    }
  }

  if (fast.length > 0) groups.push(fast)
  if (medium.length > 0) groups.push(medium)
  if (slow.length > 0) groups.push(slow)

  // Fallback: if no groups formed, all in one
  if (groups.length === 0 && scannerNames.length > 0) {
    groups.push(scannerNames)
  }

  return groups
}

// ─── 执行扫描器 ────────────────────────────────────────────────────────────

async function executeScanners(
  allScanners: Scanner[],
  scannerNames: string[],
  targetPath: string,
  sessionId?: string,
): Promise<CompositeResult> {
  const scannerMap = new Map(allScanners.map(s => [s.name, s]))
  const orderedScanners = scannerNames
    .map(name => scannerMap.get(name))
    .filter((s): s is Scanner => s !== undefined)

  if (orderedScanners.length === 0) {
    return { vulnerabilities: [], totalChecks: 0, scannerResults: [] }
  }

  const groups = buildParallelGroups(scannerNames, allScanners)
  const scannerStatuses = makeScannerStatuses(orderedScanners)
  const totalScanners = orderedScanners.length
  const startTime = Date.now()
  const categoryRuntimeMs: Record<string, number[]> = {}
  const defaultEstimateMs: Record<string, number> = {
    secret: 8000,
    sast: 20000,
    dependency: 90000,
    filesystem: 120000,
  }
  const scannerStartTimes = new Map<string, number>()

  function saveProgress(
    currentScanner: string,
    doneCount: number,
    results: typeof scannerStatuses,
    completedScanner?: { name: string; category: string; runtime: number },
  ) {
    let percent = totalScanners > 0 ? Math.round((doneCount / totalScanners) * 100) : 100
    if (percent < 5 && doneCount < totalScanners && results.some(s => s.status === "running" || s.status === "pending")) {
      percent = 5
    }
    const elapsed = Date.now() - startTime

    // Record per-category runtime when a scanner just completed
    if (completedScanner) {
      const cat = completedScanner.category
      if (!categoryRuntimeMs[cat]) categoryRuntimeMs[cat] = []
      categoryRuntimeMs[cat].push(completedScanner.runtime)
    }

    // Estimate ETA: for each remaining scanner, use its category's average runtime
    // (or a conservative default if no data yet for that category)
    let eta = 0
    if (doneCount > 0) {
      const pendingScanners = results.filter(s => s.status === "running" || s.status === "pending")
      let estimatedRemainingMs = 0
      for (const ps of pendingScanners) {
        const cat = ps.category
        const catTimes = categoryRuntimeMs[cat]
        let perScannerEstimate: number
        if (catTimes && catTimes.length > 0) {
          // Use average of actual runtimes for this category
          perScannerEstimate = Math.round(catTimes.reduce((a, b) => a + b, 0) / catTimes.length)
        } else if (defaultEstimateMs[cat] !== undefined) {
          perScannerEstimate = defaultEstimateMs[cat]
        } else {
          perScannerEstimate = 60000 // 60s fallback for unknown categories
        }
        estimatedRemainingMs += perScannerEstimate
      }
      // Safety floor: at least 15s per remaining scanner
      const safetyFloor = pendingScanners.length * 15000
      eta = Math.max(safetyFloor, estimatedRemainingMs)
    }

    if (sessionId) {
      updateSession(sessionId, {
        progress: { percent, currentScanner, elapsed, eta, scannerStatuses: results },
      })
    }
  }

  if (sessionId) {
    updateSession(sessionId, {
      status: "scanning",
      progress: { percent: 0, currentScanner: "Preparing scanners...", elapsed: 0, eta: 0, scannerStatuses },
    })
  }

  const allResults: ScanResult[] = []
  let completedCount = 0

  // Execute groups sequentially, scanners within a group concurrently
  for (const group of groups) {
    const groupScanners = group
      .map(name => scannerMap.get(name))
      .filter((s): s is Scanner => s !== undefined)

    if (groupScanners.length === 0) continue

    // Mark all scanners in this group as running
    for (const s of groupScanners) {
      const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
      if (idx >= 0) scannerStatuses[idx].status = "running"
    }

    const runningDisplay = groupScanners.map(s => s.displayName).join(", ")
    saveProgress(runningDisplay, completedCount, scannerStatuses)

    // Heartbeat: update progress every 5s during long-running scanners to keep UI alive
    const heartbeat = setInterval(() => {
      const stillRunning = scannerStatuses.filter(st => st.status === "running").map(st => st.displayName)
      if (stillRunning.length > 0) {
        saveProgress(stillRunning.join(", "), completedCount, scannerStatuses)
      }
    }, 5000)

    const MAX_CONCURRENT = 5

    const runOneScanner = async (s: Scanner): Promise<void> => {
      if (sessionId) addLog(sessionId, "scanner", "info", `Starting ${s.displayName}`, undefined, s.name)
      scannerStartTimes.set(s.name, Date.now())
      const result = await s.scan(targetPath).catch(err => ({
        vulnerabilities: [], totalChecks: 0,
        errors: [(err as Error).message], scannerName: s.name,
      }))
      const si = scannerStatuses.findIndex(st => st.scannerName === s.name)
      if (si >= 0) {
        scannerStatuses[si].status = result.errors.length > 0 ? "failed" : "completed"
        scannerStatuses[si].count = result.vulnerabilities.length
        scannerStatuses[si].errors = result.errors
      }
      completedCount++
      if (sessionId) {
        if (result.errors.length > 0) {
          const errMsg = result.errors.join("; ")
          const level = /no historical|not found|could not fetch|no results|no .* found/i.test(errMsg) ? "info"
            : /not found|not installed|no .* found/i.test(errMsg) ? "warn" : "error"
          addLog(sessionId, "scanner", level, `${s.displayName} ${level === "info" ? "completed with note" : level === "warn" ? "skipped" : "failed"}`, errMsg, s.name)
        } else {
          addLog(sessionId, "scanner", "info", `${s.displayName} complete: ${result.vulnerabilities.length} issues`,
            result.vulnerabilities.length > 0
              ? `Found: ${result.vulnerabilities.slice(0, 5).map(v => v.name).join(", ")}${result.vulnerabilities.length > 5 ? ` +${result.vulnerabilities.length - 5} more` : ""}`
              : undefined, s.name)
        }
      }
      const stillRunning = scannerStatuses.filter(st => st.status === "running").map(st => st.displayName)
      const completedScanner = {
        name: s.name,
        category: orderedScanners.find(osc => osc.name === s.name)?.category || "unknown",
        runtime: Date.now() - (scannerStartTimes.get(s.name) || Date.now()),
      }
      saveProgress(
        stillRunning.length > 0 ? stillRunning.join(", ") : "Finalizing...",
        completedCount,
        scannerStatuses,
        completedScanner,
      )
      allResults.push(result)
    }

    // Sliding-window concurrency limit
    const queue = [...groupScanners]
    const inFlight = new Set<Promise<void>>()
    while (queue.length > 0 || inFlight.size > 0) {
      while (inFlight.size < MAX_CONCURRENT && queue.length > 0) {
        const p = runOneScanner(queue.shift()!).then(() => { inFlight.delete(p) })
        inFlight.add(p)
      }
      if (inFlight.size > 0) {
        await Promise.race(Array.from(inFlight))
      }
    }
    clearInterval(heartbeat)
  }

  // ── 确定性去重 ──────────────────────────────────────────────────────
  // 真实 CVE 扫描器（产生如 CVE-2024-12345 格式的编号）
  const REAL_CVE_SCANNERS = new Set([
    "trivy", "npm-audit", "pip-audit", "dependency-check",
    "cve-cpp", "swift", "osv-scanner", "nuclei",
  ])

  const vulnerabilityMap = new Map<string, Vulnerability>()
  for (const result of allResults) {
    for (const vuln of result.vulnerabilities) {
      // 设置 isRealCve — 由 source 扫描器决定
      const isRealCve = REAL_CVE_SCANNERS.has(vuln.source || "")

      const key = `${vuln.name}:${vuln.location}:${vuln.description.slice(0, 80)}`
      if (!vulnerabilityMap.has(key)) {
        vulnerabilityMap.set(key, { ...vuln, isRealCve })
      }
    }
  }
  const vulnerabilities = Array.from(vulnerabilityMap.values())
  const totalChecks = allResults.reduce((sum, r) => sum + r.totalChecks, 0)

  const finalScannerResults = allResults.map(result => ({
    scannerName: result.scannerName,
    displayName: orderedScanners.find(s => s.name === result.scannerName)?.displayName || result.scannerName,
    category: orderedScanners.find(s => s.name === result.scannerName)?.category || "unknown",
    count: result.vulnerabilities.length,
    errors: result.errors,
  }))

  if (sessionId) {
    addLog(sessionId, "system", "info", `Scan complete: ${allResults.length} scanners, ${vulnerabilities.length} vulnerabilities`)
  }

  return { vulnerabilities, totalChecks, scannerResults: finalScannerResults }
}

// ─── 主入口 ────────────────────────────────────────────────────────────────

export async function runCompositeScan(
  targetPath: string,
  mode: "url" | "source" = "source",
  sessionId?: string,
  engine: ScannerEngine = "ai",
): Promise<CompositeResult> {
  const allScanners = getAllScanners()
  const availableScanners = getAvailableScanners()
  const availableNames = availableScanners.map(s => s.name)
  const startTime = Date.now()

  function setProgress(
    percent: number,
    currentScanner: string,
    scannerStatuses: ScannerStatus[] = [],
    extra: Partial<{ elapsed: number; eta: number }> = {},
  ) {
    if (!sessionId) return
    updateSession(sessionId, {
      status: "scanning",
      progress: {
        percent,
        currentScanner,
        elapsed: extra.elapsed ?? Date.now() - startTime,
        eta: extra.eta ?? 0,
        scannerStatuses,
      },
    })
  }

  // Resolve relative path to absolute
  targetPath = require("path").resolve(targetPath)

  // ── Phase 0: 目标分析 ────────────────────────────────────────────────
  let targetAnalysis: TargetAnalysis | null = null
  if (sessionId) {
    addLog(sessionId, "system", "info", `🔍 Analyzing target source code structure: ${targetPath}`)
  }
  try {
    const analysisStart = Date.now()
    targetAnalysis = analyzeTarget(targetPath)
    const elapsed = Date.now() - analysisStart

    if (sessionId && targetAnalysis) {
      const langList = Object.entries(targetAnalysis.languages)
        .sort(([, a], [, b]) => b.count - a.count)
        .slice(0, 5)
        .map(([lang, s]) => `${lang}(${s.count})`)
        .join(", ")
      addLog(sessionId, "system", "info",
        `📊 Target analysis: ${targetAnalysis.totalFiles} files, ${targetAnalysis.projectTypes.join("/")}`,
        `Languages: ${langList || "none"} | Configs: ${targetAnalysis.configDetails.map(c => c.name).join(", ") || "none"} | ${elapsed}ms`)
    }
  } catch (err) {
    console.warn("[composite] Target analysis failed, proceeding without it:", err)
    if (sessionId) {
      addLog(sessionId, "system", "warn", "⚠ Target analysis failed")
    }
  }

  // ── Phase 1: AI 编排 → 规则回退 ─────────────────────────────────────
  if (!targetAnalysis) {
    targetAnalysis = {
      targetPath,
      totalFiles: 0,
      totalDirs: 0,
      sizeCategory: "small",
      languages: {},
      configFiles: {},
      configDetails: [],
      hasIaC: false,
      projectTypes: ["unknown"],
      fileTreeSample: [],
      hasPython: false,
      hasSourceCode: true,
      analysisTimeMs: 0,
    }
  }

  let orchestratorPlan: OrchestratorPlan | null = null
  let selectedScanners: string[] = []

  // AI 编排：仅对 "ai" 引擎且 DeepSeek 可用时
  if (engine === "ai" && isLlmAvailable()) {
    if (sessionId) addLog(sessionId, "orchestrator", "info", "🤖 AI orchestrator analyzing target...")
    orchestratorPlan = await createOrchestratorPlan(targetAnalysis, engine, allScanners, availableNames)
  }

  if (orchestratorPlan) {
    selectedScanners = orchestratorPlan.selectedScanners
    if (sessionId) {
      addLog(sessionId, "orchestrator", "info",
        `🤖 AI orchestrator: selected ${selectedScanners.length} scanners: ${selectedScanners.join(", ")}`,
        `Priority: ${orchestratorPlan.scanPriority} | AI Review: ${orchestratorPlan.aiReview} | ${orchestratorPlan.reasoning.slice(0, 200)}`)
      updateSession(sessionId, { orchestratorPlan })
    }
  } else {
    // 规则回退（AI 不可用或 engine === "all"）
    selectedScanners = selectScannersByRules(targetAnalysis, engine, availableNames)
    if (sessionId) {
      addLog(sessionId, "system", "info",
        `Rules selected ${selectedScanners.length} scanners: ${selectedScanners.join(", ")}`)
    }
  }

  const selectedScannerObjects = selectedScanners
    .map(name => allScanners.find(s => s.name === name))
    .filter((s): s is Scanner => s !== undefined)

  const statuses = makeScannerStatuses(selectedScannerObjects)
  setProgress(0, `📋 ${orchestratorPlan ? "AI" : "Rules"} matched: ${selectedScanners.length} scanners selected`, statuses)

  // ── Phase 2: 执行扫描器 ─────────────────────────────────────────────
  const result = await executeScanners(allScanners, selectedScanners, targetPath, sessionId)

  // ── Phase 3: 误报过滤（.vulnguard-ignore + UI 标记）────────────────
  const { filtered: filteredVulns, ignoredCount } = filterIgnored(result.vulnerabilities)
  if (ignoredCount > 0 && sessionId) {
    addLog(sessionId, "system", "info", `🚫 Ignored ${ignoredCount} findings (suppressed by ignore rules)`)
  }
  // 替换 vulnerabilities 为过滤后的列表
  result.vulnerabilities = filteredVulns

  // ── Phase 4: 完成 ────────────────────────────────────────────────────
  setProgress(100, "✓ Scan complete. Generating report...",
    result.scannerResults.map(r => ({
      scannerName: r.scannerName,
      displayName: r.displayName,
      category: r.category,
      count: r.count,
      errors: r.errors,
      status: (r.errors.length > 0 ? "failed" : "completed") as "failed" | "completed",
    })),
  )

  // ── Phase 4: AI 聚合（跨引擎关联 + 假阳性检测）──────────────────────
  if (sessionId && isLlmAvailable()) {
    try {
      addLog(sessionId, "aggregation", "info", "🧠 AI aggregating scan results...")

      const scannerStats = result.scannerResults.map(r => ({
        scannerName: r.scannerName,
        count: r.count,
      }))

      // 获取现有忽略规则，作为上下文传给 AI 聚合器（避免重复误报）
      const existingIgnorePatterns = getAllIgnoreRules().map(r => r.pattern)

      const aggReport = await aggregateScanResults(
        result.vulnerabilities,
        scannerStats,
        targetPath,
        existingIgnorePatterns,
      )

      // 保存聚合报告到 session
      updateSession(sessionId, {
        aiAggregationReport: aggReport,
        aiAggregation: {
          totalFindings: aggReport.findings.length,
          falsePositivesRemoved: aggReport.falsePositivesRemoved,
          highConfidence: aggReport.findings.filter(f => f.confidence === "high").length,
          mediumConfidence: aggReport.findings.filter(f => f.confidence === "medium").length,
          lowConfidence: aggReport.findings.filter(f => f.confidence === "low").length,
          correlatedFindings: aggReport.findings.filter(f => f.isCorrelated).length,
          summary: aggReport.summary,
          priorityActions: aggReport.priorityActions,
        },
      })

      addLog(sessionId, "aggregation", "info",
        `🧠 AI aggregation complete: ${aggReport.findings.length} findings, ${aggReport.falsePositivesRemoved} false positives removed`,
        aggReport.priorityActions.slice(0, 3).join(" | "))
    } catch (err) {
      addLog(sessionId, "aggregation", "warn", `⚠ AI aggregation failed: ${(err as Error).message}`)
    }
  }

  // ── Phase 5: SBOM 生成 ───────────────────────────────────────────────
  if (sessionId) {
    try {
      const sbomDir = join(process.cwd(), ".scans", "sbom")
      if (!existsSync(sbomDir)) mkdirSync(sbomDir, { recursive: true })
      const sbomFile = join(sbomDir, `${sessionId}.cdx.json`)

      // 用 Trivy 生成 CycloneDX SBOM
      const trivyPath = join(process.cwd(), "tools", "bin", "trivy.exe")
      execSync(
        `"${trivyPath}" fs --format cyclonedx --output "${sbomFile}" "${targetPath}"`,
        { timeout: 120000, stdio: "pipe" },
      )

      if (existsSync(sbomFile)) {
        addLog(sessionId, "system", "info", `📦 SBOM generated: ${sessionId}.cdx.json`)
      }
    } catch (err) {
      addLog(sessionId, "system", "warn", `⚠ SBOM generation skipped: ${(err as Error).message}`)
    }
  }

  // ── Phase 5: Webhook 通知 ────────────────────────────────────────────
  const webhookUrl = process.env.WEBHOOK_URL
  if (webhookUrl && sessionId) {
    // 异步发送，不阻塞
    notifyWebhook(webhookUrl, { sessionId, target: targetPath, engine, result }).catch(() => {})
  }

  return result
}

// ─── Webhook 通知 ─────────────────────────────────────────────────────────

interface WebhookPayload {
  sessionId: string
  target: string
  engine: ScannerEngine
  result: CompositeResult
}

async function notifyWebhook(url: string, payload: WebhookPayload): Promise<void> {
  try {
    const { fetch } = await import("undici" as any) // Next.js polyfilled
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event: "scan.completed",
        scanId: payload.sessionId,
        target: payload.target,
        engine: payload.engine,
        timestamp: new Date().toISOString(),
        summary: {
          totalVulnerabilities: payload.result.vulnerabilities.length,
          totalChecks: payload.result.totalChecks,
          ...(() => {
            const c = { critical: 0, high: 0, medium: 0, low: 0 }
            for (const v of payload.result.vulnerabilities) {
              if (c[v.severity.toLowerCase() as keyof typeof c] !== undefined) c[v.severity.toLowerCase() as keyof typeof c]++
            }
            return c
          })(),
        },
        scanners: payload.result.scannerResults.map(s => ({
          name: s.scannerName,
          displayName: s.displayName,
          category: s.category,
          findings: s.count,
          errors: s.errors.length > 0 ? s.errors : undefined,
        })),
      }),
      signal: AbortSignal.timeout(10000),
    })
  } catch {
    // Webhook 失败不阻塞扫描
  }
}
