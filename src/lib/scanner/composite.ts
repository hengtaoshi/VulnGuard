import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult, AggregationReport } from "./types"
import type { Scanner } from "./types"
import { getAvailableScanners } from "./registry"
import { updateSession } from "./scan-store"
import { createOrchestratorPlan } from "./orchestrator"
import type { ScanPlan } from "./orchestrator"
import { aggregateScanResults } from "./ai-aggregator"
import { SCANNER_MANIFEST } from "./manifest"
import { addLog } from "./scan-log"

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

// ─── Plan-Based Execution (used by AI/All engines) ──────────────────────────

async function executeScannersByPlan(
  allScanners: Scanner[],
  plan: ScanPlan,
  targetPath: string,
  mode: "url" | "source",
  sessionId?: string,
): Promise<CompositeResult> {
  const scannerMap = new Map(allScanners.map(s => [s.name, s]))

  // Build ordered scanner list from plan's parallelGroups
  const orderedNames = plan.parallelGroups.flat()
  const orderedScanners = orderedNames
    .map(name => scannerMap.get(name))
    .filter((s): s is Scanner => s !== undefined)

  if (orderedScanners.length === 0) {
    return { vulnerabilities: [], totalChecks: 0, scannerResults: [] }
  }

  // ── Parallel Group Size Safeguard ──────────────────────────────────
  // The AI orchestrator sometimes puts all scanners in a single group,
  // which overwhelms slow dev servers and causes timeouts. Split any
  // group larger than MAX_GROUP_SIZE into multiple sub-groups.
  const MAX_GROUP_SIZE = 8
  const originalGroupCount = plan.parallelGroups.length
  const newGroups: string[][] = []
  for (const group of plan.parallelGroups) {
    if (group.length > MAX_GROUP_SIZE) {
      for (let i = 0; i < group.length; i += MAX_GROUP_SIZE) {
        newGroups.push(group.slice(i, i + MAX_GROUP_SIZE))
      }
    } else {
      newGroups.push(group)
    }
  }
  if (newGroups.length !== originalGroupCount) {
    plan.parallelGroups = newGroups
    console.warn(
      `[composite] Split ${originalGroupCount} parallel groups into ${newGroups.length} ` +
      `(max ${MAX_GROUP_SIZE} scanners/group) to prevent target overload`,
    )
  }

  const scannerStatuses = makeScannerStatuses(orderedScanners)
  const totalScanners = orderedScanners.length
  const startTime = Date.now()
  const completedTimes: number[] = []

  function saveProgress(currentScanner: string, doneCount: number, results: typeof scannerStatuses) {
    let percent = totalScanners > 0 ? Math.round((doneCount / totalScanners) * 100) : 100
    // Floor at 5% while scanners are running so the frontend animation stays active
    if (percent < 5 && doneCount < totalScanners && results.some(s => s.status === "running" || s.status === "pending")) {
      percent = 5
    }
    const elapsed = Date.now() - startTime
    let eta: number
    if (doneCount === 0) {
      eta = 0
    } else {
      completedTimes.push(elapsed)
      const maxT = Math.max(...completedTimes)
      const remaining = totalScanners - doneCount
      const confidence = doneCount / totalScanners
      const estimatedTotal = Math.round(maxT * (1 + (1 - confidence) * 3))
      eta = Math.max(Math.round(elapsed * 0.3), estimatedTotal - elapsed)
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
      progress: { percent: 3, currentScanner: "Starting scanners...", elapsed: 0, eta: 0, scannerStatuses },
    })
  }

  const allResults: ScanResult[] = []
  let completedCount = 0

  // Execute groups sequentially, scanners within a group concurrently
  for (const group of plan.parallelGroups) {
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

    // ── Concurrency limiter: run at most MAX_CONCURRENT scanners at once.
    // Without this, spawning 8+ subprocesses simultaneously on Windows
    // causes spawnSync ETIMEDOUT errors. Scanners are fast (most complete
    // in <5s) so a small limit adds negligible wall-clock time.
    const MAX_CONCURRENT = 5
    const runOneScanner = async (s: Scanner): Promise<void> => {
      let result: ScanResult
      if (s.name === "crawler") {
        const { runCrawlerScan } = await import("./crawler")
        result = await runCrawlerScan(targetPath, {
          onPageCrawled: (pageNum, totalEst, url, title) => {
            const pageInfo = title ? `${url.slice(0, 60)} (${title.slice(0, 30)})` : url.slice(0, 60)
            const crawlerIdx = scannerStatuses.findIndex(st => st.scannerName === "crawler")
            if (crawlerIdx >= 0) scannerStatuses[crawlerIdx].count = pageNum
            saveProgress(`🕷️ Crawling (${pageNum}/...) ${pageInfo}`, completedCount, scannerStatuses)
          },
        }).catch(err => ({
          vulnerabilities: [], totalChecks: 0,
          errors: [(err as Error).message], scannerName: s.name,
        }))
        if (sessionId) addLog(sessionId, "scanner", "info", `Starting ${s.displayName}`, undefined, s.name)
      } else {
        if (sessionId) addLog(sessionId, "scanner", "info", `Starting ${s.displayName}`, undefined, s.name)
        result = await s.scan(targetPath).catch(err => ({
          vulnerabilities: [], totalChecks: 0,
          errors: [(err as Error).message], scannerName: s.name,
        }))
      }
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
          const level = /no historical|not found|could not fetch|no results/i.test(errMsg) ? "info"
            : /not found|not installed/i.test(errMsg) ? "warn" : "error"
          addLog(sessionId, "scanner", level, `${s.displayName} ${level === "info" ? "completed with note" : level === "warn" ? "skipped" : "failed"}`, errMsg, s.name)
        } else {
          addLog(sessionId, "scanner", "info", `${s.displayName} complete: ${result.vulnerabilities.length} issues`,
            result.vulnerabilities.length > 0
              ? `Found: ${result.vulnerabilities.slice(0, 5).map(v => v.name).join(", ")}${result.vulnerabilities.length > 5 ? ` +${result.vulnerabilities.length - 5} more` : ""}`
              : undefined, s.name)
        }
      }
      const stillRunning = scannerStatuses.filter(st => st.status === "running").map(st => st.displayName)
      saveProgress(stillRunning.length > 0 ? stillRunning.join(", ") : "Finalizing...", completedCount, scannerStatuses)
      allResults.push(result)
    }

    // Execute with sliding-window concurrency limit
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
  }

  // ── Dynamic Deep Scan Escalation ──────────────────────────────────
  // After all planned phases complete, check for indicators that suggest
  // injection/deep scanning is warranted. If found AND the plan didn't
  // include deep scanners (wapiti, sqlmap, nuclei), add them dynamically.
  if (mode === "url") {
    const hasForms = allResults.some(r =>
      r.scannerName === "form-analyzer" && r.vulnerabilities.length > 0,
    )
    const hasErrorLeaks = allResults.some(r =>
      r.scannerName === "error-analyzer" && r.vulnerabilities.length > 0,
    )
    const isLiveWeb = allResults.some(r =>
      r.scannerName === "httpx" && r.errors.length === 0,
    )
    const hasApiIndicators = allResults.some(r =>
      r.scannerName === "kiterunner" && r.vulnerabilities.length > 0,
    )
    const needsDeepScan = hasForms || hasErrorLeaks || hasApiIndicators || isLiveWeb

    const deepScannerNames = ["wapiti", "sqlmap", "nuclei"]
    const planIncludesDeep = deepScannerNames.some(n =>
      orderedNames.includes(n),
    )
    const availableDeep = deepScannerNames.filter(n =>
      scannerMap.has(n),
    )

    if (needsDeepScan && !planIncludesDeep && availableDeep.length > 0) {
      const deepScanners = availableDeep
        .map(n => scannerMap.get(n)!)
        .filter(s => s.isAvailable())

      if (deepScanners.length > 0) {
        saveProgress(
          "⚡ Dynamic escalation: injection indicators detected — adding deep scanners...",
          completedCount,
          scannerStatuses,
        )

        if (sessionId) {
          addLog(sessionId, "system", "info", `Dynamic escalation triggered`,
            `Reason: ${hasForms ? "forms" : ""}${hasErrorLeaks ? " error_leaks" : ""}${hasApiIndicators ? " api_patterns" : ""}${isLiveWeb ? " live_web" : ""}. Adding: ${deepScanners.map(s => s.displayName).join(", ")}`)
        }

        for (const s of deepScanners) {
          scannerStatuses.push({
            scannerName: s.name,
            displayName: s.displayName,
            category: s.category,
            count: 0,
            errors: [],
            status: "running",
          })
        }

        const deepResults = await Promise.all(
          deepScanners.map(async s => {
            const result = await s.scan(targetPath).catch(err => ({
              vulnerabilities: [],
              totalChecks: 0,
              errors: [(err as Error).message],
              scannerName: s.name,
            }))
            const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
            if (idx >= 0) {
              scannerStatuses[idx].status = result.errors.length > 0 ? "failed" : "completed"
              scannerStatuses[idx].count = result.vulnerabilities.length
              scannerStatuses[idx].errors = result.errors
            }
            completedCount++
            saveProgress(
              `Deep scan: ${s.displayName} completed`,
              completedCount,
              scannerStatuses,
            )
            return result
          }),
        )
        allResults.push(...deepResults)

        if (sessionId) {
          updateSession(sessionId, {
            dynamicEscalation: {
              reason: hasForms ? "forms_detected" : hasErrorLeaks ? "error_leaks_detected" : hasApiIndicators ? "api_detected" : "live_web_app",
              scannersAdded: deepScanners.map(s => s.name),
              totalVulnsFound: deepResults.reduce((sum, r) => sum + r.vulnerabilities.length, 0),
            },
          })
        }
      }
    }
  }

  // ── Store Crawler Results ─────────────────────────────────────────
  // Extract crawl data from the crawler scanner and persist to session
  if (sessionId) {
    for (const r of allResults) {
      if (r.scannerName === "crawler" && (r as any).crawlResult) {
        const cr = (r as any).crawlResult as import("./crawler").CrawlResult
        updateSession(sessionId, {
          crawlData: {
            totalPages: cr.totalPages,
            totalForms: cr.totalForms,
            totalPasswordFields: cr.totalPasswordFields,
            totalFileUploads: cr.totalFileUploads,
            sitemap: cr.sitemap,
            durationMs: cr.durationMs,
          },
        })
        break
      }
    }
  }

  // ── AI Aggregation Phase ──────────────────────────────────────────
  // Use DeepSeek to cross-correlate findings across scanners,
  // eliminate false positives, and produce unified results.
  let aggregatedVulns: Vulnerability[] | undefined
  let aggregationReport: AggregationReport | undefined

  if (allResults.length > 0) {
    // ── AI Animation: rotating messages ──────────────────────────
    const aiSteps = [
      "🤖 AI aggregating: cross-correlating findings across scanners...",
      "🤖 AI aggregating: analyzing vulnerability patterns...",
      "🤖 AI aggregating: eliminating false positives...",
      "🤖 AI aggregating: correlating related vulnerabilities...",
      "🤖 AI aggregating: computing confidence scores...",
      "🤖 AI aggregating: prioritizing high-risk findings...",
      "🤖 AI aggregating: generating unified report...",
    ]
    let aiStepIdx = 0
    saveProgress(aiSteps[0], completedCount, scannerStatuses)

    if (sessionId) {
      addLog(sessionId, "aggregation", "info", "AI aggregation starting",
        `Correlating ${allResults.length} scanner results, ${allResults.reduce((s, r) => s + r.vulnerabilities.length, 0)} total findings`)
    }

    const aiAnimTimer = setInterval(() => {
      aiStepIdx = (aiStepIdx + 1) % aiSteps.length
      saveProgress(aiSteps[aiStepIdx], completedCount, scannerStatuses)
    }, 2800)

    try {
      aggregationReport = await aggregateScanResults({
        target: targetPath,
        mode,
        scannerResults: allResults.map(r => ({
          scannerName: r.scannerName,
          vulnerabilities: r.vulnerabilities,
          totalChecks: r.totalChecks,
          errors: r.errors,
        })),
        scannerNames: orderedScanners.map(s => s.name),
      })

      clearInterval(aiAnimTimer)
      saveProgress("🤖 AI aggregation complete — processing results...", completedCount, scannerStatuses)

      if (sessionId) {
        addLog(sessionId, "aggregation", "info", "AI aggregation complete",
          `${aggregationReport.findings.length} findings (${aggregationReport.falsePositivesRemoved} false positives removed, ${aggregationReport.findings.filter(f => f.isCorrelated).length} correlated)`)
      }

      // Store the full aggregation report in session
      if (sessionId) {
        updateSession(sessionId, {
          aiAggregationReport: aggregationReport as any,
        })
      }

      // Use aggregated findings (exclude false positives)
      aggregatedVulns = aggregationReport.findings
        .filter(f => !f.isFalsePositive)
        .map(f => ({
          id: f.id,
          name: f.name,
          severity: f.severity,
          location: f.location,
          cve: f.cve,
          description: f.description,
          recommendation: f.recommendation,
          code: f.code,
          source: f.detectedBy.join(", "),
        }))

      const fpCount = aggregationReport.falsePositivesRemoved
      const correlatedCount = aggregationReport.findings.filter(f => f.isCorrelated).length

      if (sessionId) {
        const aggSummary = {
          totalFindings: aggregationReport.findings.length,
          falsePositivesRemoved: fpCount,
          highConfidence: aggregationReport.findings.filter(f => f.confidence === "high").length,
          mediumConfidence: aggregationReport.findings.filter(f => f.confidence === "medium").length,
          lowConfidence: aggregationReport.findings.filter(f => f.confidence === "low").length,
          correlatedFindings: correlatedCount,
          summary: aggregationReport.summary,
          priorityActions: aggregationReport.priorityActions,
        }
        updateSession(sessionId, { aiAggregation: aggSummary })
      }
    } catch (err) {
      clearInterval(aiAnimTimer)
      const msg = err instanceof Error ? err.message : String(err)
      console.warn("[composite] AI aggregation failed, falling back to simple dedup:", msg)
      if (sessionId) {
        addLog(sessionId, "aggregation", "error", "AI aggregation failed, using simple dedup fallback", msg)
      }
    }
  }

  // ── Build Final Vulnerability List ─────────────────────────────────
  let vulnerabilities: Vulnerability[]
  let totalChecks: number

  if (aggregatedVulns) {
    vulnerabilities = aggregatedVulns
    totalChecks = allResults.reduce((sum, r) => sum + r.totalChecks, 0)
  } else {
    // Fallback: simple dedup
    const vulnerabilityMap = new Map<string, Vulnerability>()
    for (const result of allResults) {
      for (const vuln of result.vulnerabilities) {
        const key = `${vuln.name}:${vuln.location}:${vuln.description.slice(0, 80)}`
        if (!vulnerabilityMap.has(key)) {
          vulnerabilityMap.set(key, vuln)
        }
      }
    }
    vulnerabilities = Array.from(vulnerabilityMap.values())
    totalChecks = allResults.reduce((sum, r) => sum + r.totalChecks, 0)
  }

  const finalScannerResults = allResults.map(result => ({
    scannerName: result.scannerName,
    displayName: orderedScanners.find(s => s.name === result.scannerName)?.displayName || result.scannerName,
    category: orderedScanners.find(s => s.name === result.scannerName)?.category || "unknown",
    count: result.vulnerabilities.length,
    errors: result.errors,
  }))

  return { vulnerabilities, totalChecks, scannerResults: finalScannerResults }
}

// ─── Fallback Scan (Traditional Logic) ──────────────────────────────────────

async function runFallbackScan(
  allScanners: Scanner[],
  targetPath: string,
  mode: "url" | "source",
  sessionId?: string,
): Promise<CompositeResult> {
  // Filter scanners by mode using manifest definitions
  const modeScannerNames = new Set(
    SCANNER_MANIFEST.filter(e => e.supportedModes.includes(mode)).map(e => e.name),
  )
  let scanners = allScanners.filter(s => modeScannerNames.has(s.name))

  const scannerStatuses = makeScannerStatuses(scanners)
  const totalScanners = scanners.length
  const startTime = Date.now()
  const completedTimes: number[] = []

  function saveProgress(currentScanner: string, doneCount: number, results: typeof scannerStatuses) {
    let percent = totalScanners > 0 ? Math.round((doneCount / totalScanners) * 100) : 100
    if (percent < 5 && doneCount < totalScanners && results.some(s => s.status === "running" || s.status === "pending")) {
      percent = 5
    }
    const elapsed = Date.now() - startTime
    let eta: number
    if (doneCount === 0) {
      eta = 0
    } else if (mode === "url") {
      completedTimes.push(elapsed)
      const maxT = Math.max(...completedTimes)
      const remaining = totalScanners - doneCount
      const confidence = doneCount / totalScanners
      const estimatedTotal = Math.round(maxT * (1 + (1 - confidence) * 3))
      eta = Math.max(Math.round(elapsed * 0.3), estimatedTotal - elapsed)
    } else {
      eta = Math.round((elapsed / doneCount) * (totalScanners - doneCount))
    }
    if (sessionId) {
      updateSession(sessionId, {
        progress: { percent, currentScanner, elapsed, eta, scannerStatuses: results },
      })
    }
  }

  // Initialize progress (preserve a small value since orchestrator may have shown progress)
  if (sessionId) {
    updateSession(sessionId, {
      status: "scanning",
      progress: { percent: 3, currentScanner: "Starting fallback scanners...", elapsed: 0, eta: 0, scannerStatuses },
    })
  }

  const allResults: ScanResult[] = []
  let completedCount = 0

  // ── Helper: run a batch of scanners concurrently and track progress ──
  async function runScannerBatch(batch: Scanner[], batchLabel: string): Promise<ScanResult[]> {
    for (const s of batch) {
      const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
      if (idx >= 0) scannerStatuses[idx].status = "running"
    }
    saveProgress(`⏳ ${batchLabel}...`, completedCount, scannerStatuses)

    return Promise.all(
      batch.map(s =>
        s.scan(targetPath).then(result => {
          const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
          if (idx >= 0) {
            scannerStatuses[idx].status = result.errors.length > 0 ? "failed" : "completed"
            scannerStatuses[idx].count = result.vulnerabilities.length
            scannerStatuses[idx].errors = result.errors
          }
          completedCount++
          const runningNames = scannerStatuses.filter(st => st.status === "running").map(st => st.displayName)
          saveProgress(runningNames.length > 0 ? runningNames.join(", ") : "Finalizing...", completedCount, scannerStatuses)

          if (sessionId) {
            if (result.errors.length > 0) {
              const errMsg = result.errors.join("; ")
              const isExpected = /no historical|not found|could not fetch|no results/i.test(errMsg)
              const isMissingTool = /not found|not installed/i.test(errMsg)
              const level = isMissingTool ? "warn" : isExpected ? "info" : "error"
              addLog(sessionId, "scanner", level,
                `${s.displayName} ${level === "info" ? "completed with note" : level === "warn" ? "skipped" : "failed"}`,
                errMsg, s.name)
            } else {
              addLog(sessionId, "scanner", "info", `${s.displayName} complete: ${result.vulnerabilities.length} issues`,
                result.vulnerabilities.length > 0 ? `Found: ${result.vulnerabilities.slice(0, 3).map(v => v.name).join(", ")}` : undefined,
                s.name)
            }
          }
          return result
        }).catch(err => {
          const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
          if (idx >= 0) {
            scannerStatuses[idx].status = "failed"
            scannerStatuses[idx].errors = [(err as Error).message]
          }
          completedCount++
          saveProgress(s.displayName, completedCount, scannerStatuses)
          if (sessionId) {
            addLog(sessionId, "scanner", "error", `${s.displayName} crashed`, (err as Error).message, s.name)
          }
          return { vulnerabilities: [], totalChecks: 0, errors: [(err as Error).message], scannerName: s.name }
        })
      ),
    )
  }

  // ── Run scanners in ordered batches ──
  // Divide scanners into groups: fast passive → probing → fuzzing → deep
  // This prevents one hanging scanner from blocking all results.

  if (sessionId) {
    addLog(sessionId, "system", "info", `Fallback scan starting with ${scanners.length} scanners`,
      scanners.map(s => s.displayName).join(", "))
  }

  if (mode === "url") {
    // URL mode: ordered batches by scanner category
    const categoryOrder = ["web", "network", "dns", "osint", "filesystem", "ai"]

    for (const cat of categoryOrder) {
      const batch = scanners.filter(s => s.category === cat)
      if (batch.length === 0) continue

      const batchLabel = `${cat} scanners (${batch.length})`
      const results = await runScannerBatch(batch, batchLabel)
      allResults.push(...results)
    }

    // Catch any scanners with uncategorized categories
    const uncategorized = scanners.filter(s => !categoryOrder.includes(s.category))
    if (uncategorized.length > 0) {
      const results = await runScannerBatch(uncategorized, `other scanners (${uncategorized.length})`)
      allResults.push(...results)
    }
  } else {
    // Source mode: ordered batches by scanner type, lower concurrency
    // to avoid disk I/O contention. AI scanner runs last.
    const aiScanners = scanners.filter(s => s.name === "ai-scanner")
    const traditionalScanners = scanners.filter(s => s.name !== "ai-scanner")
    const CONCURRENCY = 4

    for (let i = 0; i < traditionalScanners.length; i += CONCURRENCY) {
      const batch = traditionalScanners.slice(i, i + CONCURRENCY)
      const batchLabel = `source scanners (batch ${Math.floor(i / CONCURRENCY) + 1}/${Math.ceil(traditionalScanners.length / CONCURRENCY)})`
      const results = await runScannerBatch(batch, batchLabel)
      allResults.push(...results)
    }

    // Run AI scanner(s) last (network-bound)
    if (aiScanners.length > 0) {
      const results = await runScannerBatch(aiScanners, "ai scanner")
      allResults.push(...results)
    }
  }

  // Deduplicate vulnerabilities
  const vulnerabilityMap = new Map<string, Vulnerability>()
  for (const result of allResults) {
    for (const vuln of result.vulnerabilities) {
      const key = `${vuln.name}:${vuln.location}:${vuln.description.slice(0, 80)}`
      if (!vulnerabilityMap.has(key)) {
        vulnerabilityMap.set(key, vuln)
      }
    }
  }

  const vulnerabilities = Array.from(vulnerabilityMap.values())
  const totalChecks = allResults.reduce((sum, r) => sum + r.totalChecks, 0)

  if (sessionId) {
    addLog(sessionId, "system", "info", `Fallback scan summary: ${allResults.length} scanners, ${vulnerabilities.length} vulnerabilities`)
  }

  const finalScannerResults = allResults.map(result => ({
    scannerName: result.scannerName,
    displayName: scanners.find(s => s.name === result.scannerName)?.displayName || result.scannerName,
    category: scanners.find(s => s.name === result.scannerName)?.category || "unknown",
    count: result.vulnerabilities.length,
    errors: result.errors,
  }))

  return { vulnerabilities, totalChecks, scannerResults: finalScannerResults }
}

// ─── Main Entry Point ────────────────────────────────────────────────────────

export async function runCompositeScan(
  targetPath: string,
  mode: "url" | "source" = "source",
  sessionId?: string,
  engine: ScannerEngine = "ai",
): Promise<CompositeResult> {
  const scanners = getAvailableScanners()
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

  // ── Phase 1: AI Orchestrator Planning (animated progress) ──
  const orchestrationPhases =
    engine === "ai"
      ? [
          "🤖 AI orchestrator: analyzing target structure...",
          "🤖 AI orchestrator: detecting technology stack...",
          "🤖 AI orchestrator: evaluating scanner match...",
          "🤖 AI orchestrator: optimizing parallel schedule...",
          "🤖 AI orchestrator: generating scan plan...",
        ]
      : [
          "🤖 AI orchestrator: analyzing target for full coverage...",
          "🤖 AI orchestrator: scanning technology indicators...",
          "🤖 AI orchestrator: selecting all relevant scanners...",
          "🤖 AI orchestrator: building parallel execution groups...",
          "🤖 AI orchestrator: finalizing coverage plan...",
        ]

  setProgress(0, orchestrationPhases[0])

  let phaseIndex = 0
  const phaseTimer = setInterval(() => {
    phaseIndex++
    if (phaseIndex >= orchestrationPhases.length) {
      // Stay at the last message once all phases shown — never wrap back to 0
      return
    }
    setProgress(Math.min(phaseIndex * 2, 8), orchestrationPhases[phaseIndex])
  }, 1200)

  if (sessionId) {
    addLog(sessionId, "system", "info", `Starting scan: ${engine} engine, ${mode} mode, target: ${targetPath}`)
  }

  try {
    const plan = await createOrchestratorPlan({
      mode,
      target: targetPath,
      availableScannerNames: scanners.map(s => s.name),
      engine,
    })
    clearInterval(phaseTimer)

    // ── Phase 2: Plan Ready ──
    if (sessionId) {
      addLog(sessionId, "orchestrator", "info",
        `AI plan generated: ${plan.selectedScanners.length} scanners selected (${plan.scanPriority} priority)`,
        `Groups: ${plan.parallelGroups.map(g => g.join(", ")).join(" | ")}`)
    }
    const planScanners = plan.selectedScanners
      .map(name => scanners.find(s => s.name === name))
      .filter((s): s is Scanner => s !== undefined)

    const priorityLabel = { speed: "fast", depth: "deep", balanced: "balanced" }[plan.scanPriority] || plan.scanPriority
    const reviewLabel = plan.aiReview ? " + AI code review" : ""
    const planMsg = `✓ AI plan: ${plan.selectedScanners.length} scanners (${priorityLabel} priority${reviewLabel})`

    setProgress(3, planMsg, planScanners.map(s => ({
      scannerName: s.name,
      displayName: s.displayName,
      category: s.category,
      count: 0,
      errors: [] as string[],
      status: "pending" as const,
    })))

    if (sessionId) {
      updateSession(sessionId, { orchestratorPlan: plan as any })
    }

    // ── Phase 3: Execute Scanners ──
    const result = await executeScannersByPlan(scanners, plan, targetPath, mode, sessionId)

    // ── Phase 4: Complete ──
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

    if (sessionId) {
      addLog(sessionId, "system", "info", `AI scan complete: ${result.scannerResults.length} scanners finished`,
        `Total: ${result.vulnerabilities.length} vulnerabilities found across ${result.totalChecks} checks`)
    }

    return result
  } catch (err) {
    clearInterval(phaseTimer)
    const msg = err instanceof Error ? err.message : String(err)
    console.warn("[composite] Orchestrator failed, falling back:", msg)

    setProgress(0, `⚠️ AI orchestrator unavailable (${msg}) — using direct scanner selection`)

    // Store the fallback reason in the session for visibility in the report
    if (sessionId) {
      updateSession(sessionId, { error: `Orchestrator fallback: ${msg}` })
      addLog(sessionId, "orchestrator", "error", `AI orchestrator unavailable`,
        `Reason: ${msg}. Falling back to direct scanner selection.`)
    }

    const fallbackResult = await runFallbackScan(scanners, targetPath, mode, sessionId)

    if (sessionId) {
      addLog(sessionId, "system", "info", `Fallback scan complete: ${fallbackResult.scannerResults.length} scanners finished`,
        `Total: ${fallbackResult.vulnerabilities.length} vulnerabilities found`)
    }

    return fallbackResult
  }
}
