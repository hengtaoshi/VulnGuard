import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { getAvailableScanners } from "./registry"
import { updateSession } from "./scan-store"

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

export async function runCompositeScan(targetPath: string, mode: "url" | "source" = "source", sessionId?: string): Promise<CompositeResult> {
  const allScanners = getAvailableScanners()
  const dastScanners = ["wapiti", "sqlmap"]
  const scanners = allScanners.filter(s =>
    mode === "url" ? dastScanners.includes(s.name) : !dastScanners.includes(s.name)
  )

  const scannerStatuses = makeScannerStatuses(scanners)
  const totalScanners = scanners.length

  function saveProgress(currentScanner: string, doneCount: number, results: typeof scannerStatuses) {
    const percent = totalScanners > 0 ? Math.round((doneCount / totalScanners) * 100) : 100
    if (sessionId) {
      updateSession(sessionId, {
        progress: { percent, currentScanner, scannerStatuses: results },
      })
    }
  }

  // Initialize progress
  if (sessionId) {
    updateSession(sessionId, {
      status: "scanning",
      progress: { percent: 0, currentScanner: "", scannerStatuses },
    })
  }

  const allResults: ScanResult[] = []
  let completedCount = 0

  if (mode === "url") {
    for (const s of scanners) {
      const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
      if (idx >= 0) scannerStatuses[idx].status = "running"
      saveProgress(s.displayName, completedCount, scannerStatuses)

      const result = await s.scan(targetPath).catch(err => ({
        vulnerabilities: [], totalChecks: 0,
        errors: [(err as Error).message], scannerName: s.name,
      }))
      allResults.push(result)

      completedCount++
      if (idx >= 0) {
        scannerStatuses[idx].status = result.errors.length > 0 ? "failed" : "completed"
        scannerStatuses[idx].count = result.vulnerabilities.length
        scannerStatuses[idx].errors = result.errors
      }
      saveProgress(s.displayName, completedCount, scannerStatuses)
    }
  } else {
    const CONCURRENCY = 4
    for (let i = 0; i < scanners.length; i += CONCURRENCY) {
      const batch = scanners.slice(i, i + CONCURRENCY)

      for (const s of batch) {
        const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
        if (idx >= 0) scannerStatuses[idx].status = "running"
      }
      saveProgress("Running batch...", completedCount, scannerStatuses)

      await Promise.all(
        batch.map(s =>
          s.scan(targetPath)
            .then(result => {
              const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
              if (idx >= 0) {
                scannerStatuses[idx].status = result.errors.length > 0 ? "failed" : "completed"
                scannerStatuses[idx].count = result.vulnerabilities.length
                scannerStatuses[idx].errors = result.errors
              }
              completedCount++
              saveProgress(s.displayName, completedCount, scannerStatuses)
              return result
            })
            .catch(err => {
              const idx = scannerStatuses.findIndex(st => st.scannerName === s.name)
              if (idx >= 0) {
                scannerStatuses[idx].status = "failed"
                scannerStatuses[idx].errors = [(err as Error).message]
              }
              completedCount++
              saveProgress(s.displayName, completedCount, scannerStatuses)
              return { vulnerabilities: [], totalChecks: 0, errors: [(err as Error).message], scannerName: s.name }
            })
        )
      ).then(results => { allResults.push(...results) })
    }
  }

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

  const finalScannerResults = allResults.map(result => ({
    scannerName: result.scannerName,
    displayName: scanners.find(s => s.name === result.scannerName)?.displayName || result.scannerName,
    category: scanners.find(s => s.name === result.scannerName)?.category || "unknown",
    count: result.vulnerabilities.length,
    errors: result.errors,
  }))

  if (sessionId) {
    updateSession(sessionId, { progress: undefined })
  }

  return { vulnerabilities, totalChecks, scannerResults: finalScannerResults }
}
