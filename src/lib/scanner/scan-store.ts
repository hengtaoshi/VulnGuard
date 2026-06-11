import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from "fs"
import { join } from "path"
import type { ScanDetail, ScanSummary, Vulnerability, ScannerInfo, ScanProgress, LogEntry, ScannerEngine } from "@/lib/api/types"

export interface ScanSession {
  id: string
  target: string
  type: "url" | "source"
  status: "pending" | "scanning" | "completed" | "failed"
  riskScore: string
  totalChecks: number
  scannerEngine?: ScannerEngine
  summary: { critical: number; high: number; medium: number; low: number; passed: number }
  vulnerabilities: Vulnerability[]
  scanners?: ScannerInfo[]
  progress?: ScanProgress
  orchestratorPlan?: any
  /** Full aggregation report from AI (detailed findings with confidence, correlation) */
  aiAggregationReport?: any
  /** Summary of AI aggregation for API responses */
  aiAggregation?: {
    totalFindings: number
    falsePositivesRemoved: number
    highConfidence: number
    mediumConfidence: number
    lowConfidence: number
    correlatedFindings: number
    summary: string
    priorityActions: string[]
  }
  /** Dynamic escalation info (when deep scanners are auto-added) */
  dynamicEscalation?: {
    reason: string
    scannersAdded: string[]
    totalVulnsFound: number
  }
  /** Crawl data: discovered pages and sitemap */
  crawlData?: {
    totalPages: number
    totalForms: number
    totalPasswordFields: number
    totalFileUploads: number
    sitemap: { url: string; title: string; depth: number }[]
    durationMs: number
  }
  error?: string
  /** Structured scan activity log for debugging */
  logs?: LogEntry[]
  createdAt: string
}

const STORAGE_DIR = process.env.NODE_ENV === "production"
  ? join(process.cwd(), "data", "scans")
  : join(process.cwd(), ".scans")

function ensureDir() {
  if (!existsSync(STORAGE_DIR)) {
    mkdirSync(STORAGE_DIR, { recursive: true })
  }
}

function filePath(id: string): string {
  return join(STORAGE_DIR, `${id}.json`)
}

function generateId(): string {
  return `scan-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
}

export function createSession(type: "url" | "source", target: string): ScanSession {
  ensureDir()
  const session: ScanSession = {
    id: generateId(),
    target,
    type,
    status: "pending",
    riskScore: "—",
    totalChecks: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, passed: 0 },
    vulnerabilities: [],
    createdAt: new Date().toISOString(),
  }
  writeFileSync(filePath(session.id), JSON.stringify(session, null, 2), "utf-8")
  return session
}

export function getSession(id: string): ScanSession | undefined {
  try {
    const path = filePath(id)
    if (!existsSync(path)) return undefined
    return JSON.parse(readFileSync(path, "utf-8"))
  } catch {
    return undefined
  }
}

export function updateSession(id: string, updates: Partial<ScanSession>) {
  const s = getSession(id)
  if (s) {
    Object.assign(s, updates)
    writeFileSync(filePath(id), JSON.stringify(s, null, 2), "utf-8")
  }
}

export function getAllSessions(): ScanSession[] {
  ensureDir()
  try {
    return readdirSync(STORAGE_DIR)
      .filter(f => f.endsWith(".json"))
      .map(f => {
        try {
          return JSON.parse(readFileSync(join(STORAGE_DIR, f), "utf-8")) as ScanSession
        } catch {
          return null
        }
      })
      .filter((s): s is ScanSession => s !== null)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
  } catch {
    return []
  }
}

export function deleteSession(id: string): boolean {
  const path = filePath(id)
  if (!existsSync(path)) return false
  unlinkSync(path)
  return true
}

export function clearSessions() {
  ensureDir()
  for (const f of readdirSync(STORAGE_DIR)) {
    if (f.endsWith(".json")) unlinkSync(join(STORAGE_DIR, f))
  }
}

export function toScanSummary(session: ScanSession): ScanSummary {
  const hasResults = session.summary.critical > 0 || session.summary.high > 0 || session.summary.medium > 0 || session.summary.low > 0
  return {
    id: session.id,
    target: session.target,
    type: session.type,
    status: session.status,
    risk: session.riskScore || "—",
    date: session.createdAt,
    engine: session.scannerEngine,
    summary: hasResults ? session.summary : undefined,
  }
}

export function toScanDetail(session: ScanSession): ScanDetail {
  return {
    id: session.id,
    target: session.target,
    status: session.status,
    riskScore: session.riskScore,
    totalChecks: session.totalChecks,
    engine: session.scannerEngine,
    summary: session.summary,
    vulnerabilities: session.vulnerabilities,
    scanners: session.scanners,
    progress: session.progress,
    aiAggregation: session.aiAggregation,
    orchestratorPlan: session.orchestratorPlan,
    dynamicEscalation: session.dynamicEscalation,
    crawlData: session.crawlData,
    logs: session.logs,
    createdAt: session.createdAt,
  }
}
