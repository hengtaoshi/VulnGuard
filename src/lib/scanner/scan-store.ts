import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync, rmSync } from "fs"
import { join, normalize } from "path"
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

  error?: string
  totalFiles?: number
  skippedFiles?: number
  projectName?: string
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

export function createSession(_type: "url" | "source", target: string, extra?: { totalFiles?: number; skippedFiles?: number; projectName?: string }): ScanSession {
  ensureDir()
  const session: ScanSession = {
    id: generateId(),
    target,
    type: "source",
    status: "pending",
    riskScore: "—",
    totalChecks: 0,
    summary: { critical: 0, high: 0, medium: 0, low: 0, passed: 0 },
    vulnerabilities: [],
    totalFiles: extra?.totalFiles,
    skippedFiles: extra?.skippedFiles,
    projectName: extra?.projectName || undefined,
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
      .filter((s): s is ScanSession => s !== null && typeof s.id === "string" && s.id.startsWith("scan-"))
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

/**
 * Sanitize target path for display — avoid leaking server absolute paths to the frontend.
 * Uses the UPLOAD_BASE const defined below (for cleanupUploadDir).
 */
function safeTarget(session: ScanSession): string {
  // If a project name is available, use it (user-friendly)
  if (session.projectName) return session.projectName

  // If the target is an absolute upload path, show only the last segment
  try {
    const normalized = normalize(session.target)
    if (normalized.startsWith(UPLOAD_BASE)) {
      const rel = normalized.slice(UPLOAD_BASE.length).replace(/^[/\\]+/, "")
      return rel ? `uploads/${rel}` : session.target
    }
  } catch {
    // ignore normalization errors
  }

  return session.target
}

export function toScanSummary(session: ScanSession): ScanSummary {
  const s = session.summary || { critical: 0, high: 0, medium: 0, low: 0, passed: 0 }
  const hasResults = s.critical > 0 || s.high > 0 || s.medium > 0 || s.low > 0
  return {
    id: session.id,
    target: safeTarget(session),
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
    target: safeTarget(session),
    status: session.status,
    riskScore: session.riskScore,
    totalChecks: session.totalChecks,
    engine: session.scannerEngine,
    summary: session.summary || { critical: 0, high: 0, medium: 0, low: 0, passed: 0 },
    vulnerabilities: session.vulnerabilities || [],
    scanners: session.scanners || [],
    progress: session.progress,
    aiAggregation: session.aiAggregation,
    orchestratorPlan: session.orchestratorPlan,
    logs: session.logs,
    totalFiles: session.totalFiles,
    skippedFiles: session.skippedFiles,
    projectName: session.projectName,
    createdAt: session.createdAt,
  }
}

/**
 * 判断目标路径是否为上传目录，若是则递归删除
 */
const UPLOAD_BASE = normalize(join(process.cwd(), "data", "uploads"))

function isUploadDir(targetPath: string): boolean {
  try {
    const normalized = normalize(targetPath)
    return normalized.startsWith(UPLOAD_BASE) && existsSync(normalized)
  } catch {
    return false
  }
}

/**
 * 扫描完成后清理上传目录
 */
export function cleanupUploadDir(targetPath: string): void {
  if (!isUploadDir(targetPath)) return
  try {
    rmSync(targetPath, { recursive: true, force: true })
    console.log(`[cleanup] Deleted upload directory: ${targetPath}`)
  } catch (err) {
    console.warn(`[cleanup] Failed to delete upload directory ${targetPath}:`, err)
  }
}

/**
 * 清理所有上传目录（清空 data/uploads/ 下所有子目录）
 */
export function clearAllUploads(): void {
  try {
    if (!existsSync(UPLOAD_BASE)) return
    for (const entry of readdirSync(UPLOAD_BASE)) {
      const fullPath = join(UPLOAD_BASE, entry)
      try {
        rmSync(fullPath, { recursive: true, force: true })
      } catch { /* ignore per-file errors */ }
    }
    console.log(`[cleanup] All upload directories cleared`)
  } catch (err) {
    console.warn(`[cleanup] Failed to clear uploads:`, err)
  }
}
