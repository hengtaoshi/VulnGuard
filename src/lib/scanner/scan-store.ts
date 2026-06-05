import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, unlinkSync } from "fs"
import { join } from "path"
import type { ScanDetail, ScanSummary, Vulnerability, ScannerInfo, ScanProgress } from "@/lib/api/types"

export interface ScanSession {
  id: string
  target: string
  type: "url" | "source"
  status: "pending" | "scanning" | "completed" | "failed"
  riskScore: string
  totalChecks: number
  summary: { critical: number; high: number; medium: number; low: number; passed: number }
  vulnerabilities: Vulnerability[]
  scanners?: ScannerInfo[]
  progress?: ScanProgress
  error?: string
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

export function clearSessions() {
  ensureDir()
  for (const f of readdirSync(STORAGE_DIR)) {
    if (f.endsWith(".json")) unlinkSync(join(STORAGE_DIR, f))
  }
}

export function toScanSummary(session: ScanSession): ScanSummary {
  return {
    id: session.id,
    target: session.target,
    type: session.type,
    status: session.status,
    risk: session.riskScore || "—",
    date: session.createdAt,
  }
}

export function toScanDetail(session: ScanSession): ScanDetail {
  return {
    id: session.id,
    target: session.target,
    status: session.status,
    riskScore: session.riskScore,
    totalChecks: session.totalChecks,
    summary: session.summary,
    vulnerabilities: session.vulnerabilities,
    scanners: session.scanners,
    progress: session.progress,
  }
}
