import { updateSession, getSession } from "./scan-store"
import type { LogEntry } from "@/lib/api/types"

export type { LogEntry }

/**
 * Add a log entry to a scan session.
 * Persisted immediately so logs survive crashes.
 */
export function addLog(
  sessionId: string,
  phase: LogEntry["phase"],
  level: LogEntry["level"],
  message: string,
  details?: string,
  scannerName?: string,
) {
  const entry: LogEntry = {
    timestamp: Date.now(),
    phase,
    level,
    message,
    ...(details ? { details } : {}),
    ...(scannerName ? { scannerName } : {}),
  }
  const session = getSession(sessionId)
  if (!session) return
  const logs = session.logs || []
  logs.push(entry)
  updateSession(sessionId, { logs })
}

/**
 * Format a LogEntry for display.
 */
export function formatLogEntry(entry: LogEntry): string {
  const time = new Date(entry.timestamp).toLocaleTimeString("zh-CN", { hour12: false })
  const phaseMap: Record<string, string> = {
    orchestrator: "🧠",
    scanner: "🔍",
    aggregation: "🤖",
    system: "⚙️",
  }
  const levelMap: Record<string, string> = {
    info: "ℹ️",
    warn: "⚠️",
    error: "❌",
    debug: "🔧",
  }
  const icon = phaseMap[entry.phase] || "•"
  const levelIcon = levelMap[entry.level] || "•"
  const scanner = entry.scannerName ? ` [${entry.scannerName}]` : ""
  return `${time} ${icon} ${levelIcon} ${entry.message}${scanner}${entry.details ? `\n    └ ${entry.details}` : ""}`
}
