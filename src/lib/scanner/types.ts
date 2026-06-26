import type { Vulnerability } from "@/lib/api/types"

export interface ScanResult {
  vulnerabilities: Vulnerability[]
  totalChecks: number
  errors: string[]
  scannerName: string
}

export interface Scanner {
  name: string
  displayName: string
  category: string
  isAvailable(): boolean
  scan(targetPath: string): Promise<ScanResult>
}

// ─── AI Aggregation Types ────────────────────────────────────────────────────

export type Confidence = "high" | "medium" | "low"

export interface AggregatedFinding {
  /** Unique identifier within this aggregation run */
  id: string
  name: string
  severity: "Critical" | "High" | "Medium" | "Low"
  location: string
  cve: string
  description: string
  recommendation: string
  code?: string
  /** AI-assessed confidence: high=confirmed, medium=likely, low=speculative */
  confidence: Confidence
  /** AI flagged this as a false positive */
  isFalsePositive: boolean
  /** Why it was flagged as false positive (only when isFalsePositive=true) */
  falsePositiveReason?: string
  /** Which scanner(s) detected this finding */
  detectedBy: string[]
  /** True when multiple independent scanners confirmed the same finding */
  isCorrelated: boolean
}

export interface AggregationReport {
  /** Final deduplicated findings after AI correlation */
  findings: AggregatedFinding[]
  /** Count of findings AI flagged as false positives (excluded from findings) */
  falsePositivesRemoved: number
  /** Overall AI assessment of the scan results */
  summary: string
  /** Ordered list of recommended actions */
  priorityActions: string[]
  /** Target name for context */
  target: string
  /** When the aggregation was performed */
  createdAt: string
}
