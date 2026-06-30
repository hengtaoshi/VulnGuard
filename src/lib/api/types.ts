export type ScannerEngine = "ai" | "all"

export interface LogEntry {
  timestamp: number
  phase: "orchestrator" | "scanner" | "aggregation" | "system"
  level: "info" | "warn" | "error" | "debug"
  message: string
  details?: string
  scannerName?: string
}

export interface ScanSummary {
  id: string
  target: string
  type: "url" | "source"
  status: "completed" | "scanning" | "pending" | "failed"
  risk: string
  date: string
  engine?: ScannerEngine
  summary?: {
    critical: number
    high: number
    medium: number
    low: number
    passed: number
  }
  /** 扫描器执行统计 */
  scannerStats?: {
    total: number
    success: number
    failed: number
  }
}

export interface Vulnerability {
  id: string
  name: string
  severity: "Critical" | "High" | "Medium" | "Low"
  location: string
  cve: string
  /** 是否为真实 CVE（如 CVE-2024-12345），false = 内部 ID（如 SG-1、CWE-89） */
  isRealCve?: boolean
  description: string
  recommendation: string
  code?: string
  /** AI 生成的修复代码示例 */
  codeFix?: string
  source?: string
}

export interface ScannerInfo {
  scannerName: string
  displayName: string
  category: string
  count: number
  errors: string[]
}

export interface ScanProgress {
  percent: number
  currentScanner: string
  elapsed: number
  eta: number
  engine?: ScannerEngine
  scannerStatuses: { scannerName: string; displayName: string; category: string; count: number; errors: string[]; status: "pending" | "running" | "completed" | "failed" }[]
}

export interface AggregationSummary {
  totalFindings: number
  falsePositivesRemoved: number
  highConfidence: number
  mediumConfidence: number
  lowConfidence: number
  correlatedFindings: number
  summary: string
  priorityActions: string[]
}

export interface ScanDetail {
  id: string
  target: string
  status: "completed" | "scanning" | "pending" | "failed"
  riskScore: string
  totalChecks: number
  engine?: ScannerEngine
  summary: {
    critical: number
    high: number
    medium: number
    low: number
    passed: number
  }
  vulnerabilities: Vulnerability[]
  scanners?: ScannerInfo[]
  progress?: ScanProgress
  aiAggregation?: AggregationSummary
  orchestratorPlan?: {
    reasoning: string
    selectedScanners: string[]
    parallelGroups: string[][]
    aiReview: boolean
    scanPriority: "speed" | "depth" | "balanced"
  }
  /** Number of source files uploaded for scanning */
  totalFiles?: number
  /** Number of files skipped (node_modules, .git, etc.) */
  skippedFiles?: number
  projectName?: string
  /** Full scan activity log */
  logs?: LogEntry[]
  createdAt?: string
}

export interface DashboardStats {
  totalScans: number
  totalVulnerabilities: number
  secure: number
  riskScore: string
  scanChange: string
  vulnChange: string
  secureChange: string
  riskChange: string
}
