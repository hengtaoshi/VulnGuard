export interface ScanSummary {
  id: string
  target: string
  type: "url" | "source"
  status: "completed" | "scanning" | "pending" | "failed"
  risk: string
  date: string
}

export interface Vulnerability {
  id: string
  name: string
  severity: "Critical" | "High" | "Medium" | "Low"
  location: string
  cve: string
  description: string
  recommendation: string
  code?: string
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
  scannerStatuses: { scannerName: string; displayName: string; category: string; count: number; errors: string[]; status: "pending" | "running" | "completed" | "failed" }[]
}

export interface ScanDetail {
  id: string
  target: string
  status: "completed" | "scanning" | "pending" | "failed"
  riskScore: string
  totalChecks: number
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
