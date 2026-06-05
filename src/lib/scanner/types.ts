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
  category: "sast" | "secret" | "dependency" | "filesystem"
  isAvailable(): boolean
  scan(targetPath: string): Promise<ScanResult>
}
