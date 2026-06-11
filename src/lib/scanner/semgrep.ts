import { execSync } from "child_process"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const LOCAL_RULES = join(process.cwd(), "tools", "semgrep-rules", "security.yaml")

type SemgrepSev = "ERROR" | "WARNING" | "INFO"
type VulnSev = "Critical" | "High" | "Medium"

interface SemgrepResult {
  check_id: string
  path: string
  start: { line: number }
  extra: {
    message: string
    metadata: { cwe?: string[]; references?: string[] }
    severity: SemgrepSev
    lines?: string
  }
}

function severityMap(s: SemgrepSev): VulnSev {
  return s === "ERROR" ? "Critical" : s === "WARNING" ? "High" : "Medium"
}

interface SemgrepOutput {
  results: SemgrepResult[]
  paths: { scanned: string[] }
}

export async function runSemgrepScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "semgrep"

  if (!existsSync(LOCAL_RULES)) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Semgrep rules not found at " + LOCAL_RULES], scannerName }
  }

  try {
    // Use execSync for reliable Windows compatibility
    const rulesPath = LOCAL_RULES.replace(/\\/g, "/")
    const target = targetPath.replace(/\\/g, "/")
    const cmd = `"semgrep" --config="${rulesPath}" --json --timeout=30 "${target}"`
    const stdout = execSync(cmd, { timeout: 120000, maxBuffer: 10 * 1024 * 1024, encoding: "utf-8", env: { ...process.env, PYTHONIOENCODING: "utf-8" } })

    const jsonStart = stdout.indexOf("{")
    const jsonEnd = stdout.lastIndexOf("}")
    const jsonStr = jsonStart >= 0 && jsonEnd >= 0 ? stdout.slice(jsonStart, jsonEnd + 1) : stdout
    const parsed: SemgrepOutput = JSON.parse(jsonStr)

    const vulnerabilities: Vulnerability[] = parsed.results.map((r, i) => ({
      id: `SG-${i + 1}`,
      name: r.extra.message.split(".")[0] || "Semgrep finding",
      severity: severityMap(r.extra.severity),
      location: `${r.path}:${r.start.line}`,
      cve: r.extra.metadata.cwe?.[0] || "CWE-Info",
      description: r.extra.message,
      recommendation: r.extra.metadata.references?.[0]
        ? `参考: ${r.extra.metadata.references[0]}`
        : "Review and fix the identified issue",
      code: r.extra.lines || undefined,
      source: scannerName,
    }))

    return {
      vulnerabilities,
      totalChecks: parsed.paths?.scanned?.length || vulnerabilities.length + 10,
      errors: [],
      scannerName,
    }
  } catch (err: unknown) {
    // Try to extract results from stdout/stderr on non-zero exit
    const output = err && typeof err === "object"
      ? ((err as any).stdout || (err as any).stderr || "")
      : ""

    if (output) {
      try {
        const jsonStart = output.indexOf("{")
        const jsonEnd = output.lastIndexOf("}")
        const jsonStr = jsonStart >= 0 && jsonEnd >= 0 ? output.slice(jsonStart, jsonEnd + 1) : output
        const parsed: SemgrepOutput = JSON.parse(jsonStr)
        if (parsed.results?.length) {
          const vulnerabilities = parsed.results.map((r, i) => ({
            id: `SG-${i + 1}`,
            name: r.extra.message.split(".")[0] || "Semgrep finding",
            severity: severityMap(r.extra.severity),
            location: `${r.path}:${r.start.line}`,
            cve: r.extra.metadata.cwe?.[0] || "CWE-Info",
            description: r.extra.message,
            recommendation: r.extra.metadata.references?.[0]
              ? `参考: ${r.extra.metadata.references[0]}`
              : "Review and fix the identified issue",
            code: r.extra.lines || undefined,
            source: scannerName,
          }))
          return { vulnerabilities, totalChecks: vulnerabilities.length + 10, errors: [], scannerName }
        }
      } catch { /* ignore */ }
    }

    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Semgrep scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
