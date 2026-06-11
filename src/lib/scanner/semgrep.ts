import { execAsync } from "./exec"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"

const LOCAL_RULES = join(process.cwd(), "tools", "semgrep-rules", "security.yaml")

// Resolve semgrep binary: try env var, then PATH, then default
function resolveSemgrepBin(): string {
  const cached = (globalThis as any).__semgrep_path_cache
  if (cached) return cached
  try {
    const { execSync } = require("child_process") as typeof import("child_process")
    const output = execSync("where semgrep 2>nul", { encoding: "utf-8", timeout: 5000 })
    const path = output.trim().split("\n")[0]
    if (path) {
      (globalThis as any).__semgrep_path_cache = path
      return path
    }
  } catch { /* fallthrough */ }
  return "semgrep"
}

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

export async function runSemgrepScan(targetPath: string): Promise<import("./types").ScanResult> {
  const scannerName = "semgrep"
  const bin = resolveSemgrepBin()

  if (!existsSync(LOCAL_RULES)) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Semgrep rules not found at " + LOCAL_RULES], scannerName }
  }

  try {
    const { stdout: stdoutBuf } = await execAsync(
      `"${bin}" --config="${LOCAL_RULES}" --json --timeout=30 "${targetPath}"`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024 },
    )

    const stdout = stdoutBuf.trim()
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
    // Semgrep may exit non-zero — try to parse stdout from error
    if (err instanceof Error && "stdout" in err) {
      const stdout = (err as { stdout: string }).stdout?.toString().trim()
      if (stdout) {
        try {
          const jsonStart = stdout.indexOf("{")
          const jsonEnd = stdout.lastIndexOf("}")
          const jsonStr = jsonStart >= 0 && jsonEnd >= 0 ? stdout.slice(jsonStart, jsonEnd + 1) : stdout
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
    }
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Semgrep scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
