import { execAsync } from "./exec"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface BanditResult {
  results: {
    code: string
    filename: string
    issue_confidence: string
    issue_severity: string
    issue_text: string
    line_number: number
    line_range: number[]
    more_info: string
    test_id: string
    test_name: string
  }[]
}

function severityMap(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev.toUpperCase()) {
    case "HIGH": return "High"
    case "MEDIUM": return "Medium"
    case "LOW": return "Low"
    default: return "Low"
  }
}

function isAvailable(): boolean {
  try {
    const { execSync } = require("child_process")
    execSync("bandit --version", { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

function parseBanditJson(stdout: string): ScanResult | null {
  const trimmed = stdout.trim()
  const jsonStart = trimmed.indexOf("{")
  if (jsonStart < 0) return null

  try {
    const parsed: BanditResult = JSON.parse(trimmed.slice(jsonStart))
    const vulnerabilities: Vulnerability[] = parsed.results.map((r, idx) => ({
      id: `BANDIT-${idx + 1}`,
      name: r.test_name || r.issue_text.split(". ")[0] || "Security issue",
      severity: severityMap(r.issue_severity),
      location: `${r.filename}:${r.line_number}`,
      cve: r.test_id,
      description: r.issue_text,
      recommendation: `Refer to: ${r.more_info}`,
      code: r.code || undefined,
      source: "bandit",
    }))

    return {
      vulnerabilities,
      totalChecks: parsed.results.length + 30,
      errors: [],
      scannerName: "bandit",
    }
  } catch {
    return null
  }
}

export async function runBanditScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "bandit"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Bandit not installed. Run: pip install bandit"], scannerName }
  }

  try {
    const { stdout } = await execAsync(
      `bandit -r "${targetPath}" -f json --quiet`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024 },
    )

    const result = parseBanditJson(stdout)
    if (result) return result
    return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
  } catch (err: unknown) {
    // Bandit exits non-zero when issues are found — stdout has the JSON
    if (err instanceof Error && "stdout" in err) {
      const stdout = (err as { stdout: string }).stdout?.toString().trim()
      if (stdout) {
        const result = parseBanditJson(stdout)
        if (result) return result
      }
    }
    // Include stderr in error message for debugging
    const stderr = err instanceof Error && "stderr" in err
      ? (err as { stderr: string }).stderr?.toString().trim().slice(0, 500)
      : ""
    const details = stderr ? `${err instanceof Error ? err.message : String(err)} — ${stderr}` : err instanceof Error ? err.message : String(err)
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Bandit scan failed: ${details}`],
      scannerName,
    }
  }
}
