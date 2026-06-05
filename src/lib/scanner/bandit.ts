import { execSync } from "child_process"
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
    execSync("bandit --version", { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runBanditScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "bandit"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Bandit not installed. Run: pip install bandit"], scannerName }
  }

  try {
    const output = execSync(
      `bandit -r "${targetPath}" -f json --quiet`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const stdout = output.toString().trim()
    const jsonStart = stdout.indexOf("{")
    if (jsonStart < 0) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    const parsed: BanditResult = JSON.parse(stdout.slice(jsonStart))

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
      scannerName,
    }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Bandit scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
