import { execAsync } from "./exec"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface CheckovReport {
  check_type: string
  results: {
    passed_checks: { check_id: string; check_name: string; file: string }[]
    failed_checks: {
      check_id: string
      check_name: string
      file: string
      file_line_range: [number, number]
      resource: string
      severity: string | null
      guideline: string
      description: string
      bc_check_id: string
    }[]
  }
}

function severityMap(sev: string | null): "Critical" | "High" | "Medium" | "Low" {
  switch ((sev || "MEDIUM").toUpperCase()) {
    case "CRITICAL": return "Critical"
    case "HIGH": return "High"
    case "MEDIUM": return "Medium"
    case "LOW": return "Low"
    default: return "Low"
  }
}

function isAvailable(): boolean {
  try {
    const { execSync } = require("child_process")
    execSync("checkov --version", { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runCheckovScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "checkov"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Checkov not installed. Run: pip install checkov"], scannerName }
  }

  let rawJson = ""

  try {
    const { stdout } = await execAsync(
      `checkov -d "${targetPath.replace(/\\/g, "/")}" --framework terraform kubernetes dockerfile cloudformation --output json`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024 },
    )
    rawJson = stdout.trim()
  } catch (err: unknown) {
    // Checkov exits non-zero when findings exist
    if (err instanceof Error && "stdout" in err) {
      rawJson = (err as { stdout: string }).stdout?.toString().trim() || ""
    }
    if (!rawJson) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }
  }

  if (!rawJson) {
    return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
  }

  try {
    // Checkov may output a JSON array [{...},{...},{...}] or a single object {...}
    const trimmed = rawJson.trim()
    let parsed: any

    if (trimmed.startsWith("[")) {
      // Array format — combine all results
      const reports: CheckovReport[] = JSON.parse(trimmed)
      // Merge passed/failed checks from all reports
      const allFailed: CheckovReport["results"]["failed_checks"] = []
      const allPassed: CheckovReport["results"]["passed_checks"] = []
      for (const r of reports) {
        if (r.results?.failed_checks) allFailed.push(...r.results.failed_checks)
        if (r.results?.passed_checks) allPassed.push(...r.results.passed_checks)
      }
      parsed = { check_type: "merged", results: { failed_checks: allFailed, passed_checks: allPassed } }
    } else {
      const jsonStart = trimmed.indexOf("{")
      const jsonEnd = trimmed.lastIndexOf("}")
      if (jsonStart < 0 || jsonEnd < 0) {
        return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
      }
      parsed = JSON.parse(trimmed.slice(jsonStart, jsonEnd + 1))
    }

    const report: CheckovReport = parsed
    const failed = report.results?.failed_checks || []
    const passed = report.results?.passed_checks || []

    const vulnerabilities: Vulnerability[] = failed.map((c, idx) => ({
      id: `CKV-${idx + 1}`,
      name: c.check_name || "IaC security issue",
      severity: severityMap(c.severity),
      location: `${c.file}:${c.file_line_range?.[0] || "?"}`,
      cve: c.check_id || c.bc_check_id || "CKV",
      description: c.description || c.check_name,
      recommendation: c.guideline || `Fix ${c.check_id} according to IaC security best practices`,
      source: "checkov",
    }))

    return {
      vulnerabilities,
      totalChecks: vulnerabilities.length + passed.length,
      errors: [],
      scannerName,
    }
  } catch {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Failed to parse Checkov output"], scannerName }
  }
}
