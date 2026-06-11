import { execAsync } from "./exec"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface PipAuditFinding {
  name: string
  version: string
  vulnerability: {
    id: string
    description: string
    severity?: { cvssv3?: { score?: number } }
    fix_versions: string[]
  }
}

function severityFromScore(score?: number): "Critical" | "High" | "Medium" | "Low" {
  if (!score) return "Medium"
  if (score >= 9) return "Critical"
  if (score >= 7) return "High"
  if (score >= 4) return "Medium"
  return "Low"
}

function isAvailable(): boolean {
  try {
    const { execSync } = require("child_process")
    execSync("pip-audit --version", { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runPipAuditScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "pip-audit"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["pip-audit not found"], scannerName }
  }

  try {
    const requirementsPath = `${targetPath}/requirements.txt`
    // Check if requirements.txt exists first
    try {
      await execAsync(`test -f "${requirementsPath}" || dir "${requirementsPath}" 2>nul`, { timeout: 5000 })
    } catch {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    const { stdout } = await execAsync(
      `pip-audit --requirement "${requirementsPath}" --format=json`,
      { timeout: 60000, maxBuffer: 10 * 1024 * 1024 },
    )

    const trimmed = stdout.trim()
    const jsonStart = trimmed.indexOf("{")
    const jsonEnd = trimmed.lastIndexOf("}")
    if (jsonStart < 0 || jsonEnd < 0) {
      return { vulnerabilities: [], totalChecks: 0, errors: ["No JSON output from pip-audit"], scannerName }
    }

    const parsed = JSON.parse(trimmed.slice(jsonStart, jsonEnd + 1))
    const findings: PipAuditFinding[] = parsed.dependencies || []

    const vulnerabilities: Vulnerability[] = []

    for (const dep of findings) {
      if (!dep.vulnerability) continue
      const v = dep.vulnerability
      const sev = severityFromScore(v.severity?.cvssv3?.score)

      vulnerabilities.push({
        id: v.id || `PIP-${dep.name}`,
        name: `Vulnerable package: ${dep.name}`,
        severity: sev,
        location: `${dep.name}@${dep.version}`,
        cve: v.id || "CVE-Pending",
        description: v.description || `${dep.name} ${dep.version} has known vulnerabilities`,
        recommendation: v.fix_versions?.length > 0
          ? `Upgrade ${dep.name} from ${dep.version} to ${v.fix_versions.join(" or ")}`
          : `Update ${dep.name} to a patched version`,
        source: "pip-audit",
      })
    }

    return {
      vulnerabilities,
      totalChecks: findings.length + 20,
      errors: [],
      scannerName,
    }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`pip-audit failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
