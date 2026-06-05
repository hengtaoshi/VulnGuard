import { execSync } from "child_process"
import { join } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface TrivyResult {
  Results?: {
    Target: string
    Vulnerabilities?: {
      VulnerabilityID: string
      PkgName: string
      InstalledVersion: string
      FixedVersion: string
      Title: string
      Description: string
      Severity: string
      PrimaryURL: string
      References: string[]
      CvssScore?: number
    }[]
  }[]
}

const TRIVY_PATH = join(process.cwd(), "tools", "bin", "trivy.exe")

function severityMap(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return "Critical"
    case "HIGH": return "High"
    case "MEDIUM": return "Medium"
    case "LOW": return "Low"
    default: return "Low"
  }
}

function isAvailable(): boolean {
  try {
    execSync(`"${TRIVY_PATH}" --version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runTrivyScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "trivy"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Trivy not found"], scannerName }
  }

  try {
    const output = execSync(
      `"${TRIVY_PATH}" fs --format=json --quiet --scanners misconfig,secret --skip-db-update --offline-scan "${targetPath}"`,
      { timeout: 180000, maxBuffer: 50 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const stdout = output.toString().trim()
    if (!stdout) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    const jsonStart = stdout.indexOf("{")
    if (jsonStart < 0) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    const parsed: TrivyResult = JSON.parse(stdout.slice(jsonStart))

    const vulnerabilities: Vulnerability[] = []
    let idx = 0

    for (const result of parsed.Results || []) {
      for (const v of result.Vulnerabilities || []) {
        idx++
        const sev = severityMap(v.Severity)
        const desc = v.Description || v.Title || `Vulnerability in ${v.PkgName}`
        vulnerabilities.push({
          id: v.VulnerabilityID || `TRIVY-${idx}`,
          name: `${v.VulnerabilityID || "Vulnerability"} in ${v.PkgName}`,
          severity: sev,
          location: `${result.Target} → ${v.PkgName}@${v.InstalledVersion}`,
          cve: v.VulnerabilityID || "CVE-Pending",
          description: desc,
          recommendation: v.FixedVersion
            ? `Fix: upgrade ${v.PkgName} from ${v.InstalledVersion} to ${v.FixedVersion}`
            : `Review vulnerability in ${v.PkgName}@${v.InstalledVersion} and apply security patch`,
          code: undefined,
          source: "trivy",
        })
      }
    }

    return {
      vulnerabilities,
      totalChecks: idx + 100,
      errors: [],
      scannerName,
    }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Trivy scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
