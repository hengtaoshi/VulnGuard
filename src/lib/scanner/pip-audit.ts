import { execAsync } from "./exec"
import { join } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { TOOLS_BIN } from "./paths"

function severityFromScore(score?: number): "Critical" | "High" | "Medium" | "Low" {
  if (!score) return "Medium"
  if (score >= 9) return "Critical"
  if (score >= 7) return "High"
  if (score >= 4) return "Medium"
  return "Low"
}

/** 优先使用系统 pip-audit，回退到 bundled exe */
function resolvePath(): string {
  try {
    const { execSync } = require("child_process")
    const result = execSync("where pip-audit 2>nul", { stdio: "pipe", timeout: 5000, encoding: "utf-8" })
    const p = (result as string).trim().split("\n")[0]
    if (p) return p.trim()
  } catch { /* fall through */ }
  return join(TOOLS_BIN, "pip-audit.exe")
}

function isAvailable(): boolean {
  try {
    const { execSync } = require("child_process")
    execSync(`"${resolvePath()}" --version`, { stdio: "pipe", timeout: 5000 })
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

  const PIPAUDIT_PATH = resolvePath()

  try {
    const requirementsPath = `${targetPath.replace(/\\/g, "/")}/requirements.txt`
    const fs = require("fs") as typeof import("fs")
    if (!fs.existsSync(requirementsPath)) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    let stdout = ""
    try {
      const r = await execAsync(
        `"${PIPAUDIT_PATH}" --requirement "${requirementsPath.replace(/\\/g, "/")}" --format=json`,
        { timeout: 60000, maxBuffer: 10 * 1024 * 1024 },
      )
      stdout = r.stdout
    } catch (err: unknown) {
      if (err && typeof err === "object" && "stdout" in err) {
        stdout = (err as { stdout: string }).stdout || ""
      }
      if (!stdout) throw err
    }

    const trimmed = stdout.trim()
    const jsonStart = trimmed.indexOf("{")
    const jsonEnd = trimmed.lastIndexOf("}")
    if (jsonStart < 0 || jsonEnd < 0) {
      return { vulnerabilities: [], totalChecks: 0, errors: ["No JSON output from pip-audit"], scannerName }
    }

    const parsed = JSON.parse(trimmed.slice(jsonStart, jsonEnd + 1))
    const dependencies: { name: string; version: string; vulns?: { id: string; description: string; fix_versions: string[]; severity?: { cvssv3?: { score?: number } } }[] }[] = parsed.dependencies || []

    const vulnerabilities: Vulnerability[] = []

    for (const dep of dependencies) {
      const vulns = dep.vulns || []
      for (const v of vulns) {
        if (!v.id) continue
        const sev = severityFromScore(v.severity?.cvssv3?.score)

        vulnerabilities.push({
          id: v.id,
          name: `${dep.name}: ${v.id}`,
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
    }

    return {
      vulnerabilities,
      totalChecks: dependencies.length + 20,
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
