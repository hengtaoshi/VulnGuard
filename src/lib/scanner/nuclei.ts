import { execSync } from "child_process"
import { join } from "path"
import { existsSync, writeFileSync, readdirSync, statSync } from "fs"
import { homedir, tmpdir } from "os"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface NucleiFinding {
  templateID: string
  templateInfo: { name?: string; severity?: string; author?: string; description?: string }
  matchedAt: string
  host: string
  path: string
  type: string
  severity: string
  description: string
  info: { description?: string; remediation?: string; reference?: string }
}

const NUCLEI_PATH = join(process.cwd(), "tools", "bin", "nuclei.exe")
const CUSTOM_TEMPLATES = join(process.cwd(), "tools", "nuclei-templates")

function severityMap(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev) {
    case "critical": return "Critical"
    case "high": return "High"
    case "medium": return "Medium"
    case "low": return "Low"
    default: return "Low"
  }
}

function isAvailable(): boolean {
  try {
    execSync(`"${NUCLEI_PATH}" -version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

/** Recursively collect all .yaml template files from a directory */
function collectTemplates(dir: string): string[] {
  const results: string[] = []
  try {
    const entries = readdirSync(dir, { withFileTypes: true })
    for (const entry of entries) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        results.push(...collectTemplates(full))
      } else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) {
        results.push(full)
      }
    }
  } catch { /* ignore unreadable directories */ }
  return results
}

function resolveTemplateArg(): string {
  // Try full template repo in user home
  const homeTemplates = join(homedir(), "nuclei-templates")
  if (existsSync(homeTemplates)) {
    const templates = collectTemplates(homeTemplates)
    if (templates.length > 0) {
      return `-t "${join(homeTemplates, "file")}"`
    }
  }
  // Fallback to bundled custom templates
  if (existsSync(CUSTOM_TEMPLATES)) {
    return `-t "${CUSTOM_TEMPLATES}"`
  }
  return ""
}

export async function runNucleiScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "nuclei"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Nuclei not found"], scannerName }
  }

  const templateArg = resolveTemplateArg()
  if (!templateArg) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["No Nuclei templates found"], scannerName }
  }

  try {
    const output = execSync(
      `"${NUCLEI_PATH}" -target "${targetPath}" -j -silent -duc -file -severity low,medium,high,critical ${templateArg}`,
      { timeout: 60000, maxBuffer: 50 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = []

    for (const line of lines) {
      try {
        const f: NucleiFinding = JSON.parse(line)
        vulnerabilities.push({
          id: `NUCLEI-${vulnerabilities.length + 1}`,
          name: f.templateInfo?.name || f.templateID || "Security finding",
          severity: severityMap(f.severity || f.templateInfo?.severity || "medium"),
          location: f.path || f.matchedAt || targetPath,
          cve: f.templateID || "Nuclei",
          description: f.info?.description || f.description || f.templateInfo?.description || `Matched at ${f.matchedAt}`,
          recommendation: f.info?.remediation || f.info?.reference || `Review ${f.templateID}`,
          source: "nuclei",
        })
      } catch {
        // skip malformed JSON lines
      }
    }

    const totalChecks = vulnerabilities.length > 0 ? vulnerabilities.length + 50 : 50
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Nuclei scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
