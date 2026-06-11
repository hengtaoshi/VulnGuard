import { execSync } from "child_process"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const BIN_DIR = join(process.cwd(), "tools", "bin")

function extractDomain(target: string): string {
  let domain = target.replace(/^https?:\/\//, "")
  domain = domain.split("/")[0].split("?")[0]
  domain = domain.split(":")[0]
  return domain || target
}

// ─── Gau ────────────────────────────────────────────────────────────────────────

const GAU_PATH = join(BIN_DIR, "gau.exe")

function isGauAvailable(): boolean {
  try {
    execSync(`"${GAU_PATH}" --version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runGauScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "gau"
  if (!isGauAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Gau not found"], scannerName }
  }

  const domain = extractDomain(targetPath)
  if (!domain) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Invalid target for URL extraction"], scannerName }
  }

  try {
    const output = execSync(
      `"${GAU_PATH}" "${domain}"`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const urls = output.toString().trim().split("\n").filter(Boolean)
    if (urls.length === 0) {
      return { vulnerabilities: [], totalChecks: 0, errors: ["No historical URLs found by gau"], scannerName }
    }

    // Group by path patterns to identify interesting findings
    const sensitivePatterns = [
      { pattern: /admin/i, name: "Admin Panel", sev: "High" as const },
      { pattern: /backup/i, name: "Backup File", sev: "High" as const },
      { pattern: /\.git/i, name: "Git Exposure", sev: "High" as const },
      { pattern: /\.env/i, name: "Environment File", sev: "High" as const },
      { pattern: /api/i, name: "API Endpoint", sev: "Medium" as const },
      { pattern: /swagger|openapi/i, name: "API Documentation", sev: "Medium" as const },
      { pattern: /config|conf/i, name: "Configuration File", sev: "Medium" as const },
      { pattern: /login|signin|auth/i, name: "Authentication Page", sev: "Medium" as const },
      { pattern: /upload/i, name: "Upload Endpoint", sev: "Medium" as const },
      { pattern: /sql|dump|export/i, name: "Database Export", sev: "High" as const },
      { pattern: /debug|test|dev/i, name: "Development Endpoint", sev: "Medium" as const },
      { pattern: /wp-admin|wp-content/i, name: "WordPress Path", sev: "Medium" as const },
    ]

    const pathCategories = new Map<string, Set<string>>()

    for (const url of urls) {
      try {
        const parsed = new URL(url)
        const path = parsed.pathname
        for (const sp of sensitivePatterns) {
          if (sp.pattern.test(path)) {
            if (!pathCategories.has(sp.name)) pathCategories.set(sp.name, new Set())
            pathCategories.get(sp.name)!.add(url)
            break
          }
        }
      } catch {
        // skip invalid URLs
      }
    }

    const vulnerabilities: Vulnerability[] = []
    let idx = 0

    Array.from(pathCategories).forEach(([catName, urlsSet]) => {
      const exampleUrl = Array.from(urlsSet)[0]
      const sev = sensitivePatterns.find((s) => s.name === catName)?.sev || "Medium"

      vulnerabilities.push({
        id: `GAU-${++idx}`,
        name: `Historical ${catName} Found`,
        severity: sev,
        location: exampleUrl!,
        cve: "OSINT",
        description: `Historical URL discovered via gau (${catName}): ${exampleUrl}. Found ${urlsSet.size} related URL(s). These may expose endpoints no longer linked from the main site.`,
        recommendation: "Review historical URLs for sensitive data exposure. Remove or restrict old endpoints that should not be publicly accessible.",
        source: scannerName,
      })
    })

    // If no sensitive patterns matched, report the raw count as recon info
    if (vulnerabilities.length === 0) {
      vulnerabilities.push({
        id: "GAU-1",
        name: "Historical URLs Collected",
        severity: "Low",
        location: domain,
        cve: "OSINT",
        description: `Found ${urls.length} historical URLs for ${domain} via gau. No sensitive patterns matched, but the data provides valuable recon context.`,
        recommendation: "Review the full list of historical URLs for any overlooked sensitive endpoints.",
        source: scannerName,
      })
    }

    const totalChecks = urls.length
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Gau scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Waybackurls ────────────────────────────────────────────────────────────────

const WAYBACKURLS_PATH = join(BIN_DIR, "waybackurls.exe")

function isWaybackurlsAvailable(): boolean {
  // waybackurls doesn't support --version, check by running with no args
  try {
    execSync(`"${WAYBACKURLS_PATH}" -h`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    try { return existsSync(WAYBACKURLS_PATH) } catch { return false }
  }
}

export async function runWaybackurlsScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "waybackurls"
  if (!isWaybackurlsAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Waybackurls not found"], scannerName }
  }

  const domain = extractDomain(targetPath)
  if (!domain) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Invalid target"], scannerName }
  }

  try {
    const output = execSync(
      `"${WAYBACKURLS_PATH}" "${domain}"`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const urls = output.toString().trim().split("\n").filter(Boolean)
    if (urls.length === 0) {
      return { vulnerabilities: [], totalChecks: 1, errors: [], scannerName }
    }

    // Find interesting paths from historical URLs
    const interesting: { url: string; reason: string; sev: "High" | "Medium" | "Low" }[] = []

    for (const url of urls) {
      try {
        const lower = url.toLowerCase()
        if (lower.includes(".git")) { interesting.push({ url, reason: "Git data", sev: "High" }); continue }
        if (lower.includes(".env")) { interesting.push({ url, reason: "Environment file", sev: "High" }); continue }
        if (lower.includes("backup")) { interesting.push({ url, reason: "Backup file", sev: "High" }); continue }
        if (lower.includes("admin")) { interesting.push({ url, reason: "Admin panel", sev: "Medium" }); continue }
        if (lower.includes("api/")) { interesting.push({ url, reason: "API endpoint", sev: "Medium" }); continue }
        if (lower.includes("swagger") || lower.includes("openapi")) { interesting.push({ url, reason: "API docs", sev: "Medium" }); continue }
        if (lower.includes("config")) { interesting.push({ url, reason: "Config file", sev: "Medium" }); continue }
        if (lower.includes("sql") || lower.includes("dump")) { interesting.push({ url, reason: "DB dump", sev: "High" }); continue }
        if (lower.includes("debug") || lower.includes("test")) { interesting.push({ url, reason: "Dev endpoint", sev: "Medium" }); continue }
      } catch {
        // skip individual URL errors
      }
    }

    const vulnerabilities: Vulnerability[] = interesting.map((item, i) => ({
      id: `WAYBACK-${i + 1}`,
      name: `Wayback Machine: ${item.reason}`,
      severity: item.sev,
      location: item.url,
      cve: "OSINT",
      description: `Historical URL from Wayback Machine (${item.reason}): ${item.url}. Archive.org may have captured sensitive pages no longer on the live site.`,
      recommendation: "Check if this historical resource still exists or has been properly removed. Ensure sensitive data is not accessible through archived copies.",
      source: scannerName,
    }))

    // If no sensitive findings, report the recon value
    if (vulnerabilities.length === 0) {
      vulnerabilities.push({
        id: "WAYBACK-1",
        name: "Historical URLs Available",
        severity: "Low",
        location: domain,
        cve: "OSINT",
        description: `Found ${urls.length} archived URLs for ${domain} via Wayback Machine. No highly sensitive patterns identified, but data provides recon value.`,
        recommendation: "Review archived URLs to understand historical attack surface.",
        source: scannerName,
      })
    }

    const totalChecks = urls.length
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Waybackurls scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
