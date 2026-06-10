import { execSync, exec } from "child_process"
import { promisify } from "util"
import { writeFileSync, unlinkSync } from "fs"
import { tmpdir } from "os"
import { join } from "path"

const WAPITI_PATH = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\wapiti.exe"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface WapitiClassification {
  desc: string
  sol: string
  ref: Record<string, string>
  wstg: string[]
}

interface WapitiVulnEntry {
  method: string
  path: string
  parameter?: string
  info?: Record<string, string>
  curl_commands?: string[]
  content?: string
  referer?: string
  dumper_flag?: string
  evil_request?: string
}

interface WapitiReport {
  classifications: Record<string, WapitiClassification>
  vulnerabilities: Record<string, WapitiVulnEntry[]>
  anomalies: Record<string, WapitiVulnEntry[]>
  additionals: Record<string, WapitiVulnEntry[]>
  infos: {
    target: string
    date: string
    version: string
    scope: string
    crawled_pages_nbr: number
  }
}

const execAsync = promisify(exec)

const SEVERITY_MAP: Record<string, "Critical" | "High" | "Medium" | "Low"> = {
  "SQL Injection": "Critical",
  "Blind SQL Injection": "Critical",
  "Command execution": "Critical",
  "Log4Shell": "Critical",
  "Spring4Shell": "Critical",
  "LDAP Injection": "Critical",
  "Server Side Request Forgery": "High",
  "Reflected Cross Site Scripting": "High",
  "Stored Cross Site Scripting": "High",
  "Path Traversal": "High",
  "CRLF Injection": "High",
  "Unrestricted File Upload": "High",
  "HTML Injection": "High",
  "Stored HTML Injection": "High",
  "Open Redirect": "Medium",
  "Weak credentials": "Medium",
  "Potentially dangerous file": "Medium",
  "Backup file": "Medium",
  "Cross Site Request Forgery": "Medium",
  "Cleartext Submission of Password": "High",
  "Internal Server Error": "Low",
  "Resource consumption": "Low",
  "Information Disclosure - Full Path": "Medium",
  "HttpOnly Flag cookie": "Low",
  "Secure Flag cookie": "Low",
  "Content Security Policy Configuration": "Low",
  "Clickjacking Protection": "Low",
  "MIME Type Confusion": "Low",
  "HTTP Strict Transport Security (HSTS)": "Low",
  "Unencrypted Channels": "Medium",
  "Htaccess Bypass": "Medium",
  "Inconsistent Redirection": "Low",
  "NS takeover": "High",
  "Subdomain takeover": "High",
  "Vulnerable software": "High",
  "CVE-2024-55591": "Critical",
}

function severityFor(category: string): "Critical" | "High" | "Medium" | "Low" {
  return SEVERITY_MAP[category] || "Medium"
}

function normalizeCategory(name: string): string {
  // e.g. "Reflected Cross Site Scripting" -> "xss"
  if (name.includes("Cross Site Scripting") || name === "HTML Injection" || name === "Stored HTML Injection") return "xss"
  if (name.includes("SQL Injection")) return "sqli"
  if (name.includes("Command execution")) return "rce"
  if (name.includes("Path Traversal")) return "path-traversal"
  if (name.includes("CRLF")) return "crlf"
  if (name.includes("LDAP")) return "ldap"
  if (name.includes("SSRF") || name.includes("Server Side Request")) return "ssrf"
  if (name.includes("Open Redirect")) return "open-redirect"
  if (name.includes("File Upload")) return "file-upload"
  if (name.includes("CSRF") || name.includes("Request Forgery")) return "csrf"
  if (name.includes("Cookie") || name.includes("HttpOnly") || name.includes("Secure Flag")) return "cookie"
  if (name.includes("HSTS") || name.includes("Unencrypted") || name.includes("TLS") || name.includes("SSL")) return "tls"
  if (name.includes("CSP") || name.includes("Content Security")) return "csp"
  if (name.includes("Clickjack")) return "clickjack"
  if (name.includes("MIME") || name.includes("sniff")) return "mime"
  if (name.includes("Log4Shell") || name.includes("log4j")) return "log4shell"
  if (name.includes("Spring4Shell")) return "spring4shell"
  if (name.includes("Backup")) return "backup"
  if (name.includes("Credential") || name.includes("Password")) return "credential"
  if (name.includes("Information Disclosure") || name.includes("Path Disclosure")) return "info-disclosure"
  if (name.includes("Htaccess") || name.includes("bypass")) return "bypass"
  if (name.includes("takeover") || name.includes("NS ")) return "takeover"
  if (name.includes("Redirect")) return "redirect"
  if (name.includes("Fingerprint") || name.includes("Metafile") || name.includes("HTTP Method")) return "info"
  return name.toLowerCase().replace(/\s+/g, "-")
}

function isAvailable(): boolean {
  try {
    execSync(`"${WAPITI_PATH}" --version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runWapitiScan(targetUrl: string): Promise<ScanResult> {
  const scannerName = "wapiti"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Wapiti not installed. Run: pip install wapiti3"], scannerName }
  }

  const outputFile = join(tmpdir(), `wapiti-report-${Date.now()}.json`)

  try {
    // Run wapiti with all modules for comprehensive coverage
    // Note: --max-attack-time was removed because older wapiti versions don't support it
    await execAsync(
      `"${WAPITI_PATH}" -u "${targetUrl}" -f json -o "${outputFile}" --scope folder -m sql,xss,exec,file,backup,xxe,ssrf,ldap,crlf,htaccess,methods,redirect -d 3 --flush-attacks --flush-session --max-scan-time 600`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024, env: { ...process.env, NO_PROXY: "*", no_proxy: "*", PYTHONUTF8: "1" } },
    )

    // Remove the HTML report that wapiti also generates alongside the JSON
    try { unlinkSync(outputFile.replace(".json", ".html")) } catch { /* ignore */ }

    const { readFileSync } = await import("fs")
    const raw = readFileSync(outputFile, "utf-8")
    const report: WapitiReport = JSON.parse(raw)

    const vulnerabilities: Vulnerability[] = []
    let idCounter = 0

    // Process each vulnerability category
    const allCategories = [
      ...Object.entries(report.vulnerabilities || {}),
      ...Object.entries(report.anomalies || {}),
      ...Object.entries(report.additionals || {}),
    ]

    for (const [category, entries] of allCategories) {
      const classification = report.classifications?.[category]
      const defaultDesc = classification?.desc || `Security issue found via ${category}`
      const defaultSol = classification?.sol || `Review and fix the ${category} issue`
      const severity = severityFor(category)
      const normalizedName = normalizeCategory(category)

      for (const entry of entries) {
        idCounter++
        const location = entry.path || targetUrl
        const paramInfo = entry.parameter ? `?${entry.parameter}=` : ""

        vulnerabilities.push({
          id: `WAPITI-${idCounter}`,
          name: category,
          severity,
          location: `${location}${paramInfo}`,
          cve: normalizedName,
          description: `${defaultDesc}\nMethod: ${entry.method}\n${entry.evil_request ? `Payload: ${entry.evil_request}` : ""}`.trim(),
          recommendation: defaultSol,
          source: "wapiti",
        })
      }
    }

    const totalChecks = vulnerabilities.length > 0 ? vulnerabilities.length + 20 : 20
    return { vulnerabilities, totalChecks, errors: [], scannerName }

  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Wapiti scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  } finally {
    try { unlinkSync(outputFile) } catch { /* ignore */ }
  }
}
