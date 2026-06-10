import { execSync } from "child_process"
import { join } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const BIN_DIR = join(process.cwd(), "tools", "bin")

// ─── Httpx ──────────────────────────────────────────────────────────────────────

const HTTPX_PATH = join(BIN_DIR, "httpx.exe")

function isHttpxAvailable(): boolean {
  try {
    execSync(`"${HTTPX_PATH}" -version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runHttpxScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "httpx"
  if (!isHttpxAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Httpx not found"], scannerName }
  }

  try {
    const output = execSync(
      `"${HTTPX_PATH}" -u "${targetPath}" -json -silent -tech-detect -status-code -content-type -content-length -web-server -title`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = []

    for (const line of lines) {
      try {
        const data = JSON.parse(line)
        const techs: string[] = data.tech || []
        const webserver = data.webserver || ""
        const title = data.title || ""
        const statusCode = data.status_code || 0
        const contentType = data.content_type || ""
        const contentLength = data.content_length || 0

        // Detected technologies
        if (techs.length > 0) {
          vulnerabilities.push({
            id: `HTTPX-TECH-${vulnerabilities.length + 1}`,
            name: `Detected Technologies: ${techs.join(", ")}`,
            severity: "Low",
            location: targetPath,
            cve: "FINGERPRINT",
            description: `Detected technologies on target: ${techs.join(", ")}. This information can help attackers identify potential attack vectors.`,
            recommendation: "Review the necessity of each detected technology. Remove unused components and keep all software updated.",
            source: scannerName,
          })
        }

        // Web server info
        if (webserver) {
          vulnerabilities.push({
            id: `HTTPX-SRV-${vulnerabilities.length + 1}`,
            name: `Web Server: ${webserver}`,
            severity: "Low",
            location: targetPath,
            cve: "FINGERPRINT",
            description: `Server is running ${webserver}. Page title: "${title}". Status: ${statusCode}. Content-Type: ${contentType}. Content-Length: ${contentLength}.`,
            recommendation: "Keep the web server software updated and follow security best practices for its configuration.",
            source: scannerName,
          })
        }

        // Important header / status findings
        if (statusCode === 301 || statusCode === 302 || statusCode === 307 || statusCode === 308) {
          vulnerabilities.push({
            id: `HTTPX-REDIR-${vulnerabilities.length + 1}`,
            name: `Redirect Detected (HTTP ${statusCode})`,
            severity: "Low",
            location: targetPath,
            cve: "INFO",
            description: `Target returns a ${statusCode} redirect. This may affect scanning results if the redirect target is not followed.`,
            recommendation: "Ensure redirect targets are also included in the security assessment scope.",
            source: scannerName,
          })
        }
      } catch {
        // skip malformed JSON lines
      }
    }

    // If no enriched findings, still report the probe completed
    if (vulnerabilities.length === 0) {
      vulnerabilities.push({
        id: "HTTPX-INFO-1",
        name: "HTTP Probe Completed",
        severity: "Low",
        location: targetPath,
        cve: "FINGERPRINT",
        description: "HTTP probing completed. No specific technology fingerprint or server info identified.",
        recommendation: "N/A",
        source: scannerName,
      })
    }

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Httpx scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Wafw00f ────────────────────────────────────────────────────────────────────

const WAFW00F_EXPLICIT = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\wafw00f.exe"

function resolveWafw00fPath(): string | null {
  // Try generic command first
  try {
    execSync(`wafw00f --version 2>&1`, { stdio: "pipe", timeout: 5000 })
    return "wafw00f"
  } catch {
    // Try explicit Python path
    try {
      execSync(`"${WAFW00F_EXPLICIT}" --version 2>&1`, { stdio: "pipe", timeout: 5000 })
      return WAFW00F_EXPLICIT
    } catch {
      return null
    }
  }
}

export async function runWafw00fScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "wafw00f"
  const wafPath = resolveWafw00fPath()
  if (!wafPath) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Wafw00f not found"], scannerName }
  }

  try {
    const output = execSync(
      `"${wafPath}" "${targetPath}" -v`,
      { timeout: 60000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const text = output.toString()
    const vulnerabilities: Vulnerability[] = []

    // Parse WAF detection: "The site https://... is behind Cloudflare (Cloudflare)"
    const wafMatch = text.match(/The site\s+\S+\s+is behind\s+([^\n]+)/i)
    const wafGeneric = text.match(/behind.*WAF/i)

    if (wafMatch) {
      const wafName = wafMatch[1].trim()
      vulnerabilities.push({
        id: "WAF-1",
        name: `WAF Detected: ${wafName}`,
        severity: "Low",
        location: targetPath,
        cve: "WAF",
        description: `Web Application Firewall detected: ${wafName}. The WAF may block or alter certain requests during security testing.`,
        recommendation: "Ensure WAF rules are properly configured. Test for bypass techniques during authorized assessments.",
        source: scannerName,
      })
    } else if (text.includes("No WAF detected")) {
      vulnerabilities.push({
        id: "WAF-1",
        name: "No WAF Detected",
        severity: "Low",
        location: targetPath,
        cve: "WAF",
        description: "No Web Application Firewall was detected. The target may be directly accessible without filtering.",
        recommendation: "Consider implementing a WAF to protect against common web attacks.",
        source: scannerName,
      })
    } else if (wafGeneric) {
      vulnerabilities.push({
        id: "WAF-1",
        name: "WAF Detected (Generic)",
        severity: "Low",
        location: targetPath,
        cve: "WAF",
        description: "A Web Application Firewall appears to be present, but the vendor could not be identified from the output.",
        recommendation: "Identify the WAF vendor and ensure rules are up to date.",
        source: scannerName,
      })
    }

    if (vulnerabilities.length === 0) {
      vulnerabilities.push({
        id: "WAF-1",
        name: "WAF Detection Completed",
        severity: "Low",
        location: targetPath,
        cve: "WAF",
        description: "WAF detection completed. The output did not clearly indicate a WAF presence or absence.",
        recommendation: "Manually verify WAF presence by inspecting response headers.",
        source: scannerName,
      })
    }

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Wafw00f scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
