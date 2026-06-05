import { execSync } from "child_process"
import { tmpdir } from "os"
import { rmSync } from "fs"
import { join } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

function isAvailable(): boolean {
  try {
    execSync("sqlmap --version", { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

function parseSqlmapOutput(output: string, url: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = []

  // Quick check if vulnerable at all
  if (!output.includes("vulnerable") && !output.includes("injection point")) {
    return vulnerabilities
  }

  // Find all Parameter: lines and extract metadata from context after each
  const paramRegex = /(?:^|\n)Parameter:\s+(\S+)\s+\((\w+)\)/gm
  let paramMatch: RegExpExecArray | null
  while ((paramMatch = paramRegex.exec(output)) !== null) {
    const param = paramMatch[1]
    const method = paramMatch[2]

    // Get text after this parameter line to extract Type/Title/Payload
    const afterMatch = output.slice(paramMatch.index)

    const typeMatch = afterMatch.match(/Type:\s+(.+)/)
    const titleMatch = afterMatch.match(/Title:\s+(.+)/)
    const payloadMatch = afterMatch.match(/Payload:\s+(.+)/)

    const type = typeMatch ? typeMatch[1].trim() : "Unknown"
    const title = titleMatch ? titleMatch[1].trim() : "Unknown"
    const payload = payloadMatch ? payloadMatch[1].trim() : ""

    const severity: "Critical" | "High" = title.toLowerCase().includes("union") ? "Critical" : "High"

    vulnerabilities.push({
      id: `SQLMAP-${vulnerabilities.length + 1}`,
      name: `SQL Injection: ${title}`,
      severity,
      location: `${url}${method.toLowerCase() === "get" && !url.includes("?") ? "?" : method.toLowerCase() === "get" ? "&" : ""}${param}=`,
      cve: "SQLI",
      description: `SQL injection in "${param}" (${method}).\nType: ${type}\nTechnique: ${title}\nPayload: ${payload || "(see sqlmap log)"}`,
      recommendation: `Use parameterized queries (prepared statements). Validate and sanitize all user inputs.`,
      source: "sqlmap",
    })
  }

  return vulnerabilities
}

export async function runSqlmapScan(targetUrl: string): Promise<ScanResult> {
  const scannerName = "sqlmap"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["SQLMap not installed. Run: pip install sqlmap"], scannerName }
  }

  const outputDir = join(tmpdir(), `sqlmap-run-${Date.now()}`)

  try {
    // Extract base URL and potentially add a test parameter if none exists
    let scanUrl = targetUrl
    // If URL has no query parameter, try common ones or use the URL directly
    if (!scanUrl.includes("?")) {
      // For URLs without obvious parameters, sqlmap can crawl, but that's slow.
      // We'll try the URL as-is and let sqlmap test common locations
    }

    // Run sqlmap: level 3 adds ORDER BY for UNION tests, risk 1 keeps payloads minimal
    const output = execSync(
      `sqlmap -u "${scanUrl}" --batch --level=3 --risk=1 --text-only --time-sec=3 --flush-session --disable-coloring --output-dir="${outputDir}"`,
      {
        timeout: 180000,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env, NO_PROXY: "*", no_proxy: "*" },
      },
    )

    const stdout = Buffer.isBuffer(output) ? output.toString("utf-8") : ""

    console.log("[sqlmap] stdout length:", stdout.length)
    console.log("[sqlmap] vulnerable:", stdout.includes("vulnerable"))
    console.log("[sqlmap] Parameter:", stdout.includes("Parameter:"))

    const vulnerabilities = parseSqlmapOutput(stdout, targetUrl)
    console.log("[sqlmap] vulnerabilities found:", vulnerabilities.length)

    const totalChecks = vulnerabilities.length > 0 ? vulnerabilities.length * 10 + 50 : 50
    return { vulnerabilities, totalChecks, errors: [], scannerName }

  } catch (err: unknown) {
    // sqlmap outputs findings to stderr, so check both stdout and stderr
    const stdOutput = (err as { stdout?: Buffer | string }).stdout
    const errOutput = (err as { stderr?: Buffer | string }).stderr
    const allText = [
      stdOutput ? (Buffer.isBuffer(stdOutput) ? stdOutput.toString("utf-8") : String(stdOutput)) : "",
      errOutput ? (Buffer.isBuffer(errOutput) ? errOutput.toString("utf-8") : String(errOutput)) : "",
    ].join("\n")

    const vulnerabilities = parseSqlmapOutput(allText, targetUrl)
    if (vulnerabilities.length > 0) {
      const totalChecks = vulnerabilities.length * 10 + 50
      return { vulnerabilities, totalChecks, errors: [], scannerName }
    }

    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`SQLMap scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  } finally {
    try { rmSync(outputDir, { recursive: true, force: true }) } catch { /* ignore cleanup errors */ }
  }
}
