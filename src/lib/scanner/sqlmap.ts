import { execSync, spawn } from "child_process"
import { tmpdir } from "os"
import { rmSync } from "fs"
import { join } from "path"

const SQLMAP_PATH = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\sqlmap.exe"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

function isAvailable(): boolean {
  try {
    execSync(`"${SQLMAP_PATH}" --version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

function parseSqlmapOutput(output: string, url: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = []

  if (!output.includes("vulnerable") && !output.includes("injection point")) {
    return vulnerabilities
  }

  const paramRegex = /(?:^|\n)Parameter:\s+(\S+)\s+\((\w+)\)/gm
  let paramMatch: RegExpExecArray | null
  while ((paramMatch = paramRegex.exec(output)) !== null) {
    const param = paramMatch[1]
    const method = paramMatch[2]

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
      recommendation: "Use parameterized queries (prepared statements). Validate and sanitize all user inputs.",
      source: "sqlmap",
    })
  }

  return vulnerabilities
}

function runSqlmapProcess(
  targetUrl: string,
  outputDir: string,
  timeoutMs: number,
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const args = [
      "-u", targetUrl,
      "--batch",
      "--level=1",
      "--forms",
      "--text-only",
      "--flush-session",
      "--disable-coloring",
      "--output-dir", outputDir,
      "--random-agent",
    ]

    const proc = spawn(SQLMAP_PATH, args, {
      env: { ...process.env, NO_PROXY: "*", no_proxy: "*", PYTHONUTF8: "1" },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    })

    let stdout = ""
    let stderr = ""

    proc.stdout.on("data", (data: Buffer) => {
      stdout += data.toString()
    })

    proc.stderr.on("data", (data: Buffer) => {
      stderr += data.toString()
    })

    const timer = setTimeout(() => {
      proc.kill()
      reject(new Error(`SQLMap timed out after ${timeoutMs / 1000}s`))
    }, timeoutMs)

    proc.on("close", (code) => {
      clearTimeout(timer)
      // sqlmap exit codes: 0=clean, 1=error, 2=vulnerable
      if (code === 2 || code === 0) {
        resolve({ stdout, stderr })
      } else {
        const msg = stderr.trim() || stdout.trim() || `exit code ${code}`
        reject(new Error(`SQLMap exited with code ${code}: ${msg.slice(0, 200)}`))
      }
    })

    proc.on("error", (err) => {
      clearTimeout(timer)
      reject(new Error(`SQLMap process error: ${err.message}`))
    })
  })
}

export async function runSqlmapScan(targetUrl: string): Promise<ScanResult> {
  const scannerName = "sqlmap"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["SQLMap not installed. Run: pip install sqlmap"], scannerName }
  }

  const outputDir = join(tmpdir(), `sqlmap-run-${Date.now()}`)

  try {
    const { stdout, stderr } = await runSqlmapProcess(targetUrl, outputDir, 120000)

    const allOutput = [stdout, stderr].join("\n")
    const vulnerabilities = parseSqlmapOutput(allOutput, targetUrl)
    const totalChecks = vulnerabilities.length > 0 ? vulnerabilities.length * 10 + 50 : 50

    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [err instanceof Error ? err.message : String(err)],
      scannerName,
    }
  } finally {
    try { rmSync(outputDir, { recursive: true, force: true }) } catch { /* ignore cleanup errors */ }
  }
}
