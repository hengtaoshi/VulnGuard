import { execSync } from "child_process"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const BIN_DIR = join(process.cwd(), "tools", "bin")
const WORDLIST = join(process.cwd(), "tools", "wordlists", "common.txt")

function checkWordlist(): string | null {
  if (existsSync(WORDLIST)) return WORDLIST
  return null
}

// ─── Ffuf ──────────────────────────────────────────────────────────────────────

const FFUF_PATH = join(BIN_DIR, "ffuf.exe")

function isFfufAvailable(): boolean {
  try {
    execSync(`"${FFUF_PATH}" -V`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runFfufScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "ffuf"
  if (!isFfufAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Ffuf not found"], scannerName }
  }

  const wordlistPath = checkWordlist()
  if (!wordlistPath) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["Ffuf scan skipped: wordlist not found at tools/wordlists/common.txt"],
      scannerName,
    }
  }

  try {
    const baseUrl = targetPath.replace(/\/+$/, "")
    const output = execSync(
      `"${FFUF_PATH}" -u "${baseUrl}/FUZZ" -w "${wordlistPath}" -ac -of json -o -`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const raw = output.toString().trim()
    if (!raw) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    const parsed = JSON.parse(raw)
    const results = parsed.results || []

    const vulnerabilities: Vulnerability[] = results.map(
      (r: { url?: string; status?: number; redirectlocation?: string; content_length?: number }, idx: number) => {
        const status = r.status || 0
        const severity = status === 200 ? "Medium" : status === 403 ? "Low" : "Low"

        return {
          id: `FFUF-${idx + 1}`,
          name: `Discovered Path: ${r.url || "unknown"} (HTTP ${status})`,
          severity: severity as "Medium" | "Low",
          location: r.url || baseUrl,
          cve: "DISCOVERY",
          description: `Discovered ${r.redirectlocation ? "redirect" : "endpoint"} via fuzzing. Status: ${status}.${r.redirectlocation ? ` Redirects to: ${r.redirectlocation}` : ""}`,
          recommendation: `Review the discovered endpoint at ${r.url || baseUrl} and ensure it is properly secured.`,
          source: scannerName,
        }
      },
    )

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Ffuf scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Gobuster ───────────────────────────────────────────────────────────────────

const GOBUSTER_PATH = join(BIN_DIR, "gobuster.exe")

function isGobusterAvailable(): boolean {
  try {
    execSync(`"${GOBUSTER_PATH}" --version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runGobusterScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "gobuster"
  if (!isGobusterAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Gobuster not found"], scannerName }
  }

  const wordlistPath = checkWordlist()
  if (!wordlistPath) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["Gobuster scan skipped: wordlist not found at tools/wordlists/common.txt"],
      scannerName,
    }
  }

  const baseUrl = targetPath.replace(/\/+$/, "")

  try {
    const output = execSync(
      `"${GOBUSTER_PATH}" dir -u "${baseUrl}" -w "${wordlistPath}" -t 5 --timeout 30s`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = lines
      .map((line, idx) => {
        const match = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/)
        if (!match) return null

        const status = parseInt(match[2], 10)
        const path = match[1]
        const severity = status === 200 ? "Medium" : status === 403 ? "Low" : "Low"

        return {
          id: `GOBUSTER-${idx + 1}`,
          name: `Discovered Path: ${path} (HTTP ${status})`,
          severity: severity as "Medium" | "Low",
          location: `${baseUrl}${path}`,
          cve: "DISCOVERY",
          description: `Discovered directory/file via gobuster directory enumeration. Status: ${status}. Path: ${path}.`,
          recommendation: `Review the discovered path "${path}" and ensure it is properly secured.`,
          source: scannerName,
        } as Vulnerability
      })
      .filter((v): v is Vulnerability => v !== null)

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Gobuster scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Kiterunner ─────────────────────────────────────────────────────────────────

const KITERUNNER_PATH = join(BIN_DIR, "kiterunner.exe")

function isKiterunnerAvailable(): boolean {
  try {
    execSync(`"${KITERUNNER_PATH}" version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runKiterunnerScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "kiterunner"
  if (!isKiterunnerAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Kiterunner not found"], scannerName }
  }

  const wordlistPath = checkWordlist()
  if (!wordlistPath) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["Kiterunner scan skipped: wordlist not found at tools/wordlists/common.txt"],
      scannerName,
    }
  }

  const baseUrl = targetPath.replace(/\/+$/, "")

  try {
    const output = execSync(
      `"${KITERUNNER_PATH}" brute "${baseUrl}/" -w "${wordlistPath}"`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = lines
      .map((line, idx) => {
        // Attempt to match common kiterunner output formats:
        // e.g. "200   GET /api/users 1234" or timestamp-based lines
        const match = line.match(/(\d{3})\s+\w+\s+(\/\S+)/)
        if (!match) return null

        const status = parseInt(match[1], 10)
        const path = match[2]
        const severity = status === 200 ? "Medium" : status === 403 ? "Low" : "Low"

        return {
          id: `KITERUNNER-${idx + 1}`,
          name: `Discovered API Route: ${path} (HTTP ${status})`,
          severity: severity as "Medium" | "Low",
          location: `${baseUrl}${path}`,
          cve: "DISCOVERY",
          description: `API route discovered via kiterunner. Status: ${status}. Path: ${path}. API routes may expose sensitive functionality.`,
          recommendation: `Ensure the API route "${path}" requires proper authentication and authorization.`,
          source: scannerName,
        } as Vulnerability
      })
      .filter((v): v is Vulnerability => v !== null)

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Kiterunner scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
