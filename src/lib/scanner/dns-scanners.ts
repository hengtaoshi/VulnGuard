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

// ─── Subfinder ──────────────────────────────────────────────────────────────────

const SUBFINDER_PATH = join(BIN_DIR, "subfinder.exe")

function isSubfinderAvailable(): boolean {
  try {
    execSync(`"${SUBFINDER_PATH}" -version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runSubfinderScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "subfinder"
  if (!isSubfinderAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Subfinder not found"], scannerName }
  }

  const domain = extractDomain(targetPath)
  try {
    const output = execSync(
      `"${SUBFINDER_PATH}" -d "${domain}" -json`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = []

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line)
        if (parsed.host) {
          vulnerabilities.push({
            id: `SUBFINDER-${vulnerabilities.length + 1}`,
            name: `Discovered Subdomain: ${parsed.host}`,
            severity: "Low",
            location: parsed.host,
            cve: "RECON",
            description: `Subdomain discovered via subfinder passive enumeration: ${parsed.host}`,
            recommendation: "Verify the subdomain is intended to be exposed and properly secured.",
            source: scannerName,
          })
        }
      } catch {
        // skip malformed JSON lines
      }
    }

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Subfinder scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Assetfinder ────────────────────────────────────────────────────────────────

const ASSETFINDER_PATH = join(BIN_DIR, "assetfinder.exe")

function isAssetfinderAvailable(): boolean {
  // assetfinder doesn't support --version, check by running with -h
  try {
    execSync(`"${ASSETFINDER_PATH}" -h`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    try { return existsSync(ASSETFINDER_PATH) } catch { return false }
  }
}

export async function runAssetfinderScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "assetfinder"
  if (!isAssetfinderAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Assetfinder not found"], scannerName }
  }

  const domain = extractDomain(targetPath)
  try {
    const output = execSync(
      `"${ASSETFINDER_PATH}" --subs-only "${domain}"`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = lines.map((host, idx) => ({
      id: `ASSETFINDER-${idx + 1}`,
      name: `Discovered Subdomain: ${host}`,
      severity: "Low",
      location: host,
      cve: "RECON",
      description: `Subdomain discovered via assetfinder: ${host}`,
      recommendation: "Verify the subdomain is intended to be exposed and properly secured.",
      source: scannerName,
    }))

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Assetfinder scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Shuffledns ─────────────────────────────────────────────────────────────────

const SHUFFLEDNS_PATH = join(BIN_DIR, "shuffledns.exe")

function isShufflednsAvailable(): boolean {
  try {
    execSync(`"${SHUFFLEDNS_PATH}" -version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runShufflednsScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "shuffledns"
  if (!isShufflednsAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Shuffledns not found"], scannerName }
  }

  const domain = extractDomain(targetPath)
  try {
    const output = execSync(
      `"${SHUFFLEDNS_PATH}" -d "${domain}"`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = lines.map((host, idx) => ({
      id: `SHUFFLEDNS-${idx + 1}`,
      name: `Resolved Subdomain: ${host}`,
      severity: "Low",
      location: host,
      cve: "RECON",
      description: `Subdomain resolved via shuffledns: ${host}`,
      recommendation: "Verify the subdomain is intended to be exposed and properly secured.",
      source: scannerName,
    }))

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Shuffledns scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

// ─── Amass ──────────────────────────────────────────────────────────────────────

const AMASS_PATH = join(BIN_DIR, "amass.exe")

function isAmassAvailable(): boolean {
  try {
    execSync(`"${AMASS_PATH}" -version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runAmassScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "amass"
  if (!isAmassAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Amass not found"], scannerName }
  }

  const domain = extractDomain(targetPath)
  try {
    const output = execSync(
      `"${AMASS_PATH}" enum -passive -d "${domain}"`,
      { timeout: 30000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n").filter(Boolean)
    const vulnerabilities: Vulnerability[] = lines.map((host, idx) => ({
      id: `AMASS-${idx + 1}`,
      name: `Discovered Subdomain: ${host}`,
      severity: "Low",
      location: host,
      cve: "RECON",
      description: `Subdomain discovered via amass passive enumeration: ${host}`,
      recommendation: "Verify the subdomain is intended to be exposed and properly secured.",
      source: scannerName,
    }))

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Amass scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
