import { readFileSync, existsSync, readdirSync, statSync } from "fs"
import { join, basename } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

// ─── OSV.dev API ──────────────────────────────────────────────────────────
const OSV_API = "https://api.osv.dev/v1/query"

interface OsvVulnerability {
  id: string
  summary?: string
  aliases?: string[]
}

interface OsvResponse {
  vulns?: OsvVulnerability[]
}

async function queryOsv(
  ecosystem: string,
  name: string,
  version: string,
): Promise<OsvVulnerability[]> {
  try {
    const res = await fetch(OSV_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { name, ecosystem },
        version,
      }),
    })
    if (!res.ok) return []
    const data: OsvResponse = await res.json()
    return data.vulns || []
  } catch {
    return []
  }
}

// ─── Package.resolved parser ───────────────────────────────────────────────

interface ResolvedDependency {
  identity: string
  location: string
  version: string
}

function parsePackageResolved(content: string): ResolvedDependency[] {
  try {
    const json = JSON.parse(content)
    const deps: ResolvedDependency[] = []

    // v1/v2 format: { "pins": [...] }
    // v3 format: { "pins": [...], "version": 3 }
    const pins = json.pins || json.objects?.pins || []
    for (const pin of pins) {
      const state = pin.state || {}
      const version = state.version
      if (version) {
        deps.push({
          identity: pin.identity || "",
          location: pin.location?.replace(/\.git$/, "") || "",
          version,
        })
      }
    }
    return deps
  } catch {
    return []
  }
}

// ─── Package.swift parser (basic) ───────────────────────────────────────────

interface SwiftDep {
  url: string
  version?: string
}

function parsePackageSwift(content: string): SwiftDep[] {
  const deps: SwiftDep[] = []

  // Match: .package(url: "https://...", from: "1.0.0")
  const fromRegex = /\.package\s*\(\s*url\s*:\s*"([^"]+)"[^)]*?from\s*:\s*"([^"]+)"/g
  let match: RegExpExecArray | null
  while ((match = fromRegex.exec(content)) !== null) {
    deps.push({ url: match[1].replace(/\.git$/, ""), version: match[2] })
  }

  // Match: .package(url: "https://...", exact: "1.0.0")
  const exactRegex = /\.package\s*\(\s*url\s*:\s*"([^"]+)"[^)]*?exact\s*:\s*"([^"]+)"/g
  while ((match = exactRegex.exec(content)) !== null) {
    deps.push({ url: match[1].replace(/\.git$/, ""), version: match[2] })
  }

  // Match: .package(url: "https://...", .upToNextMajor(from: "1.0.0"))
  const majorRegex = /\.package\s*\(\s*url\s*:\s*"([^"]+)"[^)]*?upToNextMajor\s*\(?\s*from\s*:\s*"([^"]+)"/g
  while ((match = majorRegex.exec(content)) !== null) {
    deps.push({ url: match[1].replace(/\.git$/, ""), version: match[2] })
  }

  return deps
}

// ─── Main scanner ─────────────────────────────────────────────────────────

export async function runSwiftScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "swift"
  const vulnerabilities: Vulnerability[] = []
  const errors: string[] = []
  let depCount = 0
  let hasPackageSwift = false

  // Find Swift dependency files (max depth 3)
  const resolvedFiles: string[] = []

  function walk(dir: string, depth: number) {
    if (depth > 4) return
    try {
      const entries = readdirSync(dir)
      // Check for Package.swift at project root
      if (depth === 0 && entries.includes("Package.swift")) {
        hasPackageSwift = true
      }
      for (const entry of entries) {
        const fullPath = join(dir, entry)
        try {
          const st = statSync(fullPath)
          if (st.isDirectory()) {
            if (!entry.startsWith(".") && entry !== "node_modules" && entry !== "build" && entry !== ".build") {
              walk(fullPath, depth + 1)
            }
          } else if (st.isFile() && entry === "Package.resolved") {
            resolvedFiles.push(fullPath)
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }
  walk(targetPath, 0)

  // ── 1. Parse Package.resolved (most accurate — has exact versions) ────
  const queriedUrls = new Set<string>()

  for (const file of resolvedFiles) {
    try {
      const content = readFileSync(file, "utf-8")
      const deps = parsePackageResolved(content)
      depCount += deps.length

      for (const dep of deps) {
        if (queriedUrls.has(dep.location)) continue
        queriedUrls.add(dep.location)

        // Query OSV using the git URL as package name, ecosystem "SwiftURL"
        const osvVulns = await queryOsv("SwiftURL", dep.location, dep.version)

        // Also try by identity name
        let identityVulns: OsvVulnerability[] = []
        if (dep.identity) {
          identityVulns = await queryOsv("SwiftURL", dep.identity, dep.version)
        }

        const allVulns = [...osvVulns, ...identityVulns]
        const seenIds = new Set<string>()

        for (const vuln of allVulns) {
          if (seenIds.has(vuln.id)) continue
          seenIds.add(vuln.id)

          vulnerabilities.push({
            id: vuln.id,
            name: vuln.id,
            severity: "High",
            location: `${file} → ${basename(dep.location || dep.identity)}@${dep.version}`,
            cve: vuln.id,
            description: vuln.summary || `Known vulnerability in ${dep.identity || dep.location} ${dep.version}`,
            recommendation: `Upgrade ${dep.identity || basename(dep.location)} to a patched version`,
            source: scannerName,
          })
        }
      }
    } catch { /* skip unreadable */ }
  }

  // ── 2. Found Package.swift but no Package.resolved → basic info ────────
  if (hasPackageSwift && resolvedFiles.length === 0) {
    vulnerabilities.push({
      id: "SWIFT-NO-RESOLVED",
      name: "Package.resolved not found",
      severity: "Low",
      location: `${targetPath}/Package.swift`,
      cve: "N/A",
      description: "Package.swift exists but no Package.resolved was found. Run 'swift package resolve' to generate a resolved file for accurate CVE scanning.",
      recommendation: "Run 'swift package resolve' to generate Package.resolved and re-scan",
      source: scannerName,
    })
  }

  // ── 3. No Swift project found → empty scan ────────────────────────────
  if (!hasPackageSwift && resolvedFiles.length === 0) {
    return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
  }

  // Deduplicate by CVE ID
  const seen = new Set<string>()
  const unique = vulnerabilities.filter(v => {
    if (seen.has(v.id)) return false
    seen.add(v.id)
    return true
  })

  return {
    vulnerabilities: unique,
    totalChecks: Math.max(depCount, 1),
    errors,
    scannerName,
  }
}
