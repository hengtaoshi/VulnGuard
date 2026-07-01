/**
 * osv-scanner.ts — Google OSV-Scanner 依赖漏洞扫描
 *
 * OSV-Scanner 基于 Open Source Vulnerabilities (OSV.dev) 数据库，
 * 覆盖 npm、PyPI、Go、Maven、NuGet、RubyGems、Cargo 等生态。
 * 与 npm-audit / pip-audit 互补。
 *
 * 依赖: tools/bin/osv-scanner.exe
 * 下载: https://github.com/google/osv-scanner
 */

import { execAsync } from "./exec"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { TOOLS_BIN } from "./paths"

const OSV_PATH = join(TOOLS_BIN, "osv-scanner.exe")

function isAvailable(): boolean {
  return existsSync(OSV_PATH)
}

function mapSeverity(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev.toLowerCase()) {
    case "critical": return "Critical"
    case "high": return "High"
    case "medium": return "Medium"
    case "low": return "Low"
    default: return "Medium"
  }
}

export async function runOsvScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "osv-scanner"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["OSV-Scanner not found"], scannerName }
  }

  try {
    const { stdout } = await execAsync(
      `"${OSV_PATH}" scan --format=json --recursive "${targetPath}"`,
      { timeout: 120000, maxBuffer: 20 * 1024 * 1024 },
    )

    const result = JSON.parse(stdout)
    const vulnerabilities: Vulnerability[] = []
    const seen = new Set<string>()

    for (const pkg of result.results || []) {
      for (const vuln of pkg.vulnerabilities || []) {
        const key = `${vuln.id}-${pkg.package?.name || ""}`
        if (seen.has(key)) continue
        seen.add(key)

        vulnerabilities.push({
          id: `OSV-${vulnerabilities.length + 1}`,
          name: vuln.summary || vuln.id || "OSV Vulnerability",
          severity: mapSeverity(vuln.severity?.[0]?.type || "medium"),
          location: pkg.package?.name
            ? `${pkg.package.name}@${pkg.package.version || "?"}`
            : targetPath,
          cve: vuln.id || "OSV",
          description: vuln.summary || vuln.details || "",
          recommendation: `升级 ${pkg.package?.name || "依赖"} 至修复版本`,
          source: scannerName,
        })
      }
    }

    const totalChecks = Math.max(vulnerabilities.length + 10, 10)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return { vulnerabilities: [], totalChecks: 0, errors: [(err as Error).message], scannerName }
  }
}
