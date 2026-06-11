/**
 * bearer-scanner.ts — Bearer 数据安全 SAST 扫描器
 *
 * Bearer 专注于数据安全流分析，检测隐私合规（GDPR）违规、
 * 敏感数据泄露、数据验证链缺失等问题。与 Semgrep 互补。
 *
 * 依赖: tools/bin/bearer (Linux/macOS) 或 PATH 中的 bearer
 * 下载: https://github.com/Bearer/bearer/releases
 * 注意: Bearer 无官方 Windows 发行版，需 Linux/macOS 环境
 */

import { execAsync } from "./exec"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const BEARER_PATH = join(process.cwd(), "tools", "bin", "bearer")

function isAvailable(): boolean {
  // Windows 不支持，检查 bearer 二进制
  if (process.platform === "win32") return false
  return existsSync(BEARER_PATH)
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

export async function runBearerScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "bearer"
  if (!isAvailable()) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["Bearer CLI not found. Install from https://github.com/Bearer/bearer"],
      scannerName,
    }
  }

  try {
    const { stdout } = await execAsync(
      `"${BEARER_PATH}" scan "${targetPath}" --format json --quiet --severity critical,high,medium,low`,
      { timeout: 300000, maxBuffer: 50 * 1024 * 1024 },
    )

    const vulnerabilities: Vulnerability[] = []
    const result = JSON.parse(stdout)

    for (const finding of result?.findings || []) {
      vulnerabilities.push({
        id: `BR-${vulnerabilities.length + 1}`,
        name: finding.title || finding.rule?.title || "Data security finding",
        severity: mapSeverity(finding.severity || finding.rule?.severity || "medium"),
        location: finding.filename || finding.location?.filename || targetPath +
          (finding.line ? `:${finding.line}` : ""),
        cve: finding.rule?.id || "Bearer",
        description: finding.description || finding.rule?.description || "",
        recommendation: finding.remediation || finding.rule?.remediation || "",
        source: scannerName,
      })
    }

    const totalChecks = Math.max(vulnerabilities.length + 20, 20)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [(err as Error).message],
      scannerName,
    }
  }
}
