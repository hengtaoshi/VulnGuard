/**
 * scorecard-scanner.ts — OpenSSF Scorecard 安全评估
 *
 * Scorecard 由 Google/OpenSSF 出品，从 10+ 维度评估开源项目的安全实践，
 * 包括：CI 测试、代码审查、分支保护、Token 权限、Fuzzing、SAST 等。
 *
 * 支持 --local 模式分析本地目录。
 * 依赖: tools/bin/scorecard.exe
 */

import { execAsync } from "./exec"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { TOOLS_BIN } from "./paths"

const SCORECARD_PATH = join(TOOLS_BIN, "scorecard.exe")

function isAvailable(): boolean {
  return existsSync(SCORECARD_PATH)
}

export async function runScorecardScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "scorecard"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Scorecard CLI not found"], scannerName }
  }

  try {
    const { stdout } = await execAsync(
      `"${SCORECARD_PATH}" --local="${targetPath}" --show-details --format=json`,
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024 },
    )

    const result = JSON.parse(stdout)
    const vulnerabilities: Vulnerability[] = []

    for (const check of result.checks || []) {
      if (check.score === -1) continue // 不可用的检查忽略

      const level = check.score >= 8 ? "Low"
        : check.score >= 5 ? "Medium"
        : check.score >= 3 ? "High"
        : "Critical"

      const docUrl = check.documentation?.shortDescription
        ? `https://openssf.org${check.documentation.shortDescription.url || ""}`
        : ""

      vulnerabilities.push({
        id: `SC-${vulnerabilities.length + 1}`,
        name: check.name || "Scorecard check",
        severity: level as "Critical" | "High" | "Medium" | "Low",
        location: targetPath,
        cve: `Scorecard-${check.name || "check"}`,
        description: `Score ${check.score}/10 — ${check.reason || ""}${docUrl ? `\n详情: ${docUrl}` : ""}`,
        recommendation: check.reason
          ? `改进建议: ${check.reason}`
          : `提高 ${check.name} 得分至 8/10 以上`,
        source: scannerName,
      })
    }

    const totalChecks = Math.max(vulnerabilities.length + 10, 10)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    return { vulnerabilities: [], totalChecks: 0, errors: [(err as Error).message], scannerName }
  }
}
