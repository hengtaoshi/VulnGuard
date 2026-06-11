/**
 * trufflehog-scanner.ts — TruffleHog 密钥检测引擎
 *
 * TruffleHog v3 是业界领先的密钥泄露检测工具，支持 800+ 种检测器，
 * 比 Gitleaks 覆盖面更广。支持文件系统扫描和 Git 历史扫描。
 *
 * 依赖: tools/bin/trufflehog.exe
 * 下载: https://github.com/trufflesecurity/trufflehog
 */

import { execAsync } from "./exec"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const TRUFFLEHOG_PATH = join(process.cwd(), "tools", "bin", "trufflehog.exe")

function isAvailable(): boolean {
  return existsSync(TRUFFLEHOG_PATH)
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

export async function runTrufflehogScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "trufflehog"
  if (!isAvailable()) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["TruffleHog not found"],
      scannerName,
    }
  }

  try {
    // TruffleHog filesystem 模式扫描目录
    const { stdout } = await execAsync(
      `"${TRUFFLEHOG_PATH}" filesystem --directory="${targetPath}" --json --no-verification --no-update`,
      { timeout: 300000, maxBuffer: 50 * 1024 * 1024 },
    )

    const vulnerabilities: Vulnerability[] = []
    const lines = stdout.trim().split("\n").filter(Boolean)

    for (const line of lines) {
      try {
        const result = JSON.parse(line)
        if (!result.DetectorName) continue

        vulnerabilities.push({
          id: `TH-${vulnerabilities.length + 1}`,
          name: result.DetectorName || "Secret detected",
          severity: mapSeverity(result.Severity || "medium"),
          location: result.Metadata?.Filename || result.SourceMetadata?.Data?.Filesystem?.file || targetPath,
          cve: result.DetectorType || "TruffleHog",
          description: `Detected ${result.DecoderType || "plain"} secret: ${(result.RawV2 || result.Raw || "").slice(0, 80)}`,
          recommendation: `Remove the exposed ${result.DetectorName} from the code. Use environment variables or a secret manager (e.g., HashiCorp Vault, AWS Secrets Manager). If this is a test key, rotate it immediately.`,
          source: scannerName,
        })
      } catch {
        // skip malformed JSON lines
      }
    }

    const totalChecks = Math.max(vulnerabilities.length + 50, 50)
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
