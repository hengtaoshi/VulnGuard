import { execSync } from "child_process"
import { join } from "path"
import { existsSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const LOCAL_RULES = join(process.cwd(), "tools", "semgrep-rules", "security.yaml")

type SemgrepSev = "ERROR" | "WARNING" | "INFO"
type VulnSev = "Critical" | "High" | "Medium"

interface SemgrepResult {
  check_id: string
  path: string
  start: { line: number }
  extra: {
    message: string
    metadata: { cwe?: string[]; references?: string[] }
    severity: SemgrepSev
    lines?: string
  }
}

function severityMap(s: SemgrepSev): VulnSev {
  return s === "ERROR" ? "Critical" : s === "WARNING" ? "High" : "Medium"
}

interface SemgrepOutput {
  results: SemgrepResult[]
  paths: { scanned: string[] }
}

/**
 * 尝试用远程 Semgrep Registry 规则运行（作为备用）
 */
function runRemoteSemgrep(targetPath: string): string | null {
  try {
    // p/default 包含安全规则 + 正确性规则
    const remotes = ["p/security-audit", "p/default"]
    for (const remote of remotes) {
      try {
        const target = targetPath.replace(/\\/g, "/")
        return execSync(
          `"semgrep" --config="${remote}" --json --timeout=60 "${target}"`,
          { timeout: 180000, maxBuffer: 10 * 1024 * 1024, encoding: "utf-8", env: { ...process.env, PYTHONIOENCODING: "utf-8" } },
        )
      } catch { /* try next */ }
    }
    return null
  } catch {
    return null
  }
}

export async function runSemgrepScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "semgrep"

  // ── 优先使用本地规则 ───────────────────────────────────────
  let stdout: string | null = null
  let usedLocalRules = false

  if (existsSync(LOCAL_RULES)) {
    try {
      const rulesPath = LOCAL_RULES.replace(/\\/g, "/")
      const target = targetPath.replace(/\\/g, "/")
      const cmd = `"semgrep" --config="${rulesPath}" --json --timeout=30 "${target}"`
      stdout = execSync(cmd, { timeout: 120000, maxBuffer: 10 * 1024 * 1024, encoding: "utf-8", env: { ...process.env, PYTHONIOENCODING: "utf-8" } })
      usedLocalRules = true
    } catch { /* fall through to remote */ }
  }

  // ── 如果本地规则不存在或失败，尝试远程注册表 ─────────────
  if (!stdout) {
    stdout = runRemoteSemgrep(targetPath)
  }

  if (!stdout) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [existsSync(LOCAL_RULES)
        ? "Semgrep: both local rules and remote registry failed"
        : "Semgrep rules not found at " + LOCAL_RULES + " and remote registry unavailable"],
      scannerName,
    }
  }
  // 解析 semgrep JSON 输出
  const jsonStart = stdout.indexOf("{")
  const jsonEnd = stdout.lastIndexOf("}")
  const jsonStr = jsonStart >= 0 && jsonEnd >= 0 ? stdout.slice(jsonStart, jsonEnd + 1) : stdout
  const parsed: SemgrepOutput = JSON.parse(jsonStr)

  const vulnerabilities: Vulnerability[] = parsed.results.map((r, i) => ({
    id: `SG-${i + 1}`,
    name: r.extra.message.split(".")[0] || "Semgrep finding",
    severity: severityMap(r.extra.severity),
    location: `${r.path}:${r.start.line}`,
    cve: r.extra.metadata.cwe?.[0] || "CWE-Info",
    description: r.extra.message,
    recommendation: r.extra.metadata.references?.[0]
      ? `参考: ${r.extra.metadata.references[0]}`
      : "Review and fix the identified issue",
    code: r.extra.lines || undefined,
    source: scannerName,
  }))

  return {
    vulnerabilities,
    totalChecks: parsed.paths?.scanned?.length || vulnerabilities.length + 10,
    errors: [],
    scannerName,
  }
}
