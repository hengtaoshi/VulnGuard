import { execSync, exec } from "child_process"
import { promisify } from "util"
import { join } from "path"
import type { Vulnerability } from "@/lib/api/types"

const SEMGREP_PATH = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\semgrep.exe"
const LOCAL_RULES = join(process.cwd(), "tools", "semgrep-rules", "security.yaml")
const execAsync = promisify(exec)

interface SemgrepResult {
  check_id: string
  path: string
  start: { line: number; col: number; offset: number }
  end: { line: number; col: number; offset: number }
  extra: {
    message: string
    metadata: {
      cwe?: string[]
      cve?: string[]
      references?: string[]
      category?: string
    }
    severity: "ERROR" | "WARNING" | "INFO"
    lines?: string
    fix?: string
  }
}

interface SemgrepOutput {
  results: SemgrepResult[]
  errors: { message: string }[]
  paths: { scanned: string[] }
}

function severityMap(semgrepSeverity: string): "Critical" | "High" | "Medium" | "Low" {
  switch (semgrepSeverity) {
    case "ERROR": return "Critical"
    case "WARNING": return "High"
    case "INFO": return "Medium"
    default: return "Low"
  }
}

function extractCWE(refs: string[] | undefined): string {
  if (!refs || refs.length === 0) return "—"
  for (const r of refs) {
    const m = r.match(/CWE-\d+/)
    if (m) return m[0]
  }
  return "—"
}

function generateRecommendation(severity: string, message: string, metadata: SemgrepResult["extra"]["metadata"]): string {
  const refs = metadata.references
  if (refs && refs.length > 0) {
    return `参考安全最佳实践: ${refs[0]}. ${message.split(".")[0]}.`
  }
  const sev = severityMap(severity)
  if (sev === "Critical" || sev === "High") {
    return `立即修复: ${message.split(".")[0]}. 建议实施输入验证、输出编码、最小权限原则等安全措施。`
  }
  return `建议修复: ${message.split(".")[0]}. 遵循安全编码规范进行整改。`
}

async function runSemgrep(targetPath: string, retries = 1): Promise<{ vulnerabilities: Vulnerability[], totalChecks: number }> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const { stdout: stdoutBuf } = await execAsync(
        `"${SEMGREP_PATH}" --config="${LOCAL_RULES}" --json --no-git-ignore --timeout=30 "${targetPath}"`,
        {
          timeout: 120000,
          maxBuffer: 10 * 1024 * 1024,
          env: { ...process.env, PYTHONUTF8: "1" },
        },
      )

      const stdout = stdoutBuf.trim()
      const jsonStart = stdout.indexOf("{")
      const jsonEnd = stdout.lastIndexOf("}")
      const jsonStr = jsonStart >= 0 && jsonEnd >= 0 ? stdout.slice(jsonStart, jsonEnd + 1) : stdout
      const parsed: SemgrepOutput = JSON.parse(jsonStr)

      if (parsed.errors && parsed.errors.length > 0) {
        for (const err of parsed.errors) {
          console.error("Semgrep error:", err.message)
        }
      }

      const vulnerabilities: Vulnerability[] = parsed.results.map((r, idx) => {
        const sev = severityMap(r.extra.severity)
        const cweId = extractCWE(r.extra.metadata?.cwe)
        return {
          id: `VULN-${idx + 1}`,
          name: r.check_id.split(".").pop()?.replace(/-/g, " ") || "Unknown",
          severity: sev,
          location: `${r.path}:${r.start.line}:${r.start.col}`,
          cve: cweId,
          description: r.extra.message,
          recommendation: generateRecommendation(r.extra.severity, r.extra.message, r.extra.metadata),
          code: r.extra.lines && r.extra.lines !== "requires login" ? r.extra.lines : undefined,
          source: "semgrep",
        }
      })

      const totalChecks = parsed.paths.scanned.length > 0
        ? parsed.results.length + Math.max(0, 50 - parsed.results.length)
        : 0

      return { vulnerabilities, totalChecks }
    } catch (err) {
      if (attempt < retries) {
        console.error(`Semgrep attempt ${attempt + 1} failed, retrying...`)
        continue
      }
      const stderr = (err as { stderr?: string }).stderr || ""
      if (stderr.includes("semgrep: command not found") || stderr.includes("not recognized")) {
        throw new Error("Semgrep is not installed. Run: pip install semgrep")
      }
      if (stderr) console.error("Semgrep stderr:", stderr)
      throw new Error(`Semgrep scan failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  return { vulnerabilities: [], totalChecks: 0 }
}

export async function runSemgrepScan(targetPath: string): Promise<{
  vulnerabilities: Vulnerability[]
  totalChecks: number
}> {
  return runSemgrep(targetPath)
}

export async function runSemgrepOnCode(codeContent: string, language: string): Promise<{
  vulnerabilities: Vulnerability[]
  totalChecks: number
}> {
  const tmpDir = join(require("os").tmpdir(), `vulnguard-scan-${Date.now()}`)
  try {
    require("fs").mkdirSync(tmpDir, { recursive: true })
    const ext = language === "javascript" ? "js" : language === "typescript" ? "ts" : language === "python" ? "py" : "txt"
    const filePath = join(tmpDir, `code.${ext}`)
    require("fs").writeFileSync(filePath, codeContent, "utf-8")
    return await runSemgrepScan(tmpDir)
  } finally {
    try { require("fs").rmSync(tmpDir, { recursive: true, force: true }) } catch { /* ignore cleanup errors */ }
  }
}
