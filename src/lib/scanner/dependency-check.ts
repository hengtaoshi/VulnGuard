import { execAsync } from "./exec"
import { join } from "path"
import { existsSync, mkdirSync, readdirSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { TOOLS_BIN, TOOLS_DIR } from "./paths"

const BIN_DIR = TOOLS_BIN
const DC_BAT = join(BIN_DIR, "dependency-check.bat")
const DC_SH = join(BIN_DIR, "dependency-check.sh")
const DC_OUTPUT_DIR = join(process.cwd(), ".dc-report")
const DC_DATA_DIR = join(process.cwd(), ".nvd-cache", "data")

// ─── OWASP Dependency-Check JSON report types ─────────────────────────────

interface DcVulnerability {
  source: string
  name: string
  severity: string
  cvssScore?: number
  cvssAccessVector?: string
  cwe?: string
  description?: string
}

interface DcDependency {
  fileName: string
  filePath: string
  vulnerabilities?: DcVulnerability[]
}

interface DcReport {
  reportSchema: string
  dependencies: DcDependency[]
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function resolveDcPath(): string | null {
  // Check extracted install first (tools/dependency-check/bin/)
  const dcDir = join(TOOLS_DIR, "dependency-check", "bin", "dependency-check.bat")
  if (existsSync(dcDir)) return dcDir

  // Check bundled location (tools/bin/)
  if (existsSync(DC_BAT)) return DC_BAT
  if (existsSync(DC_SH)) return DC_SH

  // Fallback: check PATH — use execSync (quick, not blocking long)
  try {
    const { execSync } = require("child_process")
    execSync("dependency-check --version 2>&1", { stdio: "pipe", timeout: 5000 })
    return "dependency-check"
  } catch {
    try {
      const { execSync } = require("child_process")
      execSync("dependency-check.bat --version 2>&1", { stdio: "pipe", timeout: 5000 })
      return "dependency-check.bat"
    } catch {
      return null
    }
  }
}

function severityMap(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev.toUpperCase()) {
    case "CRITICAL":
    case "CRITICAL HIGH":
      return "Critical"
    case "HIGH":
      return "High"
    case "MEDIUM":
    case "MED":
      return "Medium"
    default:
      return "Low"
  }
}

// ─── Scan Implementation ──────────────────────────────────────────────────

export async function runDependencyCheckScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "dependency-check"
  const dcPath = resolveDcPath()
  if (!dcPath) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [
        "OWASP Dependency-Check not found. " +
        "Install from https://github.com/jeremylong/DependencyCheck/releases " +
        "and place dependency-check.bat in tools/bin/ or add to PATH. Requires Java 8+.",
      ],
      scannerName,
    }
  }

  // Check target exists — cleanup may have removed it before this scanner runs
  if (!existsSync(targetPath)) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["Dependency-Check: scan target no longer exists (may have been cleaned up)"],
      scannerName,
    }
  }

  // Prepare output and data directories
  if (!existsSync(DC_OUTPUT_DIR)) {
    mkdirSync(DC_OUTPUT_DIR, { recursive: true })
  }
  if (!existsSync(DC_DATA_DIR)) {
    mkdirSync(DC_DATA_DIR, { recursive: true })
  }

  try {
    // 首次运行时 NVD 数据库尚未下载，去掉 --noupdate 让它下载
    // 已有缓存时使用 --noupdate 避免每次扫描都重复下载
    const hasNvdCache = existsSync(DC_DATA_DIR) &&
      require("fs").readdirSync(DC_DATA_DIR).length > 0
    const noupdateFlag = hasNvdCache ? "--noupdate" : ""
    const nvdApiKey = process.env.NVD_API_KEY || ""
    const nvdFlag = nvdApiKey ? `--nvdApiKey ${nvdApiKey}` : ""
    const cmd = `"${dcPath}" ${noupdateFlag} --disableNodeAudit --disableRetireJS --disableOssIndex --disableAssembly --disableCentral --exclude "**/tools/**" --data "${DC_DATA_DIR}" --scan "${targetPath.replace(/\\/g, "/")}" --format JSON --out "${DC_OUTPUT_DIR}" --project VulnGuard ${nvdFlag}`
    const proxy = process.env.HTTP_PROXY || process.env.HTTPS_PROXY || ""
    const javaOpts = proxy
      ? `-Dhttp.proxyHost=${new URL(proxy).hostname} -Dhttp.proxyPort=${new URL(proxy).port} -Dhttps.proxyHost=${new URL(proxy).hostname} -Dhttps.proxyPort=${new URL(proxy).port}`
      : process.env.JAVA_OPTS || ""
    const env = { ...process.env, ...(javaOpts ? { JAVA_OPTS: javaOpts } : {}) }
    await execAsync(cmd, {
      timeout: 900000, // 15 min (首次下载 NVD 数据库可能很慢)
      maxBuffer: 50 * 1024 * 1024,
    })

    // Find the generated JSON report
    const files = readdirSync(DC_OUTPUT_DIR)
    const reportFile = files.find(f => f.endsWith("-dependency-check-report.json") || f === "dependency-check-report.json")
    if (!reportFile) {
      return { vulnerabilities: [], totalChecks: 0, errors: ["No report generated"], scannerName }
    }

    const fs = await import("fs")
    const raw = fs.readFileSync(join(DC_OUTPUT_DIR, reportFile), "utf-8")
    const report: DcReport = JSON.parse(raw)

    const vulnerabilities: Vulnerability[] = []
    let idx = 0

    for (const dep of report.dependencies || []) {
      for (const vuln of dep.vulnerabilities || []) {
        idx++
        const sev = severityMap(vuln.severity)
        const desc = vuln.description
          ? vuln.description.slice(0, 500)
          : `Vulnerability found in ${dep.fileName}`

        vulnerabilities.push({
          id: vuln.name || `DC-${idx}`,
          name: vuln.name || `Unknown CVE in ${dep.fileName}`,
          severity: sev,
          location: `${dep.fileName} → ${dep.filePath}`,
          cve: vuln.name || "CVE-Pending",
          description: desc,
          recommendation: vuln.cvssScore
            ? `CVSS ${vuln.cvssScore}. ${vuln.cwe ? `CWE: ${vuln.cwe}. ` : ""}Upgrade ${dep.fileName} to a non-vulnerable version.`
            : `Upgrade ${dep.fileName} to a non-vulnerable version.`,
          source: scannerName,
        })
      }
    }

    const totalChecks = Math.max(vulnerabilities.length, 1)
    return { vulnerabilities, totalChecks, errors: [], scannerName }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    const stderr = (err as any)?.stderr || ""
    const stdout = (err as any)?.stdout || ""
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Dependency-Check scan failed: ${msg}${stderr ? `\nstderr: ${stderr.slice(0, 500)}` : ""}`],
      scannerName,
    }
  }
}
