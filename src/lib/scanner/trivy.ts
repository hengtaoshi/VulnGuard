import { execAsync } from "./exec"
import { join } from "path"
import { existsSync, mkdirSync } from "fs"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface TrivyResult {
  Results?: {
    Target: string
    Vulnerabilities?: {
      VulnerabilityID: string
      PkgName: string
      InstalledVersion: string
      FixedVersion: string
      Title: string
      Description: string
      Severity: string
      PrimaryURL: string
      References: string[]
      CvssScore?: number
    }[]
  }[]
}

const TRIVY_PATH = join(process.cwd(), "tools", "bin", "trivy.exe")

function severityMap(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return "Critical"
    case "HIGH": return "High"
    case "MEDIUM": return "Medium"
    case "LOW": return "Low"
    default: return "Low"
  }
}

function isAvailable(): boolean {
  try {
    const { execSync } = require("child_process")
    execSync(`"${TRIVY_PATH}" --version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

function parseTrivyOutput(stdout: string, scannerName: string): ScanResult | null {
  const trimmed = stdout.trim()
  if (!trimmed) return null

  const jsonStart = trimmed.indexOf("{")
  if (jsonStart < 0) return null

  try {
    const parsed: TrivyResult = JSON.parse(trimmed.slice(jsonStart))
    const vulnerabilities: Vulnerability[] = []
    let idx = 0

    for (const result of parsed.Results || []) {
      for (const v of result.Vulnerabilities || []) {
        idx++
        const sev = severityMap(v.Severity)
        const desc = v.Description || v.Title || `Vulnerability in ${v.PkgName}`
        vulnerabilities.push({
          id: v.VulnerabilityID || `TRIVY-${idx}`,
          name: `${v.VulnerabilityID || "Vulnerability"} in ${v.PkgName}`,
          severity: sev,
          location: `${result.Target} → ${v.PkgName}@${v.InstalledVersion}`,
          cve: v.VulnerabilityID || "CVE-Pending",
          description: desc,
          recommendation: v.FixedVersion
            ? `Fix: upgrade ${v.PkgName} from ${v.InstalledVersion} to ${v.FixedVersion}`
            : `Review vulnerability in ${v.PkgName}@${v.InstalledVersion} and apply security patch`,
          code: undefined,
          source: "trivy",
        })
      }
    }

    return {
      vulnerabilities,
      totalChecks: idx + 100,
      errors: [],
      scannerName,
    }
  } catch {
    return null
  }
}

export async function runTrivyScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "trivy"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Trivy not found"], scannerName }
  }

  try {
    const trivyCacheDir = join(process.cwd(), ".trivy-cache")
    if (!existsSync(trivyCacheDir)) {
      try { mkdirSync(trivyCacheDir, { recursive: true }) } catch { /* ignore */ }
    }

    // Check if vulnerability DB is already cached — if not, skip vuln scanning
    // to avoid failed DB download (gcr.io not always accessible in China).
    const dbDir = join(trivyCacheDir, "db")
    const hasDb = existsSync(dbDir)
    // 启用所有扫描器：漏洞 + 错误配置 + secret + 许可证
    const scanners = hasDb ? "vuln,misconfig,secret,license" : "misconfig,secret,license"

    const { stdout: output } = await execAsync(
      `"${TRIVY_PATH}" fs --format=json --quiet --scanners ${scanners} --cache-dir "${trivyCacheDir}" "${targetPath}"`,
      {
        timeout: 300000,
        maxBuffer: 50 * 1024 * 1024,
        env: {
          ...process.env,
          TRIVY_DB_REPOSITORY: "ghcr.io/aquasecurity/trivy-db",
        },
      },
    )

    const result = parseTrivyOutput(output, scannerName)
    if (result) return result
    return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
  } catch (err: unknown) {
    // Trivy may return non-zero for various reasons — check stdout on the error
    if (err instanceof Error && "stdout" in err) {
      const stdout = (err as { stdout: string }).stdout?.toString().trim()
      if (stdout) {
        const result = parseTrivyOutput(stdout, scannerName)
        if (result) return result
      }
    }
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Trivy scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

/**
 * 容器镜像扫描 — 调用 `trivy image` 分析 Docker 镜像
 * 需要 Docker daemon 运行中
 */
export async function runTrivyImageScan(imageName: string): Promise<ScanResult> {
  const scannerName = "trivy-image"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Trivy not found"], scannerName }
  }

  // 防止误传文件路径
  if (/^[./\\]|[A-Z]:\\/i.test(imageName)) {
    return {
      vulnerabilities: [], totalChecks: 0,
      errors: [`trivy-image 需要镜像名称（如 node:18），收到: ${imageName}`],
      scannerName,
    }
  }

  try {
    const trivyCacheDir = join(process.cwd(), ".trivy-cache")
    if (!existsSync(trivyCacheDir)) {
      try { mkdirSync(trivyCacheDir, { recursive: true }) } catch { /* ignore */ }
    }

    const { stdout: output } = await execAsync(
      `"${TRIVY_PATH}" image --format=json --quiet --scanners vuln,license --cache-dir "${trivyCacheDir}" "${imageName}"`,
      {
        timeout: 600000,
        maxBuffer: 50 * 1024 * 1024,
        env: { ...process.env, TRIVY_DB_REPOSITORY: "ghcr.io/aquasecurity/trivy-db" },
      },
    )

    const result = parseTrivyOutput(output, scannerName)
    if (result) return result
    return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
  } catch (err: unknown) {
    if (err instanceof Error && "stdout" in err) {
      const stdout = (err as { stdout: string }).stdout?.toString().trim()
      if (stdout) {
        const result = parseTrivyOutput(stdout, scannerName)
        if (result) return result
      }
    }
    return {
      vulnerabilities: [], totalChecks: 0,
      errors: [`Trivy image scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
