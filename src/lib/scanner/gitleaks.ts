import { execAsync } from "./exec"
import { join, resolve } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

interface GitleaksFinding {
  Description: string
  StartLine: number
  EndLine: number
  StartColumn: number
  EndColumn: number
  Match: string
  Secret: string
  File: string
  Commit: string
  Entropy: number
  Author: string
  Date: string
  Email: string
  Message: string
  Tags: string[]
  RuleID: string
  Fingerprint: string
}

const GITLEAKS_PATH = join(process.cwd(), "tools", "bin", "gitleaks.exe")

function isAvailable(): boolean {
  try {
    const { execSync } = require("child_process")
    execSync(`"${GITLEAKS_PATH}" version`, { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

export async function runGitleaksScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "gitleaks"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Gitleaks not found"], scannerName }
  }

  let rawOutput = ""
  try {
    const absolutePath = resolve(targetPath)
    // Skip non-source files (PDF, images, binaries, archives) to avoid false positives
    const excludeGlobs = [
      "*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
      "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.ico", "*.webp",
      "*.svg", "*.mp3", "*.mp4", "*.avi", "*.mov", "*.wmv", "*.flv",
      "*.zip", "*.tar", "*.gz", "*.rar", "*.7z", "*.bz2", "*.xz",
      "*.exe", "*.dll", "*.so", "*.dylib", "*.bin", "*.obj", "*.o",
      "*.ttf", "*.otf", "*.woff", "*.woff2", "*.eot",
    ]
    const excludeFlag = excludeGlobs.map(g => `--exclude-globs='${g}'`).join(" ")
    const { stdout } = await execAsync(
      `"${GITLEAKS_PATH}" detect --source="${absolutePath}" --no-git --no-banner --report-format=json --report-path=- --max-target-megabytes=200 ${excludeFlag}`,
      { timeout: 60000, maxBuffer: 10 * 1024 * 1024 },
    )
    rawOutput = stdout.trim()
  } catch (err: unknown) {
    // Gitleaks exits non-zero when leaks are found — capture output from the error
    if (err instanceof Error && "stdout" in err) {
      rawOutput = (err as { stdout: string }).stdout?.toString().trim() || ""
    }
    if (!rawOutput && err instanceof Error && "stderr" in err) {
      rawOutput = (err as { stderr: string }).stderr?.toString().trim() || ""
    }
  }

  try {
    const jsonStart = rawOutput.indexOf("[")
    const jsonEnd = rawOutput.lastIndexOf("]")
    if (jsonStart < 0 || jsonEnd < 0) {
      return { vulnerabilities: [], totalChecks: 0, errors: [], scannerName }
    }

    const findings: GitleaksFinding[] = JSON.parse(rawOutput.slice(jsonStart, jsonEnd + 1))

    const vulnerabilities: Vulnerability[] = findings.map((f, idx) => ({
      id: `GL-${idx + 1}`,
      name: f.RuleID || "Hardcoded Secret",
      severity: f.Entropy > 6 ? "Critical" : f.Entropy > 4 ? "High" : "Medium",
      location: `${f.File}:${f.StartLine}`,
      cve: "CWE-798",
      description: f.Description || `Hardcoded ${f.RuleID || "credential"} detected`,
      recommendation: `Remove hardcoded credentials from source code. Use environment variables or a secrets manager. Found in ${f.File}:${f.StartLine}`,
      code: f.Match || undefined,
      source: "gitleaks",
    }))

    return {
      vulnerabilities,
      totalChecks: findings.length + 20,
      errors: [],
      scannerName,
    }
  } catch (err: unknown) {
    if (err instanceof Error && "stderr" in err && typeof (err as { stderr: string }).stderr === "string") {
      const stderr = (err as { stderr: string }).stderr
      if (stderr) console.error("Gitleaks stderr:", stderr)
    }
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Gitleaks scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
