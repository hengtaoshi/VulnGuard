import { execSync } from "child_process"
import { join } from "path"
import type { Scanner } from "./types"

// Source-mode scanners
import { runSemgrepScan } from "./semgrep"
import { runGitleaksScan } from "./gitleaks"
import { runNpmAuditScan } from "./npm-audit"
import { runPipAuditScan } from "./pip-audit"
import { runTrivyScan } from "./trivy"
import { runBanditScan } from "./bandit"
import { runCheckovScan } from "./checkov"
import { runNucleiScan } from "./nuclei"
import { runAIScan } from "./ai-scanner"
import { runCveCppScan } from "./cve-cpp-scanner"
import { runSwiftScan } from "./swift-scanner"
import { runTrufflehogScan } from "./trufflehog-scanner"
import { runBearerScan } from "./bearer-scanner"
import { runScorecardScan } from "./scorecard-scanner"
import { runOsvScan } from "./osv-scanner"

const TOOLS_BIN = join(process.cwd(), "tools", "bin")

/** Try to resolve a command path — check tools/bin first, then fall back to PATH */
function resolveBin(name: string, exeName?: string): string | null {
  const localPath = join(TOOLS_BIN, exeName || name)
  try {
    const { execSync } = require("child_process") as typeof import("child_process")
    execSync(`"${localPath}" --version 2>&1`, { stdio: "pipe", timeout: 5000 })
    return localPath
  } catch {
    // Fallback: check PATH
    try {
      execSync(`${name} --version 2>&1`, { stdio: "pipe", timeout: 5000 })
      return name
    } catch {
      return null
    }
  }
}

const scanners: Scanner[] = [
  {
    name: "semgrep",
    displayName: "Semgrep",
    category: "sast",
    isAvailable: () => resolveBin("semgrep", "semgrep.exe") !== null,
    scan: (targetPath: string) => runSemgrepScan(targetPath).then(r => ({
      ...r,
      errors: [],
      scannerName: "semgrep",
    })),
  },
  {
    name: "gitleaks",
    displayName: "Gitleaks",
    category: "secret",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "gitleaks.exe")}" version`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runGitleaksScan,
  },
  {
    name: "bandit",
    displayName: "Bandit",
    category: "sast",
    isAvailable: () => {
      try { execSync("bandit --version", { stdio: "pipe", timeout: 5000 }); return true }
      catch { return false }
    },
    scan: runBanditScan,
  },
  {
    name: "npm-audit",
    displayName: "npm audit",
    category: "dependency",
    isAvailable: () => {
      try { execSync("npm --version", { stdio: "pipe", timeout: 5000 }); return true }
      catch { return false }
    },
    scan: runNpmAuditScan,
  },
  {
    name: "pip-audit",
    displayName: "pip-audit",
    category: "dependency",
    isAvailable: () => {
      try { execSync("pip-audit --version", { stdio: "pipe", timeout: 5000 }); return true }
      catch { return false }
    },
    scan: runPipAuditScan,
  },
  {
    name: "checkov",
    displayName: "Checkov",
    category: "filesystem",
    isAvailable: () => {
      try { execSync("checkov --version", { stdio: "pipe", timeout: 5000 }); return true }
      catch { return false }
    },
    scan: runCheckovScan,
  },
  {
    name: "trivy",
    displayName: "Trivy",
    category: "filesystem",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "trivy.exe")}" --version`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runTrivyScan,
  },
  {
    name: "nuclei",
    displayName: "Nuclei",
    category: "filesystem",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "nuclei.exe")}" -version`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runNucleiScan,
  },
  {
    name: "cve-cpp",
    displayName: "C/C++ CVE Scanner",
    category: "dependency",
    isAvailable: () => true,
    scan: (targetPath: string) => runCveCppScan(targetPath),
  },
  {
    name: "swift",
    displayName: "Swift Package Scanner",
    category: "dependency",
    isAvailable: () => true,
    scan: (targetPath: string) => runSwiftScan(targetPath),
  },
  {
    name: "ai-scanner",
    displayName: "AI Scanner",
    category: "ai",
    isAvailable: () => {
      return !!process.env.DEEPSEEK_API_KEY
    },
    scan: (targetPath: string) => runAIScan(targetPath),
  },
  {
    name: "trufflehog",
    displayName: "TruffleHog",
    category: "secret",
    isAvailable: () => {
      const { existsSync } = require("fs") as typeof import("fs")
      return existsSync(join(TOOLS_BIN, "trufflehog.exe"))
    },
    scan: (targetPath: string) => runTrufflehogScan(targetPath),
  },
  {
    name: "bearer",
    displayName: "Bearer",
    category: "sast",
    isAvailable: () => {
      // Bearer 没有 Windows 版本，只在 Linux/macOS 生效
      return process.platform !== "win32"
    },
    scan: (targetPath: string) => runBearerScan(targetPath),
  },
  {
    name: "scorecard",
    displayName: "OpenSSF Scorecard",
    category: "sast",
    isAvailable: () => {
      const { existsSync } = require("fs") as typeof import("fs")
      return existsSync(join(TOOLS_BIN, "scorecard.exe"))
    },
    scan: (targetPath: string) => runScorecardScan(targetPath),
  },
  {
    name: "osv-scanner",
    displayName: "OSV-Scanner",
    category: "dependency",
    isAvailable: () => {
      const { existsSync } = require("fs") as typeof import("fs")
      return existsSync(join(TOOLS_BIN, "osv-scanner.exe"))
    },
    scan: (targetPath: string) => runOsvScan(targetPath),
  },
]

export function getAvailableScanners(): Scanner[] {
  return scanners.filter(s => s.isAvailable())
}

export function getAllScanners(): Scanner[] {
  return scanners
}
