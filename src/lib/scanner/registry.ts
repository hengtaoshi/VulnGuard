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
import { runCveCppScan } from "./cve-cpp-scanner"
import { runSwiftScan } from "./swift-scanner"
import { runTrufflehogScan } from "./trufflehog-scanner"
import { runScorecardScan } from "./scorecard-scanner"
import { runOsvScan } from "./osv-scanner"
import { runDependencyCheckScan } from "./dependency-check"
import { runCodeqlScan } from "./codeql-scanner"

const TOOLS_BIN = join(process.cwd(), "tools", "bin")
const { existsSync } = require("fs") as typeof import("fs")

/** Quick binary check — file existence + optional PATH fallback via `where` */
function binExists(name: string, exeName?: string): boolean {
  if (existsSync(join(TOOLS_BIN, exeName || name))) return true
  // Only try PATH fallback if tools/bin exists (avoids 2s where timeout in production)
  if (!existsSync(TOOLS_BIN)) return false
  try {
    execSync(`where ${name}`, { stdio: "pipe", timeout: 2000 })
    return true
  } catch {
    return false
  }
}

const scanners: Scanner[] = [
  {
    name: "semgrep",
    displayName: "Semgrep",
    category: "sast",
    isAvailable: () => binExists("semgrep", "semgrep.exe"),
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
    isAvailable: () => binExists("gitleaks", "gitleaks.exe"),
    scan: runGitleaksScan,
  },
  {
    name: "bandit",
    displayName: "Bandit",
    category: "sast",
    isAvailable: () => binExists("bandit"),
    scan: runBanditScan,
  },
  {
    name: "npm-audit",
    displayName: "npm audit",
    category: "dependency",
    isAvailable: () => binExists("npm"),
    scan: runNpmAuditScan,
  },
  {
    name: "pip-audit",
    displayName: "pip-audit",
    category: "dependency",
    isAvailable: () => binExists("pip-audit"),
    scan: runPipAuditScan,
  },
  {
    name: "checkov",
    displayName: "Checkov",
    category: "filesystem",
    isAvailable: () => binExists("checkov"),
    scan: runCheckovScan,
  },
  {
    name: "trivy",
    displayName: "Trivy",
    category: "filesystem",
    isAvailable: () => binExists("trivy", "trivy.exe"),
    scan: runTrivyScan,
  },
  {
    name: "nuclei",
    displayName: "Nuclei",
    category: "filesystem",
    isAvailable: () => binExists("nuclei", "nuclei.exe"),
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
    name: "trufflehog",
    displayName: "TruffleHog",
    category: "secret",
    isAvailable: () => existsSync(join(TOOLS_BIN, "trufflehog.exe")),
    scan: (targetPath: string) => runTrufflehogScan(targetPath),
  },
  {
    name: "scorecard",
    displayName: "OpenSSF Scorecard",
    category: "sast",
    isAvailable: () => existsSync(join(TOOLS_BIN, "scorecard.exe")),
    scan: (targetPath: string) => runScorecardScan(targetPath),
  },
  {
    name: "osv-scanner",
    displayName: "OSV-Scanner",
    category: "dependency",
    isAvailable: () => existsSync(join(TOOLS_BIN, "osv-scanner.exe")),
    scan: (targetPath: string) => runOsvScan(targetPath),
  },
  {
    name: "dependency-check",
    displayName: "Dependency-Check",
    category: "dependency",
    isAvailable: () => {
      const TOOLS = join(process.cwd(), "tools", "bin")
      if (existsSync(join(TOOLS, "dependency-check.bat"))) return true
      if (existsSync(join(TOOLS, "dependency-check.sh"))) return true
      if (existsSync(join(process.cwd(), "tools", "dependency-check", "bin", "dependency-check.bat"))) return true
      return binExists("dependency-check")
    },
    scan: (targetPath: string) => runDependencyCheckScan(targetPath),
  },
  {
    name: "codeql",
    displayName: "CodeQL",
    category: "sast",
    isAvailable: () => {
      if (existsSync(join(process.cwd(), "tools", "bin", "codeql", "codeql", "codeql.exe"))) return true
      return binExists("codeql")
    },
    scan: (targetPath: string) => runCodeqlScan(targetPath),
  },
]

export function getAvailableScanners(): Scanner[] {
  return scanners.filter(s => s.isAvailable())
}

export function getAllScanners(): Scanner[] {
  return scanners
}
