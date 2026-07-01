import { execSync } from "child_process"
import { join } from "path"
import type { Scanner } from "./types"
import { TOOLS_BIN, TOOLS_DIR } from "./paths"

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

import { runCodeqlScan } from "./codeql-scanner"

const { existsSync } = require("fs") as typeof import("fs")

/** 存档标记文件，v0.6.6+ 的扫描器统一通过单个归档下载后标记 */
const ARCHIVE_MARKER = join(TOOLS_DIR, ".archive-extracted")

function archiveExtracted(): boolean {
  return existsSync(ARCHIVE_MARKER)
}

/** 归档中包含的扫描器名称集合 */
const BUNDLED_SCANNERS = new Set([
  "semgrep", "gitleaks", "bandit", "pip-audit", "checkov",
  "trivy", "nuclei", "trufflehog", "osv-scanner", "scorecard",
  "codeql",
])

/** Quick binary check — file existence + optional PATH fallback via `where` */
function binExists(name: string, exeName?: string): boolean {
  if (BUNDLED_SCANNERS.has(name) && !archiveExtracted()) return false
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
    isAvailable: () => binExists("bandit", "bandit.exe"),
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
    isAvailable: () => binExists("pip-audit", "pip-audit.exe"),
    scan: runPipAuditScan,
  },
  {
    name: "checkov",
    displayName: "Checkov",
    category: "filesystem",
    isAvailable: () => binExists("checkov", "checkov.exe"),
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
    isAvailable: () => archiveExtracted() && existsSync(join(TOOLS_BIN, "trufflehog.exe")),
    scan: (targetPath: string) => runTrufflehogScan(targetPath),
  },
  {
    name: "scorecard",
    displayName: "OpenSSF Scorecard",
    category: "sast",
    isAvailable: () => archiveExtracted() && existsSync(join(TOOLS_BIN, "scorecard.exe")),
    scan: (targetPath: string) => runScorecardScan(targetPath),
  },
  {
    name: "osv-scanner",
    displayName: "OSV-Scanner",
    category: "dependency",
    isAvailable: () => archiveExtracted() && existsSync(join(TOOLS_BIN, "osv-scanner.exe")),
    scan: (targetPath: string) => runOsvScan(targetPath),
  },
  {
    name: "codeql",
    displayName: "CodeQL",
    category: "sast",
    isAvailable: () => {
      if (!archiveExtracted()) return false
      if (existsSync(join(TOOLS_DIR, "codeql", "codeql", "codeql.exe"))) return true
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
