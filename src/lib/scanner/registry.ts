import { execSync } from "child_process"
import { join } from "path"
import type { Scanner } from "./types"
import { runSemgrepScan } from "./semgrep"
import { runGitleaksScan } from "./gitleaks"
import { runNpmAuditScan } from "./npm-audit"
import { runPipAuditScan } from "./pip-audit"
import { runTrivyScan } from "./trivy"
import { runBanditScan } from "./bandit"
import { runCheckovScan } from "./checkov"
import { runNucleiScan } from "./nuclei"
import { runWapitiScan } from "./wapiti"
import { runSqlmapScan } from "./sqlmap"

const CWD = process.cwd()

const scanners: Scanner[] = [
  {
    name: "semgrep",
    displayName: "Semgrep",
    category: "sast",
    isAvailable: () => true,
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
        execSync(`"${join(CWD, "tools", "bin", "gitleaks.exe")}" version`, { stdio: "pipe", timeout: 5000 })
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
      try { execSync("checkov --version", { stdio: "pipe", timeout: 30000 }); return true }
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
        execSync(`"${join(CWD, "tools", "bin", "trivy.exe")}" --version`, { stdio: "pipe", timeout: 5000 })
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
        execSync(`"${join(CWD, "tools", "bin", "nuclei.exe")}" -version`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runNucleiScan,
  },
  {
    name: "wapiti",
    displayName: "Wapiti",
    category: "filesystem",
    isAvailable: () => {
      try {
        execSync("wapiti --version", { stdio: "pipe", timeout: 10000 })
        return true
      } catch {
        return false
      }
    },
    scan: (targetPath: string) => runWapitiScan(targetPath),
  },
  {
    name: "sqlmap",
    displayName: "SQLMap",
    category: "filesystem",
    isAvailable: () => {
      try {
        execSync("sqlmap --version", { stdio: "pipe", timeout: 10000 })
        return true
      } catch {
        return false
      }
    },
    scan: (targetPath: string) => runSqlmapScan(targetPath),
  },
]

export function getAvailableScanners(): Scanner[] {
  return scanners.filter(s => s.isAvailable())
}

export function getAllScanners(): Scanner[] {
  return scanners
}
