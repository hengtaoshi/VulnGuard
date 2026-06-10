import { execSync } from "child_process"
import { join } from "path"
import type { Scanner } from "./types"

// Source-mode scanners (existing)
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
import { runAIScan } from "./ai-scanner"

// URL-mode CLI scanners (new)
import { runSubfinderScan, runAssetfinderScan, runShufflednsScan, runAmassScan } from "./dns-scanners"
import { runFfufScan, runGobusterScan } from "./web-fuzzers"
import { runHttpxScan, runWafw00fScan } from "./web-probes"
import { runWaybackurlsScan } from "./osint-scanners"
import { runNmapScan } from "./nmap-scan"
import { runGitDumperScan } from "./gitdumper"

// Node.js native URL detection modules (new)
import { runHttpHeadersScan, runCorsScan, runFormScan, runErrorPageScan, runFaviconScan, runThirdPartyScan } from "./http-analyzer"
import { runTlsScan } from "./tls-analyzer"
import { runCrawlerScan } from "./crawler"

const CWD = process.cwd()
const WAPITI_PATH = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\wapiti.exe"
const SQLMAP_PATH = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\sqlmap.exe"
const SEMGREP_PATH = "C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\semgrep.exe"
const TOOLS_BIN = join(CWD, "tools", "bin")

const scanners: Scanner[] = [
  // ── Existing Source-Mode Scanners ─────────────────────────────────────
  {
    name: "semgrep",
    displayName: "Semgrep",
    category: "sast",
    isAvailable: () => {
      try {
        execSync(`"${SEMGREP_PATH}" --version`, { stdio: "pipe", timeout: 10000 })
        return true
      } catch {
        return false
      }
    },
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
    name: "wapiti",
    displayName: "Wapiti",
    category: "filesystem",
    isAvailable: () => {
      try {
        execSync(`"${WAPITI_PATH}" --version`, { stdio: "pipe", timeout: 10000 })
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
        execSync(`"${SQLMAP_PATH}" --version`, { stdio: "pipe", timeout: 10000 })
        return true
      } catch {
        return false
      }
    },
    scan: (targetPath: string) => runSqlmapScan(targetPath),
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

  // ── DNS Reconnaissance (URL mode) ─────────────────────────────────────
  {
    name: "subfinder",
    displayName: "Subfinder",
    category: "dns",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "subfinder.exe")}" --version 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runSubfinderScan,
  },
  {
    name: "assetfinder",
    displayName: "Assetfinder",
    category: "dns",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "assetfinder.exe")}" --help 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runAssetfinderScan,
  },
  {
    name: "shuffledns",
    displayName: "Shuffledns",
    category: "dns",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "shuffledns.exe")}" --version 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runShufflednsScan,
  },
  {
    name: "amass",
    displayName: "Amass",
    category: "dns",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "amass.exe")}" --version 2>&1`, { stdio: "pipe", timeout: 10000 })
        return true
      } catch {
        return false
      }
    },
    scan: runAmassScan,
  },

  // ── Port Scanning (URL mode) ──────────────────────────────────────────
  {
    name: "nmap",
    displayName: "Nmap",
    category: "network",
    isAvailable: () => {
      try {
        execSync("nmap --version", { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runNmapScan,
  },

  // ── Web Fuzzing & Content Discovery (URL mode) ────────────────────────
  {
    name: "ffuf",
    displayName: "Ffuf",
    category: "web",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "ffuf.exe")}" -V 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runFfufScan,
  },
  {
    name: "gobuster",
    displayName: "Gobuster",
    category: "web",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "gobuster.exe")}" --version 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runGobusterScan,
  },
// ── Web Probing & Fingerprinting (URL mode) ───────────────────────────
  {
    name: "httpx",
    displayName: "Httpx",
    category: "web",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "httpx.exe")}" --version 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runHttpxScan,
  },
  {
    name: "wafw00f",
    displayName: "WAFw00f",
    category: "web",
    isAvailable: () => {
      try {
        execSync("wafw00f --version 2>&1", { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        try {
          execSync("C:\\Users\\SHT\\AppData\\Local\\Programs\\Python\\Python312\\Scripts\\wafw00f.exe --version 2>&1", { stdio: "pipe", timeout: 5000 })
          return true
        } catch {
          return false
        }
      }
    },
    scan: runWafw00fScan,
  },

  // ── OSINT & Historical Data (URL mode) ────────────────────────────────
{
    name: "waybackurls",
    displayName: "Waybackurls",
    category: "osint",
    isAvailable: () => {
      try {
        execSync(`"${join(TOOLS_BIN, "waybackurls.exe")}" --help 2>&1`, { stdio: "pipe", timeout: 5000 })
        return true
      } catch {
        return false
      }
    },
    scan: runWaybackurlsScan,
  },

  // ── Sensitive Info Disclosure (URL mode) ──────────────────────────────
  {
    name: "gitdumper",
    displayName: "GitDumper",
    category: "web",
    isAvailable: () => {
      return true  // HTTP-based, always available
    },
    scan: runGitDumperScan,
  },

  // ── Web Crawler (URL mode) ─────────────────────────────────────────────
  {
    name: "crawler",
    displayName: "Website Crawler",
    category: "web",
    isAvailable: () => true,  // fetch-based, always available
    scan: runCrawlerScan,
  },

  // ── Node.js Native HTTP Security Analyzers (URL mode) ─────────────────
  {
    name: "http-headers",
    displayName: "HTTP Security Headers",
    category: "web",
    isAvailable: () => true,  // Always available
    scan: runHttpHeadersScan,
  },
  {
    name: "cors-detector",
    displayName: "CORS Misconfiguration",
    category: "web",
    isAvailable: () => true,
    scan: runCorsScan,
  },
  {
    name: "form-analyzer",
    displayName: "Form Security Analyzer",
    category: "web",
    isAvailable: () => true,
    scan: runFormScan,
  },
  {
    name: "error-analyzer",
    displayName: "Error Page Analyzer",
    category: "web",
    isAvailable: () => true,
    scan: runErrorPageScan,
  },
  {
    name: "favicon-analyzer",
    displayName: "Favicon Analyzer",
    category: "web",
    isAvailable: () => true,
    scan: runFaviconScan,
  },
  {
    name: "third-party-deps",
    displayName: "Third-Party Dependency Check",
    category: "web",
    isAvailable: () => true,
    scan: runThirdPartyScan,
  },

  // ── TLS/SSL Analyzer (URL mode) ──────────────────────────────────────
  {
    name: "tls-analyzer",
    displayName: "TLS/SSL Analyzer",
    category: "network",
    isAvailable: () => true,
    scan: runTlsScan,
  },
]

export function getAvailableScanners(): Scanner[] {
  return scanners.filter(s => s.isAvailable())
}

export function getAllScanners(): Scanner[] {
  return scanners
}
