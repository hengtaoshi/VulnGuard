#!/usr/bin/env node

/**
 * VulnGuard Scanner Installer
 * Run: node scripts/install-scanners.js
 * 
 * Downloads and installs all scanner dependencies:
 * - Python packages: semgrep, bandit, checkov, pip-audit
 * - Go binaries: gitleaks, trivy, nuclei (to tools/bin/)
 * - Checks: Java (for Dependency-Check)
 * - Sets up: nuclei templates
 */

const { execSync } = require("child_process")
const { existsSync, mkdirSync, writeFileSync, createWriteStream } = require("fs")
const { join } = require("path")
const https = require("https")
const http = require("http")
const { platform, arch } = require("os")

const IS_WIN = platform() === "win32"
const BIN_DIR = join(__dirname, "..", "tools", "bin")
const PROXY = process.env.HTTPS_PROXY || process.env.HTTP_PROXY || ""

const COLORS = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
}

function log(label, msg, ok = true) {
  const tag = ok ? `${COLORS.green}✓${COLORS.reset}` : `${COLORS.red}✗${COLORS.reset}`
  console.log(`  ${tag} ${COLORS.cyan}${label.padEnd(18)}${COLORS.reset} ${msg}`)
}

function warn(msg) {
  console.log(`  ${COLORS.yellow}⚠${COLORS.reset} ${msg}`)
}

function fail(label, msg) {
  log(label, msg, false)
}

function exec(cmd, opts = {}) {
  try {
    return execSync(cmd, { stdio: "pipe", timeout: 120000, encoding: "utf-8", ...opts }).trim()
  } catch {
    return null
  }
}

// ─── Download helpers ──────────────────────────────────────────────────────

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = createWriteStream(dest)
    const agent = PROXY ? new http.Agent({ host: new URL(PROXY).hostname, port: parseInt(new URL(PROXY).port) }) : undefined

    https.get(url, { agent }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        file.close()
        download(res.headers.location, dest).then(resolve).catch(reject)
        return
      }
      if (res.statusCode !== 200) {
        file.close()
        reject(new Error(`HTTP ${res.statusCode}`))
        return
      }
      res.pipe(file)
      file.on("finish", () => { file.close(); resolve() })
    }).on("error", (err) => { file.close(); reject(err) })
  })
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n  ${COLORS.cyan}═══════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}  VulnGuard Scanner Installer${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}═══════════════════════════════════════${COLORS.reset}\n`)

  // Ensure bin directory
  if (!existsSync(BIN_DIR)) mkdirSync(BIN_DIR, { recursive: true })

  // ── 1. Python packages ──────────────────────────────────────────────────
  console.log(`  ${COLORS.cyan}[1/4]${COLORS.reset} Python packages\n`)
  const pip = IS_WIN ? "pip" : "pip3"
  const pyPkgs = ["semgrep", "bandit", "checkov", "pip-audit"]
  for (const pkg of pyPkgs) {
    const ok = exec(`${pip} show ${pkg} >nul 2>&1`) !== null
    if (ok) {
      log(pkg, "already installed")
    } else {
      try {
        exec(`${pip} install ${pkg} 2>&1`, { timeout: 300000 })
        log(pkg, "installed")
      } catch {
        fail(pkg, "install failed (try: pip install " + pkg + ")")
      }
    }
  }

  // ── 2. Download Go binaries ─────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[2/4]${COLORS.reset} Scanner binaries → tools/bin/\n`)

  const binaries = [
    {
      name: "Gitleaks",
      file: IS_WIN ? "gitleaks.exe" : "gitleaks",
      url: IS_WIN
        ? "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_win_x64.exe"
        : "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz",
      extract: !IS_WIN,
    },
    {
      name: "Trivy",
      file: IS_WIN ? "trivy.exe" : "trivy",
      url: IS_WIN
        ? "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Windows-64bit.exe"
        : "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Linux-64bit.tar.gz",
      extract: !IS_WIN,
    },
    {
      name: "Nuclei",
      file: IS_WIN ? "nuclei.exe" : "nuclei",
      url: IS_WIN
        ? "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_windows_amd64.zip"
        : "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_linux_amd64.zip",
      extract: true,
    },
  ]

  for (const bin of binaries) {
    const dest = join(BIN_DIR, bin.file)
    if (existsSync(dest)) {
      log(bin.name, "already in tools/bin/")
      continue
    }

    try {
      if (bin.extract) {
        // Download ZIP/tar and extract
        const tmp = join(BIN_DIR, bin.file + ".download")
        log(bin.name, `downloading...`)

        // For zip/tar, we need to download then extract
        const zipDest = join(BIN_DIR, bin.name.toLowerCase() + ".zip")
        await download(bin.url, zipDest)

        if (IS_WIN) {
          // Windows: use tar to extract from zip (built-in since Win10)
          execSync(`tar -xf "${zipDest}" -C "${BIN_DIR}" ${bin.file} 2>nul`, { stdio: "pipe", timeout: 30000 })
        } else {
          execSync(`tar -xzf "${zipDest}" -C "${BIN_DIR}" ${bin.file} 2>nul`, { stdio: "pipe", timeout: 30000 })
        }

        if (existsSync(zipDest)) execSync(`"${IS_WIN ? 'del' : 'rm'}" "${zipDest}"`)
      } else {
        await download(bin.url, dest)
      }

      if (existsSync(dest)) {
        // Make executable on Unix
        if (!IS_WIN) execSync(`chmod +x "${dest}"`)
        log(bin.name, `installed (${(await getSize(dest)).toFixed(1)} MB)`)
      } else {
        fail(bin.name, "download failed")
      }
    } catch (err) {
      fail(bin.name, `download failed: ${err.message}`)
    }
  }

  // ── 3. Nuclei templates ────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[3/4]${COLORS.reset} Nuclei templates\n`)
  const nucleiBin = join(BIN_DIR, IS_WIN ? "nuclei.exe" : "nuclei")
  if (existsSync(nucleiBin)) {
    try {
      execSync(`"${nucleiBin}" -update-templates 2>&1`, { stdio: "pipe", timeout: 120000 })
      log("Templates", "downloaded")
    } catch {
      warn("Nuclei template download failed — will retry on first scan")
    }
  } else {
    warn("Nuclei not installed, skip template download")
  }

  // ── 4. Check Java ─────────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[4/4]${COLORS.reset} Java check (Dependency-Check)\n`)
  const javaVer = exec("java -version 2>&1")
  if (javaVer) {
    const v = javaVer.match(/(\d+\.\d+)/)?.[0] || "?"
    log("Java", `found (${v})`)
    warn("Dependency-Check requires manual download from:\n" +
         "  https://github.com/jeremylong/DependencyCheck/releases")
  } else {
    fail("Java", "not found — Dependency-Check needs Java 11+")
  }

  // ── Summary ──────────────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}═══════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  Setup complete!${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  Start: npm run dev${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  Visit: http://localhost:3000${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}═══════════════════════════════════════${COLORS.reset}\n`)
}

function getSize(p) {
  return new Promise((resolve) => {
    const { stat } = require("fs")
    stat(p, (err, s) => resolve(err ? 0 : s.size / 1024 / 1024))
  })
}

main().catch((err) => {
  console.error("Setup failed:", err.message)
  process.exit(1)
})
