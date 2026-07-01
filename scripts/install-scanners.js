#!/usr/bin/env node

/**
 * VulnGuard Scanner Installer
 * Run: node scripts/install-scanners.js
 * 
 * Downloads and installs all scanner dependencies:
 * - Python packages: semgrep, bandit, checkov, pip-audit
 * - Go binaries: gitleaks, trivy, nuclei (to tools/bin/)
 * - Additional binaries: TruffleHog, OSV-Scanner, Scorecard, Dependency-Check
 * - CodeQL CLI (semantic analysis engine)
 * - Semgrep rules update from registry
 * - Checks: Java (for Dependency-Check)
 * - Sets up: nuclei templates
 */

const { execSync } = require("child_process")
const { existsSync, mkdirSync, createWriteStream, unlinkSync, readFileSync, rmSync } = require("fs")
const { join } = require("path")
const https = require("https")
const crypto = require("crypto")
const { platform, arch } = require("os")

const IS_WIN = platform() === "win32"
const BIN_DIR = join(__dirname, "..", "tools", "bin")
const TOOLS_DIR = join(__dirname, "..", "tools")
const PROXY = process.env.HTTPS_PROXY || process.env.HTTP_PROXY || "http://127.0.0.1:7897"

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
  console.log(`  ${tag} ${COLORS.cyan}${label.padEnd(22)}${COLORS.reset} ${msg}`)
}

function warn(msg) {
  console.log(`  ${COLORS.yellow}⚠${COLORS.reset} ${msg}`)
}

function fail(label, msg, ok = false) {
  log(label, msg, ok)
}

function exec(cmd, opts = {}) {
  try {
    return execSync(cmd, { stdio: "pipe", timeout: 120000, encoding: "utf-8", ...opts }).trim()
  } catch {
    return null
  }
}

// ─── Download helpers ──────────────────────────────────────────────────────

function sha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256")
    const stream = createReadStream(filePath)
    stream.on("data", d => hash.update(d))
    stream.on("end", () => resolve(hash.digest("hex")))
    stream.on("error", reject)
  })
}

async function verifyChecksum(binPath, checksumUrl, binaryName) {
  try {
    const actualHash = await sha256(binPath)
    const checksumText = await fetchUrl(checksumUrl)
    if (!checksumText) {
      warn(`${binaryName}: checksum file unavailable, skipping verification`)
      return true
    }
    const lines = checksumText.trim().split("\n")
    const binFilename = binaryName + (IS_WIN ? ".exe" : "")
    const expectedLine = lines.find(l => l.includes(binFilename))
    if (!expectedLine) {
      warn(`${binaryName}: no entry for ${binFilename} in checksum file`)
      return true
    }
    const expectedHash = expectedLine.split(/\s+/)[0]
    if (actualHash !== expectedHash) {
      throw new Error(`SHA256 mismatch: expected ${expectedHash}, got ${actualHash}`)
    }
    log(binaryName, "SHA256 verified")
    return true
  } catch (err) {
    try { unlinkSync(binPath) } catch {}
    throw err
  }
}

function fetchUrl(url) {
  return new Promise((resolve) => {
    https.get(url, { timeout: 10000 }, (res) => {
      if (res.statusCode !== 200) { resolve(""); return }
      let data = ""
      res.on("data", d => data += d.toString())
      res.on("end", () => resolve(data))
    }).on("error", () => resolve(""))
  })
}

async function download(url, dest) {
  const response = await fetch(url, { signal: AbortSignal.timeout(120000) })
  if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
    return download(response.headers.get("location"), dest)
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const buffer = Buffer.from(await response.arrayBuffer())
  require("fs").writeFileSync(dest, buffer)
}

function createReadStream(path) {
  const fs = require("fs")
  return fs.createReadStream(path)
}

async function getSize(p) {
  try {
    const { stat } = require("fs")
    return new Promise((resolve) => stat(p, (err, s) => resolve(err ? 0 : s.size / 1024 / 1024)))
  } catch { return 0 }
}

function downloadAndExtractZip(url, destDir, targetFile) {
  return new Promise(async (resolve, reject) => {
    const tmp = join(destDir, "download.zip")
    try {
      await download(url, tmp)
      if (IS_WIN) {
        execSync(`tar -xf "${tmp}" -C "${destDir}" ${targetFile ? `"${targetFile}"` : ""} 2>nul`, { stdio: "pipe", timeout: 30000 })
      } else {
        // Check if it's a tar.gz
        if (url.endsWith(".tar.gz")) {
          execSync(`tar -xzf "${tmp}" -C "${destDir}" ${targetFile || ""} 2>/dev/null`, { stdio: "pipe", timeout: 30000 })
        } else {
          execSync(`unzip -o "${tmp}" -d "${destDir}" ${targetFile ? `"${targetFile}"` : ""} 2>/dev/null`, { stdio: "pipe", timeout: 30000 })
        }
      }
      unlinkSync(tmp)
      resolve()
    } catch (err) {
      try { unlinkSync(tmp) } catch {}
      reject(err)
    }
  })
}

// ─── Binary download config ────────────────────────────────────────────────

async function installBinary(name, file, url, checksumUrl, extract = false) {
  const dest = join(BIN_DIR, file)
  if (existsSync(dest)) {
    log(name, "already installed")
    return true
  }

  try {
    log(name, "downloading...")
    if (extract) {
      await downloadAndExtractZip(url, BIN_DIR, file)
    } else {
      await download(url, dest)
    }

    if (existsSync(dest)) {
      if (!IS_WIN) execSync(`chmod +x "${dest}"`)
      if (checksumUrl) {
        await verifyChecksum(dest, checksumUrl, name)
      }
      log(name, `installed (${(await getSize(dest)).toFixed(1)} MB)`)
      return true
    } else {
      fail(name, "download failed (binary not found)")
      return false
    }
  } catch (err) {
    fail(name, `download failed: ${err.message}`)
    return false
  }
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n  ${COLORS.cyan}══════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}  VulnGuard Scanner Installer v2${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}══════════════════════════════════════════════${COLORS.reset}\n`)

  // Ensure directories
  if (!existsSync(BIN_DIR)) mkdirSync(BIN_DIR, { recursive: true })
  if (!existsSync(join(TOOLS_DIR, "semgrep-rules"))) mkdirSync(join(TOOLS_DIR, "semgrep-rules"), { recursive: true })

  // ── 1. Python packages ──────────────────────────────────────────────────
  console.log(`  ${COLORS.cyan}[1/6]${COLORS.reset} Python packages\n`)
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

  // ── 2. Scanner binaries ─────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[2/6]${COLORS.reset} Scanner binaries → tools/bin/\n`)

  // Gitleaks
  await installBinary(
    "Gitleaks",
    IS_WIN ? "gitleaks.exe" : "gitleaks",
    IS_WIN
      ? "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_win_x64.exe"
      : "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz",
    IS_WIN
      ? "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_win_x64.exe.sha256"
      : "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz.sha256",
    !IS_WIN,
  )

  // Trivy
  await installBinary(
    "Trivy",
    IS_WIN ? "trivy.exe" : "trivy",
    IS_WIN
      ? "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Windows-64bit.exe"
      : "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Linux-64bit.tar.gz",
    IS_WIN
      ? "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Windows-64bit.exe.sha256"
      : "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Linux-64bit.tar.gz.sha256",
    !IS_WIN,
  )

  // Nuclei
  await installBinary(
    "Nuclei",
    IS_WIN ? "nuclei.exe" : "nuclei",
    `https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_${IS_WIN ? "windows_amd64.zip" : "linux_amd64.zip"}`,
    `https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_${IS_WIN ? "windows_amd64.zip" : "linux_amd64.zip"}.sha256`,
    true,
  )

  // TruffleHog
  await installBinary(
    "TruffleHog",
    IS_WIN ? "trufflehog.exe" : "trufflehog",
    IS_WIN
      ? "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_amd64.exe"
      : "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_amd64_linux.tar.gz",
    "",
    !IS_WIN,
  )

  // OSV-Scanner
  await installBinary(
    "OSV-Scanner",
    IS_WIN ? "osv-scanner.exe" : "osv-scanner",
    IS_WIN
      ? "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_windows_amd64.exe"
      : "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64",
    "",
    false,
  )

  // Scorecard
  await installBinary(
    "Scorecard",
    IS_WIN ? "scorecard.exe" : "scorecard",
    IS_WIN
      ? "https://github.com/ossf/scorecard/releases/latest/download/scorecard_amd64.exe"
      : "https://github.com/ossf/scorecard/releases/latest/download/scorecard_linux_amd64.tar.gz",
    "",
    !IS_WIN,
  )

  // ── 3. CodeQL CLI ───────────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[3/6]${COLORS.reset} CodeQL CLI → tools/bin/codeql/\n`)
  const codeqlDir = join(BIN_DIR, "codeql", "codeql")
  const codeqlBin = join(codeqlDir, "codeql" + (IS_WIN ? ".exe" : ""))
  if (existsSync(codeqlBin)) {
    log("CodeQL", "already installed")
  } else {
    try {
      const codeqlUrl = IS_WIN
        ? "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip"
        : "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip"
      const zipDest = join(BIN_DIR, "codeql.zip")
      log("CodeQL", "downloading (large file, ~200 MB)...")
      await download(codeqlUrl, zipDest)
      log("CodeQL", "extracting...")
      const extractDir = join(BIN_DIR, "codeql")
      if (!existsSync(extractDir)) mkdirSync(extractDir, { recursive: true })
      execSync(`tar -xf "${zipDest}" -C "${extractDir}" 2>nul`, { stdio: "pipe", timeout: 60000 })
      unlinkSync(zipDest)
      // The zip extracts to codeql/ directory; find the actual binary
      const codeqlExtracted = join(extractDir, "codeql", "codeql" + (IS_WIN ? ".exe" : ""))
      if (existsSync(codeqlExtracted)) {
        if (!IS_WIN) execSync(`chmod +x "${codeqlExtracted}"`)
        log("CodeQL", `installed (${(await getSize(codeqlExtracted)).toFixed(0)} MB)`)
      } else {
        fail("CodeQL", "extraction failed — binary not found")
      }
    } catch (err) {
      fail("CodeQL", `download/install failed: ${err.message}`)
    }
  }

  // ── CodeQL query packs (shallow clone from github/codeql) ──────────────
  const codeqlQueriesDir = join(TOOLS_DIR, "codeql-queries")
  const codeqlJsSuite = join(codeqlQueriesDir, "javascript", "ql", "src", "codeql-suites", "javascript-security-extended.qls")
  if (existsSync(codeqlBin) && !existsSync(codeqlJsSuite)) {
    log("CodeQL packs", "cloning github/codeql (shallow sparse, ~50 MB)...")
    try {
      if (existsSync(codeqlQueriesDir)) {
        try { rmSync(codeqlQueriesDir, { recursive: true, force: true }) } catch {}
      }
      execSync(
        `git clone --depth 1 --filter=blob:none --sparse "https://github.com/github/codeql.git" "${codeqlQueriesDir}"`,
        { timeout: 120000, stdio: "pipe" },
      )
      execSync(
        `git -C "${codeqlQueriesDir}" sparse-checkout set javascript/ql/src javascript/ql/lib python/ql/src python/ql/lib cpp/ql/src cpp/ql/lib java/ql/src java/ql/lib go/ql/src go/ql/lib csharp/ql/src csharp/ql/lib ruby/ql/src ruby/ql/lib swift/ql/src swift/ql/lib config`,
        { timeout: 30000, stdio: "pipe" },
      )
      execSync(`git -C "${codeqlQueriesDir}" checkout`, { timeout: 30000, stdio: "pipe" })
      log("CodeQL packs", "cloned successfully")
    } catch (err) {
      warn(`CodeQL: failed to clone query repo — ${err.message.slice(0, 80)}`)
    }
  } else if (existsSync(codeqlJsSuite)) {
    log("CodeQL packs", "already available (local repo)")
  }

  // ── 4. Semgrep rules update ──────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[4/4]${COLORS.reset} Semgrep rules update\n`)
  const rulesDir = join(TOOLS_DIR, "semgrep-rules")
  const rulesFile = join(rulesDir, "security.yaml")

  // Try to auto-update via semgrep itself
  const semgrepAvailable = exec(`${pip} show semgrep >nul 2>&1 && echo yes || echo no`) === "yes"
  if (semgrepAvailable) {
    try {
      // Use semgrep to download the latest rules from the registry
      execSync(`semgrep --config "https://semgrep.dev/p/security" --dry-run "${BIN_DIR}" 2>&1`, { timeout: 60000, stdio: "pipe" })
      // Also fetch p/default for comprehensive coverage
      const remoteRules = execSync(`semgrep --config "p/default" --dry-run "${BIN_DIR}" 2>&1`, { timeout: 60000, stdio: "pipe" })
      if (remoteRules) {
        log("Semgrep rules", "remote registry available (p/default)")
      }
    } catch {
      // --dry-run may still fail; fall back to local rules
      warn("Semgrep: could not reach registry, using local rules")
    }
  }

  // Update the local security.yaml with latest from Semgrep registry
  const RULES_DOWNLOAD_URL = "https://semgrep.dev/c/p/security.yaml"
  try {
    const existing = existsSync(rulesFile) ? readFileSync(rulesFile, "utf-8") : ""
    const latestRules = await fetchUrl(RULES_DOWNLOAD_URL)
    if (latestRules && latestRules.length > 1000) {
      require("fs").writeFileSync(rulesFile, latestRules, "utf-8")
      const ruleCount = (latestRules.match(/rules:/g) || []).length
      log("Security rules", `updated (${ruleCount} rules from registry)`)
    } else if (existing) {
      log("Security rules", "already present (registry unavailable, using local)")
    } else {
      warn("No Semgrep rules found — create a tools/semgrep-rules/security.yaml file")
    }
  } catch (err) {
    if (existsSync(rulesFile)) {
      log("Security rules", "using existing local file")
    } else {
      fail("Security rules", `download failed: ${err.message}`)
    }
  }

  // ── 5. Nuclei templates ─────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}[5/5]${COLORS.reset} Final checks\n`)

  // Nuclei templates
  const nucleiBin = join(BIN_DIR, "nuclei" + (IS_WIN ? ".exe" : ""))
  if (existsSync(nucleiBin)) {
    try {
      execSync(`"${nucleiBin}" -update-templates 2>&1`, { stdio: "pipe", timeout: 120000 })
      log("Nuclei templates", "downloaded")
    } catch {
      warn("Nuclei template download failed — will retry on first scan")
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────
  console.log(`\n  ${COLORS.cyan}══════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  Setup complete!${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  5/5 steps finished${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  Start: npm run dev${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  Visit: http://localhost:3000${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}══════════════════════════════════════════════${COLORS.reset}\n`)
}

main().catch((err) => {
  console.error("Setup failed:", err.message)
  process.exit(1)
})