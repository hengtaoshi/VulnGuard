/**
 * VulnGuard Scanner Downloader
 *
 * Downloads scanner binaries/tools to the user data directory.
 * Supports progress reporting via IPC callbacks.
 */
const https = require("https")
const http = require("http")
const { createWriteStream, existsSync, mkdirSync, unlinkSync } = require("fs")
const { join, extname } = require("path")
const { execSync } = require("child_process")
const { platform } = require("os")

const IS_WIN = platform() === "win32"

// --- Scanner definitions ---------------------------------------------------

const SCANNER_DEFS = {
  gitleaks: {
    label: "Gitleaks",
    type: "binary",
    url: IS_WIN
      ? "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_win_x64.exe"
      : "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64",
    filename: IS_WIN ? "gitleaks.exe" : "gitleaks",
  },
  trivy: {
    label: "Trivy",
    type: "binary",
    url: IS_WIN
      ? "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Windows-64bit.exe"
      : "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.71.0_Linux-64bit.tar.gz",
    filename: IS_WIN ? "trivy.exe" : "trivy",
  },
  nuclei: {
    label: "Nuclei",
    type: "zip",
    url: `https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_${IS_WIN ? "windows_amd64.zip" : "linux_amd64.zip"}`,
    filename: IS_WIN ? "nuclei.exe" : "nuclei",
    extractFilter: (entry) => entry.endsWith("nuclei" + (IS_WIN ? ".exe" : "")),
  },
  trufflehog: {
    label: "TruffleHog",
    type: "binary",
    url: IS_WIN
      ? "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_amd64.exe"
      : "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_amd64_linux",
    filename: IS_WIN ? "trufflehog.exe" : "trufflehog",
  },
  "osv-scanner": {
    label: "OSV-Scanner",
    type: "binary",
    url: IS_WIN
      ? "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_windows_amd64.exe"
      : "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64",
    filename: IS_WIN ? "osv-scanner.exe" : "osv-scanner",
  },
  scorecard: {
    label: "OpenSSF Scorecard",
    type: "binary",
    url: IS_WIN
      ? "https://github.com/ossf/scorecard/releases/latest/download/scorecard_amd64.exe"
      : "https://github.com/ossf/scorecard/releases/latest/download/scorecard_linux_amd64",
    filename: IS_WIN ? "scorecard.exe" : "scorecard",
  },
  semgrep: {
    label: "Semgrep",
    type: "pip",
    pkg: "semgrep",
  },
  bandit: {
    label: "Bandit",
    type: "pip",
    pkg: "bandit",
  },
  checkov: {
    label: "Checkov",
    type: "pip",
    pkg: "checkov",
  },
  "pip-audit": {
    label: "pip-audit",
    type: "pip",
    pkg: "pip-audit",
  },
  "dependency-check": {
    label: "Dependency-Check",
    type: "zip-extract",
    url: IS_WIN
      ? "https://github.com/jeremylong/DependencyCheck/releases/latest/download/dependency-check-12.1.0-release.zip"
      : "https://github.com/jeremylong/DependencyCheck/releases/latest/download/dependency-check-12.1.0-release.tar.gz",
    destDir: "dependency-check",
  },
  codeql: {
    label: "CodeQL",
    type: "zip-extract",
    url: IS_WIN
      ? "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-win64.zip"
      : "https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip",
    destDir: "codeql",
    extractFilter: (entry) => entry.includes("codeql/codeql" + (IS_WIN ? ".exe" : "")),
  },
}

// --- Progress Reporter -----------------------------------------------------

class ProgressReporter {
  constructor(sendProgress) {
    this._send = sendProgress
    this._last = 0
    this._maxPercent = 0 // never decrease
  }

  update(downloaded, total) {
    const pct = total > 0 ? Math.round((downloaded / total) * 100) : 0
    // Only send every ~2% to avoid flooding IPC
    if (Math.abs(pct - this._last) >= 2 || pct === 100) {
      this._maxPercent = Math.max(this._maxPercent, pct)
      this._last = this._maxPercent
      this._send({ percent: this._maxPercent, bytes: downloaded, total })
    }
  }

  done() {
    this._send({ percent: 100, bytes: 0, total: 0, done: true })
  }

  error(msg) {
    this._send({ percent: 0, bytes: 0, total: 0, error: msg })
  }
}

// --- Download helpers ------------------------------------------------------

function downloadFile(url, dest, reporter) {
  return new Promise((resolve, reject) => {
    const proto = url.startsWith("https") ? https : http
    proto.get(url, { timeout: 30000 }, (res) => {
      // Follow redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume()
        return downloadFile(res.headers.location, dest, reporter).then(resolve).catch(reject)
      }
      if (res.statusCode !== 200) {
        res.resume()
        return reject(new Error(`HTTP ${res.statusCode}`))
      }

      const total = parseInt(res.headers["content-length"] || "0", 10)
      let downloaded = 0
      const file = createWriteStream(dest)

      res.on("data", (chunk) => {
        downloaded += chunk.length
        reporter.update(downloaded, total)
      })

      res.pipe(file)
      file.on("finish", () => {
        file.close()
        reporter.done()
        resolve()
      })
      file.on("error", (err) => {
        file.close()
        unlinkSync(dest)
        reject(err)
      })
    }).on("error", reject)
  })
}

function extractZip(zipPath, destDir, filter) {
  return new Promise((resolve, reject) => {
    try {
      if (IS_WIN) {
        // Use tar (Windows 10+ built-in) or PowerShell
        const cmd = `tar -xf "${zipPath}" -C "${destDir}" 2>nul`
        execSync(cmd, { stdio: "pipe", timeout: 60000 })
      } else {
        execSync(`unzip -o "${zipPath}" -d "${destDir}" 2>/dev/null`, { stdio: "pipe", timeout: 60000 })
      }
      unlinkSync(zipPath)
      resolve()
    } catch (err) {
      try { unlinkSync(zipPath) } catch {}
      reject(err)
    }
  })
}

// --- Scanner installers ----------------------------------------------------

async function installBinaryScanner(def, binDir, reporter) {
  const dest = join(binDir, def.filename)
  if (existsSync(dest)) {
    reporter.update(100, 100)
    reporter.done()
    return { ok: true, skipped: true }
  }

  reporter.update(0, 100)
  await downloadFile(def.url, dest + ".download", reporter)
  // Rename after download complete
  try { unlinkSync(dest) } catch {}
  const { renameSync } = require("fs")
  renameSync(dest + ".download", dest)
  if (!IS_WIN) {
    execSync(`chmod +x "${dest}"`, { stdio: "pipe" })
  }
  return { ok: true }
}

async function installPipScanner(def, reporter) {
  const pip = IS_WIN ? "pip" : "pip3"
  // Check if already installed
  try {
    execSync(`${pip} show ${def.pkg} >nul 2>&1`, { stdio: "pipe", timeout: 10000 })
    reporter.update(100, 100)
    reporter.done()
    return { ok: true, skipped: true }
  } catch {} // not installed, proceed

  reporter.update(0, 100)
  // Simulate progress for pip (we can't track pip's real progress)
  const progressInterval = setInterval(() => {
    reporter.update(50, 100)
  }, 2000)

  try {
    execSync(`${pip} install ${def.pkg} 2>&1`, { timeout: 300000, stdio: "pipe" })
    clearInterval(progressInterval)
    reporter.update(100, 100)
    reporter.done()
    return { ok: true }
  } catch (err) {
    clearInterval(progressInterval)
    reporter.error(err.message)
    return { ok: false, error: err.message }
  }
}

async function installZipExtractScanner(def, binDir, reporter) {
  const { join } = require("path")

  if (def.destDir === "dependency-check") {
    const dcDir = join(require("path").dirname(binDir), "dependency-check")
    const dcBat = join(dcDir, "bin", "dependency-check.bat")
    const dcSh = join(dcDir, "bin", "dependency-check.sh")
    if (existsSync(dcBat) || existsSync(dcSh)) {
      reporter.done()
      return { ok: true, skipped: true }
    }
  }

  reporter.update(0, 100)
  const tmp = join(binDir, "download")
  const ext = def.url.endsWith(".zip") ? ".zip" : ".tar.gz"
  await downloadFile(def.url, tmp + ext, reporter)

  reporter.update(90, 100)
  const destDir = join(require("path").dirname(binDir), def.destDir)
  if (!existsSync(destDir)) mkdirSync(destDir, { recursive: true })

  if (ext === ".zip") {
    await extractZip(tmp + ext, destDir, def.extractFilter)
  } else {
    execSync(`tar -xzf "${tmp + ext}" -C "${destDir}" 2>/dev/null`, { stdio: "pipe", timeout: 120000 })
    try { unlinkSync(tmp + ext) } catch {}
  }

  reporter.done()
  return { ok: true }
}

// --- Public API ------------------------------------------------------------

async function installScanner(name, toolsDir, sendProgress) {
  const def = SCANNER_DEFS[name]
  if (!def) return { ok: false, error: `Unknown scanner: ${name}` }

  const reporter = new ProgressReporter(sendProgress)
  const binDir = join(toolsDir, "bin")

  try {
    if (!existsSync(binDir)) mkdirSync(binDir, { recursive: true })

    let result
    switch (def.type) {
      case "binary":
        result = await installBinaryScanner(def, binDir, reporter)
        break
      case "pip":
        result = await installPipScanner(def, reporter)
        break
      case "zip-extract":
        result = await installZipExtractScanner(def, binDir, reporter)
        break
      default:
        result = { ok: false, error: `Unknown type: ${def.type}` }
    }
    return result
  } catch (err) {
    reporter.error(err.message)
    return { ok: false, error: err.message }
  }
}

function getScannerInfo(name) {
  return SCANNER_DEFS[name] || null
}

function getRegisteredScanners() {
  return Object.keys(SCANNER_DEFS)
}

module.exports = { installScanner, getScannerInfo, getRegisteredScanners }
