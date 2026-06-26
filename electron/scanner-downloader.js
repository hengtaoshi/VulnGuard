/**
 * VulnGuard Scanner Downloader
 *
 * Downloads scanner binaries/tools to the user data directory.
 * Supports progress reporting via IPC callbacks and proxy-aware downloads.
 */
const https = require("https")
const http = require("http")
const { createWriteStream, existsSync, mkdirSync, unlinkSync, readFileSync } = require("fs")
const { join, dirname } = require("path")
const { execSync } = require("child_process")
const { platform } = require("os")
const { URL } = require("url")

const IS_WIN = platform() === "win32"

// UserData dir — set by main.js via the APP_DATA_DIR env var fallback
const DATA_DIR = process.env.VULNGUARD_DATA_DIR || ""

// --- Scanner definitions ---------------------------------------------------

const SCANNER_DEFS = {
  gitleaks: {
    label: "Gitleaks",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/gitleaks${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "gitleaks.exe" : "gitleaks",
  },
  trivy: {
    label: "Trivy",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/trivy${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "trivy.exe" : "trivy",
  },
  nuclei: {
    label: "Nuclei",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/nuclei${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "nuclei.exe" : "nuclei",
  },
  trufflehog: {
    label: "TruffleHog",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/trufflehog${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "trufflehog.exe" : "trufflehog",
  },
  "osv-scanner": {
    label: "OSV-Scanner",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/osv-scanner${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "osv-scanner.exe" : "osv-scanner",
  },
  scorecard: {
    label: "OpenSSF Scorecard",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/scorecard${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "scorecard.exe" : "scorecard",
  },
  semgrep: {
    label: "Semgrep",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/semgrep${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "semgrep.exe" : "semgrep",
  },
  bandit: {
    label: "Bandit",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/bandit${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "bandit.exe" : "bandit",
  },
  checkov: {
    label: "Checkov",
    type: "pip",
    pkg: "checkov",
  },
  "pip-audit": {
    label: "pip-audit",
    type: "binary",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/pip-audit${IS_WIN ? ".exe" : ".linux"}`,
    filename: IS_WIN ? "pip-audit.exe" : "pip-audit",
  },
  "dependency-check": {
    label: "Dependency-Check",
    type: "zip-extract",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/dependency-check.zip`,
    destDir: "dependency-check",
  },
  codeql: {
    label: "CodeQL",
    type: "zip-extract",
    url: `https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.0/codeql${IS_WIN ? ".zip" : ".linux.zip"}`,
    destDir: "codeql",
    extractFilter: (entry) => entry.includes("codeql/codeql" + (IS_WIN ? ".exe" : "")),
  },
}

// --- Proxy-aware request ---------------------------------------------------

/**
 * Apply proxy settings from settings.json to environment variables.
 * Reads proxy config from the app's persistent settings file.
 */
function applyProxyFromEnv() {
  if (!DATA_DIR) return
  try {
    const settingsPath = join(DATA_DIR, "settings.json")
    if (!existsSync(settingsPath)) return

    const raw = readFileSync(settingsPath, "utf-8")
    const settings = JSON.parse(raw)

    if (settings.proxyEnabled) {
      if (settings.httpProxy) process.env.HTTP_PROXY = settings.httpProxy
      if (settings.httpsProxy) process.env.HTTPS_PROXY = settings.httpsProxy
    }
  } catch { /* best effort */ }
}

/**
 * Get proxy agent URL from environment for the given target URL.
 * Returns { hostname, port, protocol } or null.
 */
function getProxyForUrl(targetUrl) {
  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy || ""
  const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy || ""

  const proxyUrl = targetUrl.startsWith("https") ? httpsProxy : httpProxy
  if (!proxyUrl) return null

  try {
    const parsed = new URL(proxyUrl)
    return {
      hostname: parsed.hostname,
      port: parseInt(parsed.port, 10) || (parsed.protocol === "https:" ? 443 : 80),
      protocol: parsed.protocol.replace(":", ""),
      auth: parsed.username ? `${parsed.username}:${parsed.password}` : null,
    }
  } catch {
    return null
  }
}

/**
 * Make an HTTP(S) request, optionally through a proxy (CONNECT tunnel).
 * Returns the response object.
 */
function makeRequest(urlStr, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const targetUrl = new URL(urlStr)
    const proxy = getProxyForUrl(urlStr)

    const options = {
      hostname: proxy ? proxy.hostname : targetUrl.hostname,
      port: proxy ? proxy.port : (targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80)),
      timeout,
      headers: {},
    }

    if (proxy) {
      // Tunnel through proxy
      if (targetUrl.protocol === "https:") {
        options.method = "CONNECT"
        options.path = `${targetUrl.hostname}:${targetUrl.port || 443}`
        if (proxy.auth) {
          options.headers["Proxy-Authorization"] = "Basic " + Buffer.from(proxy.auth).toString("base64")
        }

        const proxyReq = http.request(options)
        proxyReq.on("connect", (res, tunnelSocket) => {
          if (res.statusCode !== 200) {
            reject(new Error(`Proxy CONNECT failed: HTTP ${res.statusCode}`))
            return
          }
          // Tunnel established — now make the real HTTPS request through the tunnel
          const realReq = https.request({
            hostname: targetUrl.hostname,
            port: targetUrl.port || 443,
            path: targetUrl.pathname + targetUrl.search,
            method: "GET",
            socket: tunnelSocket,
            agent: false,
            timeout,
          })
          realReq.on("response", resolve)
          realReq.on("error", reject)
          realReq.on("timeout", () => { realReq.destroy(); reject(new Error("Request timeout")) })
          realReq.end()
        })
        proxyReq.on("error", reject)
        proxyReq.on("timeout", () => { proxyReq.destroy(); reject(new Error("Proxy connect timeout")) })
        proxyReq.end()
      } else {
        // HTTP through proxy
        options.method = "GET"
        options.path = urlStr
        options.hostname = proxy.hostname
        options.port = proxy.port
        if (proxy.auth) {
          options.headers["Proxy-Authorization"] = "Basic " + Buffer.from(proxy.auth).toString("base64")
        }
        const req = http.request(options, resolve)
        req.on("error", reject)
        req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")) })
        req.end()
      }
    } else {
      // Direct connection
      options.method = "GET"
      options.path = targetUrl.pathname + targetUrl.search
      if (targetUrl.protocol === "https:") {
        options.rejectUnauthorized = true
        const req = https.request(options, resolve)
        req.on("error", reject)
        req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")) })
        req.end()
      } else {
        const req = http.request(options, resolve)
        req.on("error", reject)
        req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")) })
        req.end()
      }
    }
  })
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
    makeRequest(url)
      .then((res) => {
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
          try { unlinkSync(dest) } catch {}
          reject(err)
        })
      })
      .catch(reject)
  })
}

function extractZip(zipPath, destDir, filter) {
  return new Promise((resolve, reject) => {
    try {
      if (IS_WIN) {
        const cmd = `tar -xf "${zipPath}" -C "${destDir}" 2>nul`
        execSync(cmd, { stdio: "pipe", timeout: 60000 })
      } else {
        execSync(`unzip -o "${zipPath}" -d "${destDir}" 2>/dev/null`, { stdio: "pipe", timeout: 60000 })
      }
      try { unlinkSync(zipPath) } catch {}
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
  if (def.destDir === "dependency-check") {
    const dcDir = join(dirname(binDir), "dependency-check")
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
  const destDir = join(dirname(binDir), def.destDir)
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

  // Apply proxy settings before every install attempt
  applyProxyFromEnv()

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
