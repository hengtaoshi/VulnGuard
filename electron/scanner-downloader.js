/**
 * VulnGuard Scanner Downloader
 *
 * Downloads the single unified scanners archive and extracts it.
 * All scanners are pre-packaged into one scanners.tar.gz on GitHub Releases.
 */
const https = require("https")
const http = require("http")
const { createWriteStream, existsSync, mkdirSync, unlinkSync, readFileSync, openSync, readSync, closeSync, statSync, rmSync, writeFileSync } = require("fs")
const { join } = require("path")
const { execSync } = require("child_process")
const { platform } = require("os")
const { URL } = require("url")

const IS_WIN = platform() === "win32"
const DATA_DIR = process.env.VULNGUARD_DATA_DIR || ""

// Archive URL — pinned to v0.6.5 release (stable scanner bundle, not per-version)
const ARCHIVE_URL = "https://github.com/hengtaoshi/VulnGuard/releases/download/v0.6.5/scanners.tar.gz"

// All scanners provided by the bundle
const BUNDLED_SCANNERS = [
  "gitleaks", "trivy", "nuclei", "trufflehog", "osv-scanner", "scorecard",
  "semgrep", "bandit", "checkov", "pip-audit",
  "dependency-check", "codeql",
]

// Marker file written after successful extraction
const MARKER = ".archive-extracted"

// ─── Proxy helpers (unchanged) ────────────────────────────────────────────────

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
  } catch { /* best effort */ void 0 }
}

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
  } catch { return null }
}

function makeRequest(urlStr, timeout = 120000, retries = 2) {
  return _makeRequest(urlStr, timeout, retries)
}

function _makeRequest(urlStr, timeout = 120000, retries = 2) {
  return new Promise((resolve, reject) => {
    const targetUrl = new URL(urlStr)
    const proxy = getProxyForUrl(urlStr)
    const options = {
      hostname: proxy ? proxy.hostname : targetUrl.hostname,
      port: proxy ? proxy.port : (targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80)),
      timeout, headers: {},
    }
    if (proxy) {
      if (targetUrl.protocol === "https:") {
        options.method = "CONNECT"
        options.path = `${targetUrl.hostname}:${targetUrl.port || 443}`
        if (proxy.auth) options.headers["Proxy-Authorization"] = "Basic " + Buffer.from(proxy.auth).toString("base64")
        const proxyReq = http.request(options)
        proxyReq.on("connect", (res, tunnelSocket) => {
          if (res.statusCode !== 200) { reject(new Error(`Proxy CONNECT failed: HTTP ${res.statusCode}`)); return }
          const realReq = https.request({ hostname: targetUrl.hostname, port: targetUrl.port || 443, path: targetUrl.pathname + targetUrl.search, method: "GET", socket: tunnelSocket, agent: false, timeout })
          realReq.on("response", resolve); realReq.on("error", reject)
          realReq.on("timeout", () => { realReq.destroy(); reject(new Error("Request timeout")) }); realReq.end()
        })
        proxyReq.on("error", reject); proxyReq.on("timeout", () => { proxyReq.destroy(); reject(new Error("Proxy connect timeout")) }); proxyReq.end()
      } else {
        options.method = "GET"; options.path = urlStr; options.hostname = proxy.hostname; options.port = proxy.port
        if (proxy.auth) options.headers["Proxy-Authorization"] = "Basic " + Buffer.from(proxy.auth).toString("base64")
        const req = http.request(options, resolve); req.on("error", reject); req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")) }); req.end()
      }
    } else {
      options.method = "GET"; options.path = targetUrl.pathname + targetUrl.search
      const mod = targetUrl.protocol === "https:" ? https : http
      const req = mod.request(options, resolve); req.on("error", reject); req.on("timeout", () => { req.destroy(); reject(new Error("Request timeout")) }); req.end()
    }
  }).catch((err) => {
    if (retries > 0 && (err.code === "ECONNRESET" || err.code === "ETIMEDOUT" || err.message?.includes("timeout") || err.message?.includes("econnreset"))) {
      console.log(`[scanner] Retrying (${retries} left) after: ${err.code || err.message}`)
      return new Promise((r) => setTimeout(r, 1000)).then(() => _makeRequest(urlStr, timeout, retries - 1))
    }
    throw err
  })
}

// ─── Progress Reporter ────────────────────────────────────────────────────────

class ProgressReporter {
  constructor(sendProgress) {
    this._send = sendProgress; this._last = 0; this._maxPercent = 0
    this._lastTime = Date.now()
  }
  update(downloaded, total) {
    const pct = total > 0 ? Math.round((downloaded / total) * 100) : 0
    const elapsed = Date.now() - this._lastTime
    // 每 1% 或每 3 秒强制推送进度，让用户能看到反馈
    if (Math.abs(pct - this._last) >= 1 || elapsed >= 3000 || pct === 100) {
      this._maxPercent = Math.max(this._maxPercent, pct); this._last = this._maxPercent
      this._lastTime = Date.now()
      this._send({ percent: this._maxPercent, bytes: downloaded, total })
    }
  }
  done() { this._send({ percent: 100, bytes: 0, total: 0, done: true }) }
  error(msg) { this._send({ percent: this._maxPercent || 0, bytes: 0, total: 0, error: msg }) }
}

// ─── File helpers ─────────────────────────────────────────────────────────────

function downloadFile(url, dest, reporter) {
  return new Promise((resolve, reject) => {
    makeRequest(url).then((res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume(); return downloadFile(res.headers.location, dest, reporter).then(resolve).catch(reject)
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)) }
      const total = parseInt(res.headers["content-length"] || "0", 10)
      let downloaded = 0
      const file = createWriteStream(dest)
      res.on("data", (chunk) => { downloaded += chunk.length; reporter.update(downloaded, total) })
      res.pipe(file)
      file.on("finish", () => { file.close(); reporter.done(); resolve() })
      file.on("error", (err) => { file.close(); try { unlinkSync(dest) } catch { void 0 }; reject(err) })
    }).catch(reject)
  })
}

function verifyBinary(filePath) {
  try {
    if (!existsSync(filePath)) return false
    const size = statSync(filePath).size
    if (size < 1000) return false
    if (IS_WIN) {
      const buf = Buffer.alloc(2)
      const fd = openSync(filePath, 'r')
      readSync(fd, buf, 0, 2, 0); closeSync(fd)
      if (buf[0] !== 0x4D || buf[1] !== 0x5A) throw new Error(`Invalid PE executable: missing MZ header`)
    }
    return true
  } catch { return false }
}

// ─── Archive download + extract ───────────────────────────────────────────────

async function ensureArchiveExtracted(toolsDir, sendProgress) {
  const markerFile = join(toolsDir, MARKER)
  if (existsSync(markerFile)) return { ok: true, skipped: true }

  console.log(`[scanner] Downloading scanner bundle from ${ARCHIVE_URL}`)
  applyProxyFromEnv()
  const reporter = new ProgressReporter(sendProgress)
  const tmp = join(toolsDir, "scanners.tar.gz.download")

  try {
    if (!existsSync(toolsDir)) mkdirSync(toolsDir, { recursive: true })

    // Download the single archive
    await downloadFile(ARCHIVE_URL, tmp, reporter)

    // Verify archive size
    reporter.update(95, 100)
    const stat = statSync(tmp)
    if (stat.size < 1000000) throw new Error(`Downloaded archive too small: ${stat.size} bytes`)

    // Path traversal protection: check all archive entries before extracting
    const entries = execSync(`tar -tf "${tmp}"`, { stdio: "pipe", timeout: 30000 }).toString().split("\n")
    for (const entry of entries) {
      const trimmed = entry.trim()
      if (trimmed.includes("..") || trimmed.startsWith("/") || trimmed.startsWith("\\")) {
        throw new Error(`Path traversal detected in archive: ${trimmed}`)
      }
    }

    // Extract to toolsDir — archive has bin/ codeql/ dependency-check/ at root
    execSync(`tar -xzf "${tmp}" -C "${toolsDir}"`, { stdio: "pipe", timeout: 300000 })
    try { unlinkSync(tmp) } catch { void 0 }

    // Verify critical binaries
    const binDir = join(toolsDir, "bin")
    const critical = ["gitleaks.exe", "nuclei.exe", "trivy.exe"]
    for (const exe of critical) {
      const p = join(binDir, exe)
      if (!existsSync(p)) throw new Error(`Missing critical binary: ${exe}`)
      if (!verifyBinary(p)) throw new Error(`Invalid binary: ${exe}`)
    }

    // Set +x on Linux
    if (!IS_WIN) {
      execSync(`chmod +x "${join(binDir, "*")}"`, { stdio: "pipe" })
      // Also handle codeql and dependency-check scripts
      for (const dir of ["codeql", "dependency-check"]) {
        const d = join(toolsDir, dir)
        if (existsSync(d)) execSync(`find "${d}" -type f -exec chmod +x {} \\; 2>/dev/null`, { stdio: "pipe" })
      }
    }

    // Write marker
    writeFileSync(markerFile, new Date().toISOString())
    console.log(`[scanner] Bundle extracted to ${toolsDir}`)
    reporter.done()
    return { ok: true }
  } catch (err) {
    try { unlinkSync(tmp) } catch { void 0 }
    // Clean up partially extracted files so retry starts fresh
    for (const dir of ["bin", "codeql", "dependency-check"]) {
      const p = join(toolsDir, dir)
      try { rmSync(p, { recursive: true, force: true }) } catch { void 0 }
    }
    try { unlinkSync(join(toolsDir, MARKER)) } catch { void 0 }
    reporter.error(err.message)
    return { ok: false, error: err.message }
  }
}

// ─── Scanner existence check ──────────────────────────────────────────────────

function getScannerPath(name, toolsDir) {
  const binDir = join(toolsDir, "bin")
  switch (name) {
    case "gitleaks": case "trivy": case "nuclei": case "trufflehog":
    case "osv-scanner": case "scorecard": case "semgrep":
    case "bandit": case "checkov": case "pip-audit":
      return join(binDir, name + ".exe")
    case "dependency-check":
      return join(toolsDir, "dependency-check", "bin", IS_WIN ? "dependency-check.bat" : "dependency-check.sh")
    case "codeql":
      return join(toolsDir, "codeql", "codeql", "codeql" + (IS_WIN ? ".exe" : ""))
    default:
      return null
  }
}

function isScannerInstalled(name, toolsDir) {
  const p = getScannerPath(name, toolsDir)
  return p ? existsSync(p) : false
}

// ─── Public API ───────────────────────────────────────────────────────────────

async function installScanner(name, toolsDir, sendProgress) {
  if (!BUNDLED_SCANNERS.includes(name)) {
    return { ok: false, error: `Unknown scanner: ${name}` }
  }

  // Check if already installed
  if (isScannerInstalled(name, toolsDir) && existsSync(join(toolsDir, MARKER))) {
    if (sendProgress) sendProgress({ percent: 100, done: true, skipped: true })
    return { ok: true, skipped: true }
  }

  // Download + extract the bundle
  const result = await ensureArchiveExtracted(toolsDir, sendProgress)
  if (!result.ok) return result

  // Final verification
  if (!isScannerInstalled(name, toolsDir)) {
    return { ok: false, error: `Scanner '${name}' not found in extracted bundle` }
  }

  return { ok: true }
}

function getScannerInfo(name) {
  return BUNDLED_SCANNERS.includes(name) ? { name, bundled: true } : null
}

function getRegisteredScanners() {
  return [...BUNDLED_SCANNERS]
}

module.exports = { installScanner, getScannerInfo, getRegisteredScanners }
