/**
 * VulnGuard Desktop - Electron Main Process
 *
 * In development: loads the Next.js dev server at http://localhost:3000
 * In production: spawns the Next.js standalone server and loads it
 */
const { app, BrowserWindow, dialog, Menu, shell } = require("electron")
const { autoUpdater } = require("electron-updater")
const { fork } = require("child_process")
const path = require("path")
const fs = require("fs")
const http = require("http")
const { installScanner } = require("./scanner-downloader")

// ─── Constants ──────────────────────────────────────────────────────────────

const IS_DEV = !app.isPackaged
const DATA_DIR = path.join(app.getPath("userData"), "data")
const TOOLS_DIR = path.join(app.getPath("userData"), "tools")
const SCAN_ENGINE_DIR = path.join(TOOLS_DIR, "scan-engine")

// Port to use — may be updated by port-fallback logic
let ACTIVE_PORT = parseInt(process.env.VULNGUARD_PORT || "3000", 10)
const PORT_FALLBACK_MAX = 3005 // try 3000-3005

// ─── State ──────────────────────────────────────────────────────────────────

let mainWindow = null
let serverProcess = null
let serverReady = false

// ─── Data Directory Setup ───────────────────────────────────────────────────

function ensureDataDir() {
  const dirs = [
    DATA_DIR,
    path.join(DATA_DIR, "scans"),
    path.join(DATA_DIR, "uploads"),
    path.join(DATA_DIR, "downloads"),
    TOOLS_DIR,
    SCAN_ENGINE_DIR,
  ]
  for (const d of dirs) {
    if (!fs.existsSync(d)) {
      fs.mkdirSync(d, { recursive: true })
    }
  }
}

// ─── IPC Handlers ───────────────────────────────────────────────────────────

const { ipcMain } = require("electron")

// 从 package.json 读取版本，打包后 app.getVersion() 与 package.json 一致
const pkgVersion = require(path.join(__dirname, "..", "package.json")).version

ipcMain.on("get-version-sync", (event) => {
  event.returnValue = pkgVersion
})

ipcMain.handle("get-data-dir", () => DATA_DIR)

ipcMain.handle("get-scanner-status", () => {
  const scanEngineExe = path.join(SCAN_ENGINE_DIR, "scan-engine.exe")
  const scanEnginePy = path.join(SCAN_ENGINE_DIR, "scan-engine.py")
  const archiveMarker = path.join(TOOLS_DIR, ".archive-extracted")
  return {
    scanEngine: fs.existsSync(scanEngineExe) || fs.existsSync(scanEnginePy),
    toolsDir: TOOLS_DIR,
    archiveExtracted: fs.existsSync(archiveMarker),
  }
})

ipcMain.handle("download-scanner", async (_event, scannerName) => {
  try {
    // 立即发送"开始连接"进度，让用户马上看到反馈
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send("scanner-progress", { scanner: scannerName, percent: 0, bytes: 0, total: 0 })
    }

    // 新版代理设置路径直接指向 userData，不走用户登录后的缓存目录
    process.env.VULNGUARD_DATA_DIR = path.join(app.getPath("userData"))
    applyProxyFromSettings()
    const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy
    console.log(`[scanner] Downloading ${scannerName}, proxy: ${httpsProxy || "NONE"}`)
    const settingsFile = path.join(app.getPath("userData"), "settings.json")
    if (!httpsProxy) {
      console.log(`[scanner] WARNING: No proxy configured! Settings path: ${settingsFile}`)
      try {
        const exists = require("fs").existsSync(settingsFile)
        console.log(`[scanner] settings.json exists: ${exists}`)
        if (exists) {
          const raw = require("fs").readFileSync(settingsFile, "utf-8")
          const s = JSON.parse(raw)
          console.log(`[scanner] proxyEnabled: ${s.proxyEnabled}, httpsProxy: ${s.httpsProxy}`)
        }
      } catch (e) {
        console.log(`[scanner] settings check error: ${e.message}`)
      }
    }
    // 如果 settings.json 没配代理，但系统环境变量有，也直接用
    if (!httpsProxy && (process.env.HTTP_PROXY || process.env.http_proxy)) {
      process.env.HTTPS_PROXY = process.env.HTTP_PROXY || process.env.http_proxy
      console.log(`[scanner] Using HTTPS_PROXY from env: ${process.env.HTTPS_PROXY}`)
    }
    const result = await installScanner(scannerName, TOOLS_DIR, (progress) => {
      // 通过 IPC 回传下载进度给渲染进程
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send("scanner-progress", { scanner: scannerName, ...progress })
      }
    })

    // 安装成功后后台预下载 Dependency-Check NVD 缓存
    if (result?.ok && !result?.skipped) {
      prefetchNvdCache()
    }

    return result
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

// ─── 后台预下载 Dependency-Check NVD 缓存 ─────────────────────────────────

function prefetchNvdCache() {
  const dcCandidates = [
    path.join(TOOLS_DIR, "dependency-check", "dependency-check", "bin", process.platform === "win32" ? "dependency-check.bat" : "dependency-check.sh"),
    path.join(TOOLS_DIR, "dependency-check", "bin", process.platform === "win32" ? "dependency-check.bat" : "dependency-check.sh"),
  ]
  const dcPath = dcCandidates.find(p => fs.existsSync(p))
  if (!dcPath) {
    console.log("[prefetch] dependency-check not found, skipping NVD cache prefetch")
    return
  }

  const nvdCacheDir = path.join(app.getPath("userData"), ".nvd-cache", "data")
  // 已有缓存就跳过
  if (fs.existsSync(nvdCacheDir) && fs.readdirSync(nvdCacheDir).length > 0) {
    console.log("[prefetch] NVD cache already exists, skipping")
    return
  }

  if (!fs.existsSync(nvdCacheDir)) fs.mkdirSync(nvdCacheDir, { recursive: true })
  const logFile = path.join(app.getPath("userData"), "logs", "nvd-prefetch.log")
  applyProxyFromSettings()
  const proxy = process.env.HTTPS_PROXY || process.env.HTTP_PROXY || ""
  const javaOpts = proxy
    ? `-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=${new URL(proxy).port} -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=${new URL(proxy).port}`
    : ""

  console.log(`[prefetch] Starting NVD cache download in background...`)
  const child = require("child_process").spawn(
    dcPath, ["--updateonly", "--data", nvdCacheDir],
    { env: { ...process.env, ...(javaOpts ? { JAVA_OPTS: javaOpts } : {}) }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true, detached: true }
  )
  child.unref() // 不阻塞应用退出
  const logStream = fs.createWriteStream(logFile, { flags: "a" })
  child.stdout.pipe(logStream)
  child.stderr.pipe(logStream)
  child.on("exit", (code) => {
    logStream.end()
    console.log(`[prefetch] NVD cache download exited with code ${code}`)
  })
}

ipcMain.handle("check-for-updates", async () => {
  try {
    applyProxyFromSettings()
    const result = await autoUpdater.checkForUpdates()
    const latestVersion = result?.updateInfo?.version
    // 比较版本号，只有远端版本 > 当前版本时才提示可更新
    if (latestVersion && compareVersions(latestVersion, pkgVersion) > 0) {
      return { ok: true, canUpdate: true, version: latestVersion }
    }
    // 版本不同但比较不出大小（如 0.6.21 vs 0.6.3）也视为可更新
    if (latestVersion && latestVersion.replace(/^v/i, "") !== pkgVersion.replace(/^v/i, "")) {
      return { ok: true, canUpdate: true, version: latestVersion }
    }
    return { ok: true, canUpdate: false }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

/**
 * 比较两个语义化版本号（支持 v 前缀、x.y.z 格式）
 * 返回: 1 表示 a > b, 0 表示 a === b, -1 表示 a < b
 */
function compareVersions(a, b) {
  const normalize = (v) => v.replace(/^v/i, "").split(".").map(Number)
  const pa = normalize(a)
  const pb = normalize(b)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0
    const nb = pb[i] || 0
    if (na > nb) return 1
    if (na < nb) return -1
  }
  return 0
}

ipcMain.handle("start-update", async () => {
  try {
    applyProxyFromSettings()
    await autoUpdater.downloadUpdate()
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

// ─── Window Controls (custom title bar) ──────────────────────────────────

ipcMain.handle("window-minimize", () => mainWindow?.minimize())
ipcMain.handle("window-maximize", () => {
  if (mainWindow?.isMaximized()) mainWindow.unmaximize()
  else mainWindow?.maximize()
})
ipcMain.handle("window-close", () => mainWindow?.close())
ipcMain.handle("window-is-maximized", () => mainWindow?.isMaximized())

ipcMain.handle("open-file-dialog", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile", "openDirectory", "multiSelections"],
  })
  return result.canceled ? null : result.filePaths
})

// ─── Direct PDF export (via Electron printToPDF) ──────────────────────────

ipcMain.handle("download-pdf", async (_event, html, defaultName) => {
  try {
    const pdfWindow = new BrowserWindow({ show: false, webPreferences: { sandbox: true } })
    await pdfWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`)
    // Wait for fonts/layout to settle
    await new Promise(r => setTimeout(r, 500))
    const buf = await pdfWindow.webContents.printToPDF({
      printBackground: true,
      preferCSSPageSize: true,
      margins: { top: 0.4, bottom: 0.4, left: 0.4, right: 0.4 },
    })
    pdfWindow.close()

    const { filePath } = await dialog.showSaveDialog(mainWindow, {
      defaultPath: defaultName || "VulnGuard-Report.pdf",
      filters: [{ name: "PDF 文件", extensions: ["pdf"] }],
    })
    if (!filePath) return { ok: false, cancelled: true }

    fs.writeFileSync(filePath, buf)
    return { ok: true, filePath }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

// ─── Log file for server diagnostics ────────────────────────────────────────

const LOG_DIR = IS_DEV
  ? path.join(process.cwd(), ".scans")
  : path.join(app.getPath("userData"), "logs")

function writeLog(level, msg) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true })
    const logFile = path.join(LOG_DIR, "electron.log")
    const line = `[${new Date().toISOString()}] [${level}] ${msg}\n`
    fs.appendFileSync(logFile, line, "utf-8")
  } catch { /* best effort */ }
}

// ─── Collect server stderr for error dialog ─────────────────────────────────

let serverStderr = ""

// ─── Find Next.js Server ────────────────────────────────────────────────────

function findServerJs() {
  const candidates = IS_DEV
    ? [
        path.join(process.cwd(), ".next", "standalone", "server.js"),
      ]
    : [
        path.join(process.resourcesPath, "app.asar.unpacked", ".next", "standalone", "server.js"),
        path.join(path.dirname(process.execPath), "resources", "app.asar.unpacked", ".next", "standalone", "server.js"),
        path.join(__dirname, "..", ".next", "standalone", "server.js"),
        path.join(process.cwd(), ".next", "standalone", "server.js"),
      ]
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c
    } catch { /* skip invalid paths */ }
  }
  return null
}

// ─── Start Next.js Server ───────────────────────────────────────────────────

function startNextServer(port) {
  return new Promise((resolve, reject) => {
    const serverJs = findServerJs()
    if (!serverJs) {
      reject(new Error(`Next.js standalone server.js not found.\n\nSearched paths:\n  ${findServerJs.toString().match(/candidates = \[([^\]]+)\]/s)?.[1]?.split(",").map(s => s.trim()).join("\n  ") || "(see log)"}`))
      return
    }

    writeLog("info", `Found server.js at: ${serverJs} (port ${port})`)

    // Build env: inherit process.env + override key vars
    const env = {
      ...process.env,
      PORT: String(port),
      NODE_ENV: "production",
      DATA_DIR: DATA_DIR,
      VULNGUARD_DATA_DIR: path.join(app.getPath("userData")),
    }

    // Reset server stderr for each start attempt
    serverStderr = ""

    // Set up .env.local if not exists
    const serverDir = path.dirname(serverJs)
    const envLocalPath = path.join(serverDir, ".env.local")
    const envExamplePath = path.join(serverDir, ".env.example")
    if (!fs.existsSync(envLocalPath) && fs.existsSync(envExamplePath)) {
      try {
        fs.copyFileSync(envExamplePath, envLocalPath)
        writeLog("info", `Created .env.local from .env.example at ${serverDir}`)
      } catch (e) {
        writeLog("warn", `Failed to copy .env.example: ${e.message}`)
      }
    }

    // Also load .env.local into env if present
    const envLocal = envLocalPath
    if (fs.existsSync(envLocal)) {
      try {
        const content = fs.readFileSync(envLocal, "utf-8")
        for (const line of content.split("\n")) {
          const trimmed = line.trim()
          if (!trimmed || trimmed.startsWith("#")) continue
          const eqIdx = trimmed.indexOf("=")
          if (eqIdx < 1) continue
          const key = trimmed.slice(0, eqIdx).trim()
          const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "")
          if (key && !env[key]) env[key] = val
        }
        writeLog("info", "Loaded .env.local into server environment")
      } catch (e) {
        writeLog("warn", `Failed to load .env.local: ${e.message}`)
      }
    }

    serverProcess = fork(serverJs, [], {
      env,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    })

    let resolved = false

    serverProcess.stdout.on("data", (data) => {
      const msg = data.toString()
      writeLog("info", `[next] ${msg.trim()}`)
      if (!resolved && (msg.includes("started") || msg.includes("listening") || msg.includes("ready") || msg.includes("localhost"))) {
        resolved = true
        serverReady = true
        writeLog("info", "Server ready signal detected on stdout")
        resolve()
      }
    })

    serverProcess.stderr.on("data", (data) => {
      const msg = data.toString().trim()
      if (!msg) return
      serverStderr += msg + "\n"
      writeLog("error", `[next:stderr] ${msg}`)
    })

    serverProcess.on("error", (err) => {
      writeLog("error", `Server fork error: ${err.message}`)
      if (!resolved) {
        resolved = true
        reject(new Error(`Failed to fork server process:\n${err.message}`))
      }
    })

    serverProcess.on("exit", (code) => {
      const signal = serverProcess?.killed ? " (killed)" : ""
      writeLog("info", `Server process exited with code ${code}${signal}`)
      serverProcess = null
      if (!resolved && code !== null && code !== 0) {
        // Process crashed before we got a ready signal — reject early
        resolved = true
        const stderrSnippet = serverStderr
          ? `\n\nServer stderr (last 500 chars):\n${serverStderr.slice(-500)}`
          : ""
        reject(new Error(`Server exited unexpectedly (code ${code}).${stderrSnippet}`))
      }
    })

    // Poll for server readiness (fork doesn't reliably signal via stdout)
    const POLL_INTERVAL = 800    // ms between checks
    const MAX_ATTEMPTS = 90      // ~72 seconds total
    let attempts = 0

    const poll = setInterval(() => {
      if (resolved) {
        clearInterval(poll)
        return
      }

      // If the process already exited, fail fast
      if (!serverProcess && !serverReady) {
        clearInterval(poll)
        if (!resolved) {
          resolved = true
          const stderrSnippet = serverStderr
            ? `\n\nServer stderr (last 500 chars):\n${serverStderr.slice(-500)}`
            : ""
          reject(new Error(`Server process exited during startup.${stderrSnippet}`))
        }
        return
      }

      attempts++
      if (attempts > MAX_ATTEMPTS) {
        clearInterval(poll)
        checkServer(port).then((ok) => {
          if (ok && !resolved) {
            resolved = true
            serverReady = true
            resolve()
          } else if (!resolved) {
            resolved = true
            const stderrSnippet = serverStderr
              ? `\n\nServer stderr (last 800 chars):\n${serverStderr.slice(-800)}`
              : ""
            reject(new Error(
              `Server did not start within ${Math.round((MAX_ATTEMPTS * POLL_INTERVAL) / 1000)} seconds.` +
              `\nPort: ${port}` +
              `${stderrSnippet}` +
              `\n\nCheck logs: ${path.join(LOG_DIR, "electron.log")}`
            ))
          }
        })
        return
      }

      checkServer(port).then((ok) => {
        if (ok && !resolved) {
          resolved = true
          serverReady = true
          clearInterval(poll)
          writeLog("info", "Server reachable via HTTP check on port " + port)
          resolve()
        }
      })
    }, POLL_INTERVAL)
  })
}

function checkServer(port) {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${port || ACTIVE_PORT}`, (res) => {
      resolve(res.statusCode < 500)
    })
    req.on("error", () => resolve(false))
    req.setTimeout(1000, () => {
      req.destroy()
      resolve(false)
    })
  })
}

// ─── Wait for Server ────────────────────────────────────────────────────────

async function waitForServer(maxRetries = 60) {
  for (let i = 0; i < maxRetries; i++) {
    const ok = await checkServer()
    if (ok) return true
    await new Promise((r) => setTimeout(r, 1000))
  }
  throw new Error("Server did not start in time")
}

// ─── Auto-Updater ──────────────────────────────────────────────────

/**
 * 检测 Windows 系统代理设置（注册表），在没有手动配置时自动使用。
 * 对应 Clash / V2Ray / 系统代理等场景。
 */
function detectSystemProxy() {
  if (process.platform !== "win32") return
  // 如果环境变量已经由 settings.json 设置了，不覆盖
  if (process.env.HTTPS_PROXY || process.env.https_proxy) return
  try {
    const { execSync } = require("child_process")
    const registryQuery = 'reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable /t REG_DWORD 2>nul'
    const enabled = execSync(registryQuery, { stdio: "pipe", timeout: 3000 }).toString().trim()
    if (!enabled.includes("0x1")) return

    const serverQuery = 'reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyServer /t REG_SZ 2>nul'
    const server = execSync(serverQuery, { stdio: "pipe", timeout: 3000 }).toString().trim()
    const match = server.match(/ProxyServer\s+REG_SZ\s+(\S+)/)
    if (!match) return

    const proxyUrl = match[1].trim()
    // 统一添加 http:// 前缀（注册表通常只存 host:port）
    const fullUrl = proxyUrl.startsWith("http") ? proxyUrl : `http://${proxyUrl}`
    process.env.HTTP_PROXY = fullUrl
    process.env.HTTPS_PROXY = fullUrl
    console.log(`[proxy] detected system proxy: ${fullUrl}`)
  } catch {
    // reg query 可能失败（无权限、非 Windows 等），静默忽略
  }
}

/**
 * 从持久化设置中读取代理配置并设置环境变量，
 * 使 autoUpdater.checkForUpdates / downloadUpdate 通过代理访问 GitHub。
 * 如果用户未手动配置，则尝试检测系统代理。
 */
function applyProxyFromSettings() {
  try {
    const settingsPath = path.join(app.getPath("userData"), "settings.json")
    if (!fs.existsSync(settingsPath)) {
      detectSystemProxy()
      return
    }

    const raw = fs.readFileSync(settingsPath, "utf-8")
    const settings = JSON.parse(raw)

    if (settings.proxyEnabled) {
      if (settings.httpProxy) process.env.HTTP_PROXY = settings.httpProxy
      if (settings.httpsProxy) process.env.HTTPS_PROXY = settings.httpsProxy
      console.log("[auto-updater] proxy configured from settings")
    } else {
      delete process.env.HTTP_PROXY
      delete process.env.HTTPS_PROXY
      // 用户手动关闭了代理 → 不自动检测系统代理
    }
  } catch (e) {
    console.error("[scanner] Failed to apply proxy from settings:", e.message || e)
    detectSystemProxy()
  }
}

function setupAutoUpdater() {
  if (IS_DEV) return

  autoUpdater.setFeedURL({ provider: "github", owner: "hengtaoshi", repo: "VulnGuard" })
  autoUpdater.autoDownload = false

  autoUpdater.on("update-available", (info) => {
    mainWindow?.webContents.send("update-available", { version: info.version })
  })

  autoUpdater.on("download-progress", (progress) => {
    mainWindow?.webContents.send("update-progress", { percent: Math.round(progress.percent) })
  })

  autoUpdater.on("update-downloaded", () => {
    mainWindow?.webContents.send("update-downloaded")
    // Auto-quit-and-install after the renderer has shown the "done" state
    setTimeout(() => autoUpdater.quitAndInstall(), 3000)
  })
}

// ─── Create Window ──────────────────────────────────────────────────────────

function createWindow() {
  const { width, height } = require("electron").screen.getPrimaryDisplay().workAreaSize

  mainWindow = new BrowserWindow({
    width: Math.min(1400, width),
    height: Math.min(900, height),
    minWidth: 1024,
    minHeight: 700,
    title: "VulnGuard Security Scanner",
    frame: false,
    icon: path.join(__dirname, "..", "resources", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
    show: false,
    backgroundColor: "#0f172a",
  })

  // Custom title bar — notify renderer when maximize state changes
  mainWindow.on("maximize", () => mainWindow.webContents.send("window-maximize-change", true))
  mainWindow.on("unmaximize", () => mainWindow.webContents.send("window-maximize-change", false))

  // Show window when ready
  mainWindow.once("ready-to-show", () => {
    mainWindow.show()
    // Silent update check after 5s — banner will show in renderer if available
    if (!IS_DEV) {
      setTimeout(async () => {
        try {
          console.log("[auto-updater] checking for updates...")
          console.log("[auto-updater] proxy:", process.env.HTTPS_PROXY || process.env.https_proxy || "NONE")
          applyProxyFromSettings()
          const result = await autoUpdater.checkForUpdates()
          console.log("[auto-updater] check result:", result?.updateInfo?.version)
        } catch (e) {
          console.error("[auto-updater] check failed:", e.message || e)
          console.error("[auto-updater] check failed stack:", e.stack?.slice(0, 300))
        }
      }, 5000)
    }
  })

  // Open external links in browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: "deny" }
  })

  // No application menu — clean minimal desktop experience
  Menu.setApplicationMenu(null)

  // Auto-updater (production only)
  setupAutoUpdater()

  // Load the app
  if (IS_DEV) {
    mainWindow.loadURL(`http://localhost:${ACTIVE_PORT}`)
    mainWindow.webContents.openDevTools()
  } else {
    mainWindow.loadURL(`http://127.0.0.1:${ACTIVE_PORT}`)
  }

  mainWindow.on("closed", () => {
    mainWindow = null
  })
}

// ─── App Lifecycle ──────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  ensureDataDir()

  if (IS_DEV) {
    // In dev mode, assume Next.js dev server is already running
    console.log("[electron] Dev mode — waiting for Next.js dev server...")
    try {
      await waitForServer(120)
      console.log("[electron] Next.js dev server is ready")
    } catch (err) {
      console.error("[electron] Failed to connect to Next.js dev server:", err.message)
      dialog.showErrorBox(
        "Connection Error",
        "Could not connect to the Next.js dev server.\n\nMake sure to run 'npm run dev' in another terminal first.",
      )
      app.quit()
      return
    }
  } else {
    // Production: start the Next.js server with port fallback
    let lastError = null
    let started = false

    for (let port = ACTIVE_PORT; port <= PORT_FALLBACK_MAX; port++) {
      writeLog("info", `Attempting to start server on port ${port}...`)
      try {
        await startNextServer(port)
        ACTIVE_PORT = port
        started = true
        writeLog("info", `Server started successfully on port ${port}`)
        break
      } catch (err) {
        lastError = err
        writeLog("warn", `Port ${port} failed: ${err.message}`)
        // Kill any lingering process from this attempt
        if (serverProcess) {
          serverProcess.kill("SIGKILL")
          serverProcess = null
        }
        serverReady = false
        serverStderr = ""
      }
    }

    if (!started) {
      const msg = lastError ? lastError.message : "unknown error"
      writeLog("error", `All ports (${ACTIVE_PORT}-${PORT_FALLBACK_MAX}) failed. Last error: ${msg}`)
      dialog.showErrorBox(
        "Startup Error",
        `Failed to start the web server on ports ${ACTIVE_PORT}-${PORT_FALLBACK_MAX}.\n\n` +
        `Last error:\n${msg}\n\n` +
        `Logs: ${path.join(LOG_DIR, "electron.log")}`
      )
      app.quit()
      return
    }
  }

  createWindow()
})

app.on("window-all-closed", () => {
  if (serverProcess) {
    serverProcess.kill("SIGTERM")
    serverProcess = null
  }
  if (process.platform !== "darwin") {
    app.quit()
  }
})

app.on("activate", () => {
  if (mainWindow === null) {
    createWindow()
  }
})

app.on("before-quit", () => {
  if (serverProcess) {
    try {
      if (process.platform === "win32") {
        require("child_process").execSync(`taskkill /F /PID ${serverProcess.pid} 2>nul`, { stdio: "ignore" })
      } else {
        serverProcess.kill("SIGTERM")
      }
    } catch { /* ignore */ }
    serverProcess = null
  }
})
