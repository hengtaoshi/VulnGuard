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

ipcMain.handle("get-data-dir", () => DATA_DIR)

ipcMain.handle("get-scanner-status", () => {
  const scanEngineExe = path.join(SCAN_ENGINE_DIR, "scan-engine.exe")
  const scanEnginePy = path.join(SCAN_ENGINE_DIR, "scan-engine.py")
  return {
    scanEngine: fs.existsSync(scanEngineExe) || fs.existsSync(scanEnginePy),
    toolsDir: TOOLS_DIR,
  }
})

ipcMain.handle("check-for-updates", async () => {
  try {
    const result = await autoUpdater.checkForUpdates()
    return { ok: true, canUpdate: !!result?.updateInfo, version: result?.updateInfo?.version }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

ipcMain.handle("start-update", async () => {
  try {
    await autoUpdater.downloadUpdate()
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

ipcMain.handle("open-file-dialog", async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ["openFile", "openDirectory", "multiSelections"],
  })
  return result.canceled ? null : result.filePaths
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
      VULNGUARD_DATA_DIR: DATA_DIR,
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

  // Show window when ready
  mainWindow.once("ready-to-show", () => {
    mainWindow.show()
    // Silent update check after 5s — banner will show in renderer if available
    if (!IS_DEV) {
      setTimeout(async () => {
        try { await autoUpdater.checkForUpdates() }
        catch (e) { console.error("[auto-updater] check failed:", e.message) }
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
    serverProcess.kill("SIGTERM")
    serverProcess = null
  }
})
