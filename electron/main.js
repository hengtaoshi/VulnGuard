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
const PORT = process.env.VULNGUARD_PORT || 3000
const DATA_DIR = path.join(app.getPath("userData"), "data")
const TOOLS_DIR = path.join(app.getPath("userData"), "tools")
const SCAN_ENGINE_DIR = path.join(TOOLS_DIR, "scan-engine")

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

// ─── Find Next.js Server ────────────────────────────────────────────────────

function findServerJs() {
  const candidates = [
    path.join(process.resourcesPath, "app.asar.unpacked", ".next", "standalone", "server.js"),
    path.join(__dirname, "..", ".next", "standalone", "server.js"),
    path.join(process.cwd(), ".next", "standalone", "server.js"),
  ]
  for (const c of candidates) {
    if (fs.existsSync(c)) return c
  }
  return null
}

// ─── Start Next.js Server ───────────────────────────────────────────────────

function startNextServer() {
  return new Promise((resolve, reject) => {
    const serverJs = findServerJs()
    if (!serverJs) {
      reject(new Error("Next.js standalone server.js not found. Run 'npm run build' first."))
      return
    }

    const env = {
      ...process.env,
      PORT: String(PORT),
      NODE_ENV: "production",
      DATA_DIR: DATA_DIR,
      VULNGUARD_DATA_DIR: DATA_DIR,
    }

    // Set up .env.local if not exists
    const envLocalPath = path.join(path.dirname(serverJs), ".env.local")
    const envExamplePath = path.join(path.dirname(serverJs), ".env.example")
    if (!fs.existsSync(envLocalPath) && fs.existsSync(envExamplePath)) {
      fs.copyFileSync(envExamplePath, envLocalPath)
    }

    serverProcess = fork(serverJs, [], {
      env,
      stdio: ["ignore", "pipe", "pipe", "ipc"],
    })

    serverProcess.stdout.on("data", (data) => {
      const msg = data.toString()
      console.log(`[next] ${msg.trim()}`)
      if (msg.includes("started") || msg.includes("listening") || msg.includes("ready")) {
        serverReady = true
        resolve()
      }
    })

    serverProcess.stderr.on("data", (data) => {
      const msg = data.toString().trim()
      if (msg) console.error(`[next] ${msg}`)
    })

    serverProcess.on("error", (err) => {
      console.error("[next] Server error:", err)
      reject(err)
    })

    serverProcess.on("exit", (code) => {
      console.log(`[next] Server exited with code ${code}`)
      serverReady = false
      serverProcess = null
    })

    // Poll for server readiness (fork doesn't reliably signal)
    let attempts = 0
    const poll = setInterval(() => {
      if (serverReady) {
        clearInterval(poll)
        return
      }
      attempts++
      if (attempts > 60) {
        // 30 seconds timeout
        clearInterval(poll)
        // Check if the server is actually running despite no signal
        checkServer()
          .then((ok) => (ok ? resolve() : reject(new Error("Server startup timeout"))))
          .catch(() => reject(new Error("Server startup timeout")))
        return
      }
      checkServer().then((ok) => {
        if (ok) {
          serverReady = true
          clearInterval(poll)
          resolve()
        }
      })
    }, 500)
  })
}

function checkServer() {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${PORT}`, (res) => {
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
    mainWindow.loadURL(`http://localhost:${PORT}`)
    mainWindow.webContents.openDevTools()
  } else {
    mainWindow.loadURL(`http://127.0.0.1:${PORT}`)
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
    // Production: start the Next.js server
    console.log("[electron] Starting Next.js server...")
    try {
      await startNextServer()
      console.log("[electron] Next.js server is ready")
    } catch (err) {
      console.error("[electron] Failed to start server:", err.message)
      dialog.showErrorBox("Startup Error", `Failed to start the web server:\n\n${err.message}`)
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
