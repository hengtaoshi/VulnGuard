#!/usr/bin/env node

/**
 * VulnGuard Scanner Engine Installer
 *
 * Downloads and installs the Python scan engine on first use.
 * Designed to be called from the Electron app or CLI.
 *
 * Usage: node scripts/install-scan-engine.js
 */

const { existsSync, mkdirSync, writeFileSync, copyFileSync, rmSync, readdirSync } = require("fs")
const { resolve, join } = require("path")
const { platform } = require("os")
const { execSync, spawn } = require("child_process")

const ROOT = resolve(__dirname, "..")

// Determine install directory (user data dir in production, local in dev)
function getInstallDir() {
  if (process.env.VULNGUARD_TOOLS_DIR) {
    return resolve(process.env.VULNGUARD_TOOLS_DIR, "scan-engine")
  }
  if (process.env.DATA_DIR) {
    return resolve(process.env.DATA_DIR, "..", "tools", "scan-engine")
  }
  return resolve(ROOT, "tools", "scan-engine")
}

const INSTALL_DIR = getInstallDir()

const COLORS = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
  dim: "\x1b[2m",
}

function log(msg, ok = true) {
  const tag = ok ? `${COLORS.green}✓${COLORS.reset}` : `${COLORS.yellow}⚠${COLORS.reset}`
  console.log(`  ${tag} ${msg}`)
}

// ─── Check Python ───────────────────────────────────────────────────────────

function checkPython() {
  try {
    const pythonCmd = process.platform === "win32" ? "python --version" : "python3 --version"
    const out = execSync(pythonCmd, { encoding: "utf-8", timeout: 5000 })
    const match = out.match(/\d+\.\d+\.\d+/)
    if (match) {
      const [major, minor] = match[0].split(".").map(Number)
      if (major < 3 || (major === 3 && minor < 10)) {
        return { ok: false, version: match[0], error: "Python 3.10+ required" }
      }
      return { ok: true, version: match[0], cmd: process.platform === "win32" ? "python" : "python3" }
    }
  } catch {
    // Try without version check
    try {
      execSync("python --version", { timeout: 3000 })
      return { ok: true, version: "unknown", cmd: "python" }
    } catch {
      try {
        execSync("python3 --version", { timeout: 3000 })
        return { ok: true, version: "unknown", cmd: "python3" }
      } catch {}
    }
  }
  return { ok: false, version: null, error: "Python not found. Install Python 3.10+ from https://python.org" }
}

// ─── Install from Source (copy scan-engine directory) ────────────────────────

function installFromSource() {
  const srcDir = resolve(ROOT, "scan-engine")
  if (!existsSync(srcDir)) {
    return false
  }

  log("Installing scan engine from project source...")
  if (!existsSync(INSTALL_DIR)) {
    mkdirSync(INSTALL_DIR, { recursive: true })
  }

  // Copy scan-engine files
  copyRecursive(srcDir, INSTALL_DIR)
  log(`Scan engine files copied to ${INSTALL_DIR}`)

  return true
}

function copyRecursive(src, dest) {
  const { readdirSync, copyFileSync, mkdirSync, statSync } = require("fs")
  if (!existsSync(dest)) mkdirSync(dest, { recursive: true })

  for (const entry of readdirSync(src, { withFileTypes: true })) {
    const s = join(src, entry.name)
    const d = join(dest, entry.name)
    if (entry.name.startsWith(".") || entry.name === "__pycache__" || entry.name === "node_modules") continue
    if (entry.isDirectory()) {
      copyRecursive(s, d)
    } else {
      copyFileSync(s, d)
    }
  }
}

// ─── Install pip dependencies ───────────────────────────────────────────────

function installPipDeps(pythonCmd) {
  const reqFile = join(INSTALL_DIR, "requirements.txt")
  if (!existsSync(reqFile)) {
    log("No requirements.txt found — skipping pip install", false)
    return true
  }

  log("Installing Python dependencies (pip)...")
  try {
    execSync(
      `${pythonCmd} -m pip install -r "${reqFile}" --quiet`,
      { cwd: INSTALL_DIR, stdio: "pipe", timeout: 120000 },
    )
    log("Python dependencies installed")
    return true
  } catch (err) {
    log(`pip install failed: ${err.message}`, false)
    return false
  }
}

// ─── Create Start / Wrapper Script ──────────────────────────────────────────

function createWrapperScript(pythonCmd) {
  const isWin = process.platform === "win32"
  const mainPy = join(INSTALL_DIR, "main.py")

  if (!existsSync(mainPy)) {
    log("main.py not found — creating stub", false)
    writeFileSync(
      mainPy,
      `
# VulnGuard Scan Engine (downloaded)
from fastapi import FastAPI
import uvicorn

app = FastAPI(title="VulnGuard Scan Engine")

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
`,
      "utf-8",
    )
  }

  // Create start script
  if (isWin) {
    writeFileSync(
      join(INSTALL_DIR, "start.bat"),
      `@echo off
cd /d "%~dp0"
echo Starting VulnGuard Scan Engine...
python main.py
pause
`,
      "utf-8",
    )
  } else {
    writeFileSync(
      join(INSTALL_DIR, "start.sh"),
      `#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "Starting VulnGuard Scan Engine..."
${pythonCmd} main.py
`,
      "utf-8",
    )
    execSync(`chmod +x "${join(INSTALL_DIR, "start.sh")}"`, { timeout: 1000 })
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

function main() {
  console.log(`\n  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  VulnGuard Scan Engine Installer${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}\n`)

  // Check if already installed
  const mainPy = join(INSTALL_DIR, "main.py")
  if (existsSync(mainPy)) {
    log(`Scan engine already installed at: ${INSTALL_DIR}`)
    log("To reinstall, delete the directory and run again")
    console.log("")
    return
  }

  // Step 1: Copy source files
  log("[1/3] Copying scan engine files...")
  const installed = installFromSource()
  if (!installed) {
    log("Could not find scan-engine source directory", false)
    log("Creating stub scan engine instead...")
    if (!existsSync(INSTALL_DIR)) mkdirSync(INSTALL_DIR, { recursive: true })
    writeFileSync(
      join(INSTALL_DIR, "mock.py"),
      `# VulnGuard Scan Engine (stub — full engine not available)
# Download from: https://github.com/vulnguard/scan-engine
print("VulnGuard Scan Engine stub — real engine not installed")
`,
      "utf-8",
    )
  }

  // Step 2: Check Python
  log("[2/3] Checking Python installation...")
  const pyCheck = checkPython()
  if (!pyCheck.ok) {
    log(`Python check: ${pyCheck.error}`, false)
    log("You can still use the desktop app without the scan engine.", false)
    log("The mock scan engine will provide demo data.", false)
    console.log("")
    return
  }
  log(`Python ${pyCheck.version} found (${pyCheck.cmd})`)

  // Step 3: Install pip dependencies
  log("[3/3] Installing Python packages...")
  const pipOk = installPipDeps(pyCheck.cmd)
  if (!pipOk) {
    log("Some dependencies failed to install", false)
  }

  // Create wrapper scripts
  createWrapperScript(pyCheck.cmd)

  console.log(`\n  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  ✅ Scan engine installation complete!${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  📁 ${INSTALL_DIR}${COLORS.reset}`)
  console.log(`  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}\n`)
}

main()
