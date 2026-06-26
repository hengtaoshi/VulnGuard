#!/usr/bin/env node

/**
 * VulnGuard Desktop Dev Launcher
 *
 * Starts Next.js dev server and Electron in parallel.
 * Usage: node scripts/dev-electron.js
 */

const { spawn } = require("child_process")
const { resolve } = require("path")

const ROOT = resolve(__dirname, "..")

console.log("")
console.log("  ════════════════════════════════════════")
console.log("   VulnGuard Desktop (Development Mode)")
console.log("  ════════════════════════════════════════")
console.log("")

// Start Next.js dev server
const nextDev = spawn("npx", ["next", "dev"], {
  cwd: ROOT,
  stdio: "pipe",
  env: { ...process.env },
  shell: true,
})

nextDev.stdout.on("data", (data) => {
  const msg = data.toString().trim()
  if (msg) console.log(`  [next] ${msg}`)
})

nextDev.stderr.on("data", (data) => {
  const msg = data.toString().trim()
  if (msg) console.log(`  [next] ${msg}`)
})

// Wait for Next.js to start, then launch Electron
let electronStarted = false

function tryStartElectron() {
  if (electronStarted) return
  electronStarted = true

  console.log("")
  console.log("  [electron] Starting Electron...")
  console.log("")

  const electron = spawn("npx", ["electron", "."], {
    cwd: ROOT,
    stdio: "inherit",
    env: { ...process.env },
    shell: true,
  })

  electron.on("close", (code) => {
    console.log(`\n  [electron] Exited with code ${code}`)
    nextDev.kill()
    process.exit(code || 0)
  })
}

// Poll for Next.js server readiness
const http = require("http")
const pollInterval = setInterval(() => {
  const req = http.get("http://localhost:3000", (res) => {
    if (res.statusCode < 500) {
      clearInterval(pollInterval)
      tryStartElectron()
    }
  })
  req.on("error", () => {})
  req.setTimeout(1000, () => req.destroy())
}, 1000)

// Safety timeout
setTimeout(() => {
  if (!electronStarted) {
    console.error("  [ERROR] Next.js dev server did not start within 60 seconds")
    nextDev.kill()
    process.exit(1)
  }
}, 60000)

process.on("SIGINT", () => {
  nextDev.kill()
  process.exit(0)
})
