#!/usr/bin/env node

/**
 * VulnGuard Desktop Build Script
 *
 * Builds the Next.js app in standalone mode, then packages with Electron.
 * Usage: node scripts/build-electron.js
 *        node scripts/build-electron.js --win    (Windows only)
 *        node scripts/build-electron.js --linux  (Linux only)
 *        node scripts/build-electron.js --mac    (macOS only)
 */

const { execSync } = require("child_process")
const { existsSync, rmSync, cpSync, mkdirSync, readFileSync, copyFileSync, readdirSync, statSync } = require("fs")
const { resolve, join } = require("path")

const ROOT = resolve(__dirname, "..")
const RELEASE_DIR = resolve(ROOT, "release")

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

function run(cmd, opts = {}) {
  execSync(cmd, { cwd: ROOT, stdio: "pipe", timeout: 1200000, ...opts })
}

// ─── Main ───────────────────────────────────────────────────────────────────

function main() {
  const target = process.argv[2] || "" // --win, --linux, --mac, or empty (all)

  console.log(`\n  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  VulnGuard Desktop Builder${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}\n`)

  // ── [1/7] Clean previous builds ──────────────────────────────────────────
  log("[1/7] Cleaning previous builds...")
  for (const dir of [".next", RELEASE_DIR]) {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  // ── [2/7] Build Next.js standalone ───────────────────────────────────────
  log("[2/7] Building Next.js (standalone)...")
  run("npm run build")

  // Verify standalone output
  const standaloneServer = resolve(ROOT, ".next", "standalone", "server.js")
  if (!existsSync(standaloneServer)) {
    log("Next.js standalone build failed — server.js not found", false)
    process.exit(1)
  }
  log("Next.js standalone build complete")

  // ── [3/7] Remove tools/ from standalone (avoids asar ENOTEMPTY on nested codeql dir) ──
  log("[3/7] Cleaning standalone artifacts...")
  const toolsDir = resolve(ROOT, ".next", "standalone", "tools")
  if (existsSync(toolsDir)) {
    rmSync(toolsDir, { recursive: true, force: true })
  }

  // ── [4/6] Setup electron-bin (ensure Electron binary is available) ──────
  log("[4/6] Setting up electron-bin directory...")
  const electronDist = resolve(ROOT, "node_modules", "electron", "dist")
  const electronBin = resolve(ROOT, "electron-bin")
  if (!existsSync(electronBin) || !existsSync(join(electronBin, "electron.exe"))) {
    if (existsSync(join(electronDist, "electron.exe"))) {
      if (!existsSync(electronBin)) mkdirSync(electronBin, { recursive: true })
      cpSync(electronDist, electronBin, { recursive: true })
      log("electron-bin copied from node_modules/electron/dist")
    } else {
      log("electron.exe not found in node_modules — running electron install.js...", false)
      try {
        run("node node_modules/electron/install.js")
        if (!existsSync(electronBin)) mkdirSync(electronBin, { recursive: true })
        cpSync(electronDist, electronBin, { recursive: true })
        log("electron-bin setup complete")
      } catch (e) {
        log(`electron install failed: ${e.message}`, false)
        log("Trying fallback: node node_modules/.bin/electron ...")
        try {
          run("node node_modules/.bin/electron --version")
          // electron.exe was found globally — use it directly
          log("electron is available via PATH")
        } catch (e2) {
          log(`FATAL: cannot find electron binary: ${e2.message}`, false)
          process.exit(1)
        }
      }
    }
  } else {
    log("electron-bin already exists, skipping")
  }

  // ── [5/7] Ensure standalone node_modules exists ─────────────────────────
  const standaloneNodeModules = resolve(ROOT, ".next", "standalone", "node_modules")
  if (!existsSync(resolve(standaloneNodeModules, "next"))) {
    log("next module missing in standalone output — copying from project root")
    const nextSrc = resolve(ROOT, "node_modules", "next")
    if (existsSync(nextSrc)) {
      cpSync(nextSrc, resolve(standaloneNodeModules, "next"), { recursive: true })
    }
  }

  // ── [6/7] Copy static assets ─────────────────────────────────────────────
  log("[6/7] Preparing static assets...")

  // Copy .next/static to standalone
  const staticSrc = resolve(ROOT, ".next", "static")
  const staticDst = resolve(ROOT, ".next", "standalone", ".next", "static")
  if (existsSync(staticSrc) && !existsSync(staticDst)) {
    cpSync(staticSrc, staticDst, { recursive: true })
  }

  // Copy public/ to standalone
  const publicSrc = resolve(ROOT, "public")
  const publicDst = resolve(ROOT, ".next", "standalone", "public")
  if (existsSync(publicSrc) && !existsSync(publicDst)) {
    cpSync(publicSrc, publicDst, { recursive: true })
  }

  // Copy package.json and next.config.mjs
  copyFileSync(resolve(ROOT, "package.json"), resolve(ROOT, ".next", "standalone", "package.json"))
  copyFileSync(resolve(ROOT, "next.config.mjs"), resolve(ROOT, ".next", "standalone", "next.config.mjs"))

  // Copy .env.example
  const envExample = resolve(ROOT, ".env.example")
  if (existsSync(envExample)) {
    copyFileSync(envExample, resolve(ROOT, ".next", "standalone", ".env.example"))
  }

  log("Static assets prepared")

  // ── [7/7] Package with Electron Builder ────────────────────────────────────
  log("[7/7] Packaging desktop application...")

  const buildCmd = target
    ? `npx electron-builder ${target} --config electron-builder.yml`
    : `npx electron-builder --config electron-builder.yml`

  try {
    // Electron-builder 打包 NSIS 可能很久，禁用超时
    execSync(buildCmd, { cwd: ROOT, stdio: "pipe" })

    // Show results
    console.log(`\n  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}`)
    console.log(`  ${COLORS.green}  ✅ Desktop build complete!${COLORS.reset}`)
    console.log(`  ${COLORS.dim}  📁 Release directory: ${RELEASE_DIR}${COLORS.reset}`)
    console.log(`  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}\n`)

    // List output files
    if (existsSync(RELEASE_DIR)) {
      for (const f of readdirSync(RELEASE_DIR)) {
        const size = statSync(resolve(RELEASE_DIR, f)).size
        console.log(`     ${COLORS.dim}${(size / 1024 / 1024).toFixed(1)} MB  ${f}${COLORS.reset}`)
      }
      console.log("")
    }
  } catch (err) {
    log(`Build failed: ${err.message}`, false)
    if (err.stderr) console.error(`  ${COLORS.red}stderr:${COLORS.reset}\n${err.stderr.toString().slice(0, 2000)}`)
    if (err.stdout) console.error(`  ${COLORS.red}stdout (last 30 lines):${COLORS.reset}`, err.stdout.toString().split("\n").slice(-30).join("\n"))
    process.exit(1)
  }
}

main()
