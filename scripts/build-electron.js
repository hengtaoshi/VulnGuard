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
const { existsSync, rmSync } = require("fs")
const { resolve } = require("path")

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
  execSync(cmd, { cwd: ROOT, stdio: "pipe", timeout: 300000, ...opts })
}

// ─── Main ───────────────────────────────────────────────────────────────────

function main() {
  const target = process.argv[2] || "" // --win, --linux, --mac, or empty (all)

  console.log(`\n  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  VulnGuard Desktop Builder${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}\n`)

  // ── [1/4] Clean previous builds ──────────────────────────────────────────
  log("[1/4] Cleaning previous builds...")
  for (const dir of [".next", RELEASE_DIR]) {
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  // ── [2/4] Build Next.js standalone ───────────────────────────────────────
  log("[2/4] Building Next.js (standalone)...")
  run("npm run build")

  // Verify standalone output
  const standaloneServer = resolve(ROOT, ".next", "standalone", "server.js")
  if (!existsSync(standaloneServer)) {
    log("Next.js standalone build failed — server.js not found", false)
    process.exit(1)
  }
  log("Next.js standalone build complete")

  // ── [3/4] Copy static assets ─────────────────────────────────────────────
  log("[3/4] Preparing static assets...")
  const { cpSync } = require("fs")

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
  const { copyFileSync } = require("fs")
  copyFileSync(resolve(ROOT, "package.json"), resolve(ROOT, ".next", "standalone", "package.json"))
  copyFileSync(resolve(ROOT, "next.config.mjs"), resolve(ROOT, ".next", "standalone", "next.config.mjs"))

  // Copy .env.example
  const envExample = resolve(ROOT, ".env.example")
  if (existsSync(envExample)) {
    copyFileSync(envExample, resolve(ROOT, ".next", "standalone", ".env.example"))
  }

  log("Static assets prepared")

  // ── [4/4] Package with Electron Builder ──────────────────────────────────
  log("[4/4] Packaging desktop application...")

  const buildCmd = target
    ? `npx electron-builder ${target} --config electron-builder.yml`
    : `npx electron-builder --config electron-builder.yml`

  try {
    run(buildCmd)

    // Show results
    console.log(`\n  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}`)
    console.log(`  ${COLORS.green}  ✅ Desktop build complete!${COLORS.reset}`)
    console.log(`  ${COLORS.dim}  📁 Release directory: ${RELEASE_DIR}${COLORS.reset}`)
    console.log(`  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}\n`)

    // List output files
    const { readdirSync } = require("fs")
    if (existsSync(RELEASE_DIR)) {
      for (const f of readdirSync(RELEASE_DIR)) {
        const size = require("fs").statSync(resolve(RELEASE_DIR, f)).size
        console.log(`     ${COLORS.dim}${(size / 1024 / 1024).toFixed(1)} MB  ${f}${COLORS.reset}`)
      }
      console.log("")
    }
  } catch (err) {
    log(`Build failed: ${err.message}`, false)
    process.exit(1)
  }
}

main()
