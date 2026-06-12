#!/usr/bin/env node

/**
 * VulnGuard Release Builder
 * Usage: node scripts/build-release.js
 *
 * Builds a standalone release package with:
 * - Next.js standalone build
 * - All scanner binaries
 * - NVD database
 * - Start scripts for Windows/Linux/macOS
 *
 * Output: vulnguard-v{version}-{platform}-{arch}.zip
 */

const { execSync } = require("child_process")
const { existsSync, copyFileSync, cpSync, mkdirSync, readdirSync, writeFileSync, rmSync } = require("fs")
const { join } = require("path")
const { platform, arch } = require("os")

// ─── Paths ──────────────────────────────────────────────────────────────

const ROOT = join(__dirname, "..")
const NVD_DATA = join(ROOT, "..", ".nvd-cache")
const pkg = require(join(ROOT, "package.json"))
const VERSION = process.env.RELEASE_VERSION || pkg.version
const RELEASE_DIR = join(ROOT, `vulnguard-v${VERSION}`)
const APP_DIR = join(RELEASE_DIR, "vulnguard")

const COLORS = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
}

function log(msg, ok = true) {
  const tag = ok ? `${COLORS.green}✓${COLORS.reset}` : `${COLORS.yellow}⚠${COLORS.reset}`
  console.log(`  ${tag} ${msg}`)
}

function copyRecursive(src, dest, filter) {
  if (!existsSync(src)) return
  if (!existsSync(dest)) mkdirSync(dest, { recursive: true })

  for (const entry of readdirSync(src, { withFileTypes: true })) {
    const s = join(src, entry.name)
    const d = join(dest, entry.name)
    if (filter && !filter(s, entry)) continue
    if (entry.isDirectory()) {
      copyRecursive(s, d, filter)
    } else {
      copyFileSync(s, d)
    }
  }
}

// ─── Main ────────────────────────────────────────────────────────────────

function main() {
  console.log(`\n  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  VulnGuard Release Builder v${VERSION}${COLORS.reset}`)
  console.log(`  ${COLORS.cyan}════════════════════════════════════════════${COLORS.reset}\n`)

  // Clean previous
  if (existsSync(RELEASE_DIR)) {
    log("Removing old release directory...")
    rmSync(RELEASE_DIR, { recursive: true, force: true })
  }

  // ── [1/7] Build Next.js ───────────────────────────────────────────────
  log("[1/7] Building Next.js (standalone)...")
  // Pass proxy env vars to build process
  const buildEnv = { ...process.env }
  if (process.env.HTTP_PROXY) buildEnv.HTTP_PROXY = process.env.HTTP_PROXY
  if (process.env.HTTPS_PROXY) buildEnv.HTTPS_PROXY = process.env.HTTPS_PROXY
  if (process.env.http_proxy) buildEnv.http_proxy = process.env.http_proxy
  if (process.env.https_proxy) buildEnv.https_proxy = process.env.https_proxy
  execSync("npm run build", { cwd: ROOT, stdio: "pipe", timeout: 120000, env: buildEnv })

  // ── [2/7] Create directory structure ──────────────────────────────────
  log("[2/7] Creating directory structure...")
  mkdirSync(APP_DIR, { recursive: true })
  mkdirSync(join(APP_DIR, "tools", "bin"), { recursive: true })
  mkdirSync(join(APP_DIR, "tools", "dependency-check"), { recursive: true })
  mkdirSync(join(APP_DIR, ".nvd-cache", "data"), { recursive: true })
  mkdirSync(join(APP_DIR, "data", "uploads"), { recursive: true })
  mkdirSync(join(APP_DIR, ".scans"), { recursive: true })
  mkdirSync(join(APP_DIR, ".dc-report"), { recursive: true })

  // ── [3/7] Copy Next.js standalone output ──────────────────────────────
  log("[3/7] Copying Next.js standalone app...")

  // Next.js standalone output is at .next/standalone/
  const standaloneDir = join(ROOT, ".next", "standalone")
  if (!existsSync(standaloneDir)) {
    log("[3/7] Standalone output not found — build may have failed", false)
    process.exit(1)
  }

  // Copy standalone contents (server.js + .next/ + node_modules/)
  copyRecursive(standaloneDir, APP_DIR)

  // Copy .next/static/ into the standalone's .next/
  const staticDir = join(ROOT, ".next", "static")
  if (existsSync(staticDir)) {
    copyRecursive(staticDir, join(APP_DIR, ".next", "static"))
  }

  // Copy public/ assets
  if (existsSync(join(ROOT, "public"))) {
    copyRecursive(join(ROOT, "public"), join(APP_DIR, "public"))
  }

  // Copy config files needed at runtime
  copyFileSync(join(ROOT, "package.json"), join(APP_DIR, "package.json"))
  copyFileSync(join(ROOT, "next.config.mjs"), join(APP_DIR, "next.config.mjs"))

  // ── [4/7] Copy scanner binaries ────────────────────────────────────────
  log("[4/7] Copying scanner binaries...")

  // tools/bin/ — all scanner executables
  if (existsSync(join(ROOT, "tools", "bin"))) {
    copyRecursive(join(ROOT, "tools", "bin"), join(APP_DIR, "tools", "bin"), (path, entry) => {
      // Skip source zips and temporary files
      if (entry.name.endsWith(".zip") || entry.name.endsWith(".tar.gz")) return false
      return true
    })
  }

  // tools/dependency-check/ — full OWASP Dependency-Check installation
  if (existsSync(join(ROOT, "tools", "dependency-check"))) {
    copyRecursive(
      join(ROOT, "tools", "dependency-check"),
      join(APP_DIR, "tools", "dependency-check"),
      (path, entry) => {
        if (entry.name.endsWith(".zip")) return false
        return true
      }
    )
  }

  // ── [5/7] Copy NVD database ───────────────────────────────────────────
  log("[5/7] Copying NVD database...")
  if (existsSync(NVD_DATA)) {
    copyRecursive(NVD_DATA, join(RELEASE_DIR, ".nvd-cache"))
    const dbFile = join(RELEASE_DIR, ".nvd-cache", "data", "odc.mv.db")
    if (existsSync(dbFile)) {
      const size = require("fs").statSync(dbFile).size
      log(`NVD database (${(size / 1024 / 1024).toFixed(0)} MB)`)
    }
  } else {
    log("NVD database not found — run download-nvd.bat first", false)
  }

  // ── [6/7] Create config & start scripts ────────────────────────────────
  log("[6/7] Creating configuration and start scripts...")

  // .env.example
  writeFileSync(
    join(APP_DIR, ".env.example"),
    `# VulnGuard 环境配置
# 至少需要配置 DEEPSEEK_API_KEY 才能使用 AI 扫描功能

# DeepSeek API（AI 扫描和分析）
# 申请地址: https://platform.deepseek.com/api_keys
DEEPSEEK_API_KEY=your_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

# 代理（扫描器下载 NVD 更新等需要）
HTTP_PROXY=
HTTPS_PROXY=

# NVD API Key（Dependency-Check 加速，可选）
# 申请地址: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# PostgreSQL（扫描记录持久化，可选）
# DATABASE_URL=postgresql://user:password@localhost:5432/vulnguard
`
  )

  // start.bat
  writeFileSync(
    join(RELEASE_DIR, "start.bat"),
    `@echo off
title VulnGuard Security Scanner v${VERSION}
cd /d "%~dp0vulnguard"

echo.
echo  ════════════════════════════════════════
echo   VulnGuard Security Scanner v${VERSION}
echo  ════════════════════════════════════════
echo.

:: Check Node.js
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Node.js is not installed.
    echo  Please install Node.js 18+ from: https://nodejs.org/
    pause
    exit /b 1
)

:: Copy .env.example to .env.local if not exists
if not exist ".env.local" (
    if exist ".env.example" (
        copy ".env.example" ".env.local" >nul
        echo  [INFO] Created .env.local from .env.example
        echo        Edit it to add your DeepSeek API Key
        echo.
    )
)

echo  Starting server...
echo  Open http://localhost:3000 in your browser
echo  Press Ctrl+C to stop
echo.

node server.js
pause
`
  )

  // start.sh
  writeFileSync(
    join(RELEASE_DIR, "start.sh"),
    `#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "$0")/vulnguard" && pwd)"
cd "$DIR"

echo ""
echo "  ════════════════════════════════════════"
echo "   VulnGuard Security Scanner v${VERSION}"
echo "  ════════════════════════════════════════"
echo ""

# Check Node.js
if ! command -v node &>/dev/null; then
    echo "  [ERROR] Node.js is not installed."
    echo "  Please install Node.js 18+ from: https://nodejs.org/"
    exit 1
fi

# Copy .env.example to .env.local if not exists
if [ ! -f ".env.local" ] && [ -f ".env.example" ]; then
    cp .env.example .env.local
    echo "  [INFO] Created .env.local from .env.example"
    echo "        Edit it to add your DeepSeek API Key"
    echo ""
fi

echo "  Starting server..."
echo "  Open http://localhost:3000 in your browser"
echo "  Press Ctrl+C to stop"
echo ""

node server.js
`
  )

  // README.md
  writeFileSync(
    join(RELEASE_DIR, "README.md"),
    `# VulnGuard v${VERSION}

Security vulnerability scanner — SAST, SCA, secret detection, AI-powered reporting.

## Quick Start

### Requirements
- **Node.js 18+** (required)
- **Python 3.8+** (for Semgrep, Bandit, Checkov — optional)
- **Java 8+** (for Dependency-Check — optional)

### Windows
1. Extract this archive
2. Double-click \`start.bat\`
3. Open http://localhost:3000

### Linux / macOS
\`\`\`bash
chmod +x start.sh
./start.sh
\`\`\`

### First-Time Setup
1. Edit \`vulnguard/.env.local\` — add your **DeepSeek API Key**
2. Get a free key: https://platform.deepseek.com/api_keys
3. For NVD database updates: \`vulnguard\\download-nvd.bat\`

## Included Scanners

| Scanner | Type | Requires |
|---------|------|----------|
| Gitleaks | Secrets | — |
| Trivy | OS / filesystem CVEs | — |
| Nuclei | Template-based vulns | — |
| Semgrep | Multi-language SAST | Python |
| Bandit | Python SAST | Python |
| Checkov | IaC security | Python |
| Dependency-Check | SCA (Java/Go/Rust/…) | Java 8+ |
| npm-audit | JS/TS deps | npm |
| pip-audit | Python deps | Python |
| CodeQL | Semantic analysis | — |
| OSV-Scanner | Multi-ecosystem CVEs | — |

## Configuration

Edit \`vulnguard/.env.local\`:

\`\`\`
DEEPSEEK_API_KEY=sk-...     # Required for AI features
DEEPSEEK_MODEL=deepseek-chat # Optional
HTTP_PROXY=...               # Proxy for updates
\`\`\`

## Project

Source code: https://gitee.com/hengtaoshi/vuln-guard
`
  )

  // ── [7/7] Package ──────────────────────────────────────────────────────
  log("[7/7] Packaging release archive...")
  const zipName = join(ROOT, `vulnguard-v${VERSION}-${platform()}-${arch()}.zip`)

  if (existsSync(zipName)) rmSync(zipName, { force: true })

  // Use tar on Windows (built-in since Win10) to create .tar.gz
  // Or use zip if available
  try {
    execSync(
      `tar -czf "${zipName}" -C "${ROOT}" "vulnguard-v${VERSION}"`,
      { stdio: "pipe", timeout: 180000 }
    )
  } catch {
    // Fallback: try PowerShell Compress-Archive
    execSync(
      `powershell -Command "Compress-Archive -Path '${RELEASE_DIR}' -DestinationPath '${zipName}' -Force"`,
      { stdio: "pipe", timeout: 180000 }
    )
  }

  const size = existsSync(zipName) ? require("fs").statSync(zipName).size : 0

  console.log(`\n  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}`)
  console.log(`  ${COLORS.green}  ✅ Release built successfully!${COLORS.reset}`)
  console.log(`  ${COLORS.dim}  📦 ${zipName}${COLORS.reset}`)
  if (size > 0) {
    console.log(`  ${COLORS.dim}  Size: ${(size / 1024 / 1024).toFixed(0)} MB${COLORS.reset}`)
  }
  console.log(`  ${COLORS.dim}  📁 ${RELEASE_DIR}/${COLORS.reset}`)
  console.log(`  ${COLORS.green}════════════════════════════════════════════${COLORS.reset}\n`)
}

main()
