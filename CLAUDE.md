# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Start

```bash
npm install                  # Node.js dependencies
npm run setup                # Download scanner binaries + pip packages
npm run dev                  # Next.js dev server at http://localhost:3000
npm run dev:electron         # Electron + Next.js dev together
npm test                     # Vitest tests
npx tsc --noEmit             # TypeScript check
npm run lint                 # ESLint (electron/ only)
npm run build                # Next.js production build (standalone)
npm run build:electron       # Full Electron + Next.js build
```

> ⚠️ **Node.js 24 fails** — Next.js 16.2.9 has a prerender bug on Node.js 24 (`/_global-error`). Use Node.js 22 for production builds.

**Local build** (without CI):
```bash
npm run build                  # Next.js production build
node scripts/build-electron.js --win  # Electron + NSIS installer
```

## Testing

```bash
npm test                       # All Vitest tests
npx vitest run                 # Single run
npx vitest                     # Watch mode
```

Tests are in `src/` co-located with source files (`*.test.ts`). No Playwright E2E tests yet.

## Versioning & Release

SemVer (`MAJOR.MINOR.PATCH`). Release workflow (strict order):

1. Update `version` in `package.json`
2. `git commit -m "build: bump version to x.y.z"`
3. `git push origin master`
4. `git tag vX.Y.Z`
5. `git push origin vX.Y.Z`
6. CI builds and uploads to GitHub Releases

⛔ Never push a tag before the version bump commit — CI reads `package.json` from the tagged commit.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Electron Desktop Shell                 │
│  electron/main.js — forks Next.js standalone + auto-updater│
│  electron/preload.js — contextBridge IPC API             │
│  electron/scanner-downloader.js — 1.6GB archive DL/extract│
└────────────────────┬────────────────────────────────────┘
                     │ http://localhost:{port}
┌────────────────────▼────────────────────────────────────┐
│               Next.js App (App Router)                   │
│  src/app/page.tsx            — Dashboard + trend charts  │
│  src/app/scan/new/page.tsx   — Upload + scan config      │
│  src/app/scan/[id]/page.tsx  — Progress + results        │
│  src/app/scan/history/       — Scan history + baseline   │
│  src/app/reports/page.tsx    — HTML/SARIF/SBOM reports   │
│  src/app/settings/page.tsx   — All settings              │
│  src/app/scanners/page.tsx   — Scanner management + setup│
│  src/app/api/scans/          — Scan CRUD API             │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│               Scanner Engine (src/lib/scanner/)           │
│  composite.ts      — Main orchestrator (5 phases)        │
│  registry.ts       — 15 scanner definitions + availability│
│  orchestrator.ts   — DeepSeek scan plan generator        │
│  ai-aggregator.ts  — Cross-correlation + FP elimination  │
│  target-analyzer.ts— Language/framework detection        │
│  reachability.ts   — Dependency reachability analysis    │
│  baseline.ts       — Scan-to-scan regression comparison  │
│  scan-store.ts     — File-based session persistence      │
│  scan-log.ts       — Structured activity log             │
│  *.ts              — Individual scanner implementations  │
└─────────────────────────────────────────────────────────┘
```

### Scanner Engine — 5-Phase Scan Flow

```
POST /api/scans → createSession() → runCompositeScan() (background)

Phase 1: Target Analysis
  analyseTarget() — detect langs, frameworks, config files, file count

Phase 2: Scanner Selection
  AI mode: orchestrator.ts → DeepSeek → ScanPlan
  Falls back to selectScannersByRules() (language-based rule engine)

Phase 3: Scanner Execution
  3 parallel groups (sequential groups, concurrent within group):
    Fast:   gitleaks, semgrep               (~8s)
    Medium: bandit, checkov, pip-audit, ... (~90s)
    Slow:   codeql, trivy, nuclei           (~120s)
  Progress saved to session JSON — frontend polls every 1s

Phase 4: Dedup + Translation
  Dedup by name:location:description(80chars)
  translateVulnerabilities() — 526+ Chinese rules
  filterIgnored() — .vulnguard-ignore patterns
  AI aggregation (optional) — deepseek cross-correlation

Phase 5: SBOM + Webhook
  Trivy CycloneDX SBOM → .scans/sbom/{id}.cdx.json
  Webhook notification (if configured)
```

### Scanners (15 registered)

| Scanner | Category | Type | Notes |
|---------|----------|------|-------|
| semgrep | sast | Binary | 2000+ rules |
| bandit | sast | pip-installed | Python AST |
| codeql | sast | Binary | GitHub semantic analysis, 104+ queries |
| gitleaks | secret | Binary | Git history scanning |
| trufflehog | secret | Binary | 800+ detectors |
| npm-audit | dependency | npm | Requires `npm` in PATH |
| pip-audit | dependency | pip-installed | Python dependencies |
| dependency-check | dependency | Java | OWASP SCA, requires Java 8+ |
| osv-scanner | dependency | Binary | Google multi-ecosystem |
| cve-cpp | dependency | Built-in | C/C++ Conan/vcpkg (OSV.dev API) |
| swift | dependency | Built-in | Swift Package (OSV.dev API) |
| trivy | filesystem | Binary | OS packages + file system |
| checkov | filesystem | pip-installed | IaC (Terraform/K8s/Docker) |
| nuclei | filesystem | Binary | Template-based |
| scorecard | sast | Binary | OpenSSF security practices |

**Availability logic** (`registry.ts`):
- Bundled scanners check `.archive-extracted` marker + binary existence
- pip-installed ones check `where` (system PATH) → fall back to bundled exe
- Built-in ones (cve-cpp, swift) are always available

### Scanner Archive

All bundled scanners ship as a single `scanners.tar.gz` (v0.6.5, ~1.6 GB):
- **Download**: `electron/scanner-downloader.js` → `%APPDATA%/VulnGuard/tools/`
- **Extraction**: `tar -xzf` with path traversal protection
- **Marker file**: `.archive-extracted` written after successful extraction
- **Auto-download**: via `npm run setup` or in-app installer wizard (`setup-wizard.tsx`)
- **Note**: `pip-audit.exe` and `checkov.exe` in the archive are known broken (PyInstaller issues) — use pip-installed versions instead

### Electron Desktop Shell (`electron/`)

- `main.js` — forks Next.js standalone server, creates BrowserWindow, auto-updater
- `preload.js` — exposes `window.vulnguard.*` API (scanner download, updates, file dialogs, window controls)
- `scanner-downloader.js` — downloads + extracts scanner archive
- `splash.html` — startup loading animation (shield outline tracing), covers full window for 5s before app loads
- **User data**: `app.getPath("userData")` — `%APPDATA%/VulnGuard`
- **Tools dir**: `{userData}/tools/bin/` — scanner binaries
- **Scan data**: `{userData}/scans/` or `{userData}/data/scans/`
- **NVD cache**: `{userData}/.nvd-cache/data/` — Dependency-Check DB
- **Auto-updater**: `electron-updater` with GitHub provider, checks 5s after ready-to-show

**Custom title bar**: `frame: false` in BrowserWindow. TitleBar React component (`src/components/layout/titlebar.tsx`) handles window drag + min/max/close buttons via IPC (`window-minimize`, `window-maximize`, `window-close`).

**PDF export**: Uses Electron's `webContents.printToPDF()` via IPC (`download-pdf` handler in main.js). No browser popup needed — generates PDF directly and shows system save dialog. Falls back to opening HTML print view in web mode.

**DeepSeek Key injection**: Electron main.js reads `deepseekApiKey` from `settings.json` at startup and passes it as `DEEPSEEK_API_KEY` environment variable to the forked Next.js server. This ensures the `/api/llm/analyze` route always has access to the API key regardless of settings-store file path resolution.

### Key Data Paths

| Path | Purpose |
|------|---------|
| `VULNGUARD_DATA_DIR` or `userData` | Base for all runtime data |
| `{base}/tools/` | Scanner binaries + archives |
| `{base}/tools/.archive-extracted` | Marker: scanners installed |
| `{base}/scans/` | Scan session JSON files |
| `{base}/.nvd-cache/data/` | Dependency-Check NVD DB |
| `{base}/settings.json` | App settings (proxy, API key, etc.) |
| `.scans/` | Dev-mode session data (cwd) |
| `.dc-report/` | Dependency-Check JSON report output |
| `.scans/sbom/` | CycloneDX SBOM files |
| `.scans/ignore-rules.json` | User-defined suppress rules |

### Environment Variables

```
DEEPSEEK_API_KEY=sk-...         # Required for AI features
DEEPSEEK_BASE_URL=...           # Default https://api.deepseek.com
DEEPSEEK_MODEL=...              # Default deepseek-v4-flash
VULNGUARD_DATA_DIR=...          # Override data/tools root
SCAN_AUTH_TOKEN=...             # API Bearer token for production
HTTP_PROXY / HTTPS_PROXY        # Proxy for scanner download / updates
NVD_API_KEY=...                 # NVD API key (optional, for Dependency-Check)
```

## Important Architecture Details

**Scanner binary resolution** (`paths.ts`):
- `TOOLS_DIR` = `VULNGUARD_DATA_DIR/tools` or `userData/tools` (Electron) or `cwd/tools` (dev)
- `TOOLS_BIN` = `TOOLS_DIR/bin`
- pip-installed scanners (bandit, pip-audit, checkov) resolve via `where` command → fall back to bundled exe

**Settings persistence** (`settings-store.ts`):
- JSON file at `{base}/settings.json`
- API keys masked as `__MASKED__sk-a****789` in API responses
- Defaults in `DEFAULT_SETTINGS` constant

**Scan session storage** (`scan-store.ts`):
- JSON files in `{STORAGE_DIR}/{id}.json`
- `STORAGE_DIR` = `VULNGUARD_DATA_DIR/scans` or `userData/scans` or `cwd/.scans`

**Upload filtering** (`scan/new/page.tsx`):
- Excludes `.scanner-assets/` directories and `.jar` files
- 20MB file size limit on individual uploads

## Code Conventions

- TypeScript strict mode, 2-space indent
- `import type` for type-only imports
- `async/await` over `.then()`
- Functional React components with TypeScript
- npm as package manager
- Vitest for testing
- Avoid `any` — type safety first
- UI via shadcn/ui + Tailwind CSS
- i18n via custom context (`src/lib/i18n/`) — Chinese default with English fallback, 193+ keys
