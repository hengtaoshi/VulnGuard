# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Dev server (port 3008)
npm run dev

# Build
npm run build

# Production start
npm run start

# Tests (vitest)
npm test                    # single run
npm run test:watch          # watch mode

# Lint
npm run lint

# Clear Next.js cache when encountering stale module errors
rm -rf .next
```

## Project Architecture

VulnGuard is a Next.js 14 security vulnerability scanner (App Router, `src/` directory).

### Scan Flow

1. **`/scan/new`** — User selects URL or source mode and enters a target
2. **`POST /api/scans`** — Creates a session (stored as JSON in `.scans/`), starts `runCompositeScan()` in background, returns immediately
3. **`/scan/[id]`** — Polls `GET /api/scans/[id]` every 1 second while scanning, displays progress bar + per-scanner status
4. When scan completes, the session is updated with results and the page shows the report

### Key Modules

- **`src/lib/scanner/`** — All scanner orchestration
  - `composite.ts` — Runs all enabled scanners, deduplicates vulnerabilities, tracks progress
  - `registry.ts` — Scanner definitions (name, category, availability check)
  - `scan-store.ts` — Persistent JSON-file-based session storage
  - `types.ts` — `Scanner`, `ScanResult` interfaces
  - Individual scanners: `semgrep.ts`, `gitleaks.ts`, `bandit.ts`, `npm-audit.ts`, `pip-audit.ts`, `trivy.ts`, `checkov.ts`, `nuclei.ts`, `wapiti.ts`, `sqlmap.ts`

- **`src/app/api/scans/`** — API routes
  - `route.ts` — `GET` (list scans), `POST` (create + background scan)
  - `[id]/route.ts` — `GET` single scan detail

- **`src/lib/api/`** — Frontend data layer
  - `types.ts` — `ScanDetail`, `Vulnerability`, `ScanProgress` etc.
  - `hooks.ts` — React Query hooks
  - `client.ts` — fetch wrappers

- **`src/components/`** — UI components (shadcn/ui style)
  - `layout/` — App shell (sidebar + header)
  - `ui/` — Primitive components

- **`src/lib/i18n/`** — Chinese/English i18n with dot-path keys (e.g., `t("scan.detail.riskScore")`)

### Scan Modes

- **URL mode**: Only runs DAST scanners (`wapiti`, `sqlmap`) sequentially to avoid interference
- **Source mode**: Runs file scanners (semgrep, gitleaks, bandit, npm/pip audit, trivy, checkov, nuclei) in batches of 4 concurrently

### Scanner Interface

Each scanner in `registry.ts` implements `{ name, displayName, category, isAvailable(), scan(targetPath) }`. The `scan()` function must return `ScanResult { vulnerabilities, totalChecks, errors, scannerName }`.

### Progress Tracking

`composite.ts` updates `updateSession(id, { progress: { percent, currentScanner, scannerStatuses } })` as each scanner runs. The frontend polls `GET /api/scans/[id]` every 1s. Progress is cleared (`{ progress: undefined }`) when the scan completes.

### Tools Directory

`tools/bin/` contains vendored binaries (gitleaks.exe, trivy.exe, nuclei.exe). `tools/semgrep-rules/` and `tools/nuclei-templates/` hold rule files. These are referenced in scanner modules via `join(CWD, "tools", ...)`.

### Windows Proxy Issue

Wapiti and SQLMap (Python tools) need `NO_PROXY=*` in their `execSync` env to bypass the Windows system proxy when scanning localhost targets.

### Style / Conventions

- `@/` path alias maps to `./src/`
- Tailwind CSS for styling (dark mode default)
- `"use client"` for interactive components, server components by default
- i18n keys in dot notation, translations in `zh.ts` / `en.ts`
