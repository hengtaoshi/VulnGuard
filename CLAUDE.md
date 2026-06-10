# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev       # Start Next.js dev server on port 3000
npm run build     # Production build (standalone output)
npm run test      # Run all tests (vitest)
npm run test:watch # Watch mode tests
npm run lint      # next lint
npx tsc --noEmit  # TypeScript type-check without building
```

## Project Overview

VulnGuard is a security vulnerability scanner with 27 built-in scanners, AI-driven orchestration via DeepSeek, and a bilingual (zh/en) Next.js frontend. It supports URL (DAST/black-box) and source code (SAST/SCA) scanning modes.

## Architecture

### Scanner Engine (`src/lib/scanner/`)

Every scanner implements the `Scanner` interface with `category` as a free-form string:

```typescript
interface Scanner {
  name: string
  displayName: string
  category: string   // "sast" | "secret" | "dependency" | "filesystem" | "ai" | "dns" | "network" | "web" | "osint"
  isAvailable(): boolean
  scan(targetPath: string): Promise<ScanResult>
}
```

**27 scanners** registered in `registry.ts`, divided into implementation types:

| Type | Scanners | Availability |
|------|----------|-------------|
| Node.js native (6) | http-headers, cors-detector, form-analyzer, error-analyzer, favicon-analyzer, third-party-deps | Always available |
| Node.js native (2) | tls-analyzer, gitdumper | Always available |
| Go CLI tools (10) | ffuf, gobuster, kiterunner, httpx, subfinder, shuffledns, gau, assetfinder, waybackurls, amass | Require `.exe` in `tools/bin/` |
| Python CLI tools (3) | wafw00f, bandit, checkov | Pip-installed |
| Existing source scanners (5) | semgrep, gitleaks, npm-audit, pip-audit, trivy | Binary-dependent |
| Existing DAST (2) | nuclei, wapiti, sqlmap | Binary-dependent |
| AI scanner (1) | ai-scanner | Requires `DEEPSEEK_API_KEY` |

### Scanner Categories

- **dns**: subfinder, assetfinder, shuffledns, amass — subdomain enumeration
- **network**: nmap, tls-analyzer — port scanning, certificate analysis
- **web**: ffuf, gobuster, kiterunner, httpx, wafw00f, gitdumper, http-headers, cors-detector, form-analyzer, error-analyzer, favicon-analyzer, third-party-deps — web probing, fingerprinting, content discovery, security header analysis
- **osint**: gau, waybackurls — historical URL gathering from archives
- **sast**: semgrep, bandit — source code static analysis
- **secret**: gitleaks — hardcoded secrets detection
- **dependency**: npm-audit, pip-audit — dependency CVE scanning
- **filesystem**: checkov, trivy, nuclei, wapiti, sqlmap — IaC, OS packages, template-based CVE, DAST
- **ai**: ai-scanner — DeepSeek LLM analysis

### Execution Flow

```
POST /api/scans { target, mode, engine }
  → createSession() (writes JSON to .scans/{id}.json)
  → runCompositeScan() (background, not awaited — returns { id, status: "pending" } immediately)
```

The composite scan has 3 phases:

**Phase 1 — AI Orchestrator Planning**: `createOrchestratorPlan()` calls DeepSeek with a professional system prompt that analyzes the target across 5 steps (target analysis → scanner category selection → engine mode rules → 5-phase parallel grouping → priority adjustment). Returns a `ScanPlan` with `selectedScanners`, `parallelGroups`, `scanPriority`, and `aiReview` flag.

**Phase 2 — Scanner Execution**: `executeScannersByPlan()` runs scanners following the plan's `parallelGroups` (groups run sequentially, scanners within a group run concurrently). Progress is tracked via `updateSession()` which the frontend polls every 1s.

**Phase 3 — AI Aggregation** (optional, for "ai"/"all" engines): `aggregateScanResults()` calls DeepSeek to cross-correlate findings across all scanners, eliminate false positives, merge duplicate findings, and produce a unified report with confidence levels and priority actions. Falls back to simple dedup by `name:location:description(80chars)` if AI is unavailable.

### Engine Modes

- **`ai`**: Efficient — orchestrator selects the optimal subset of scanners based on target analysis, uses 5-phase parallel grouping for speed
- **`all`**: Full coverage — orchestrator selects all available scanners, forces AI code review, max depth priority

Both modes fall back to `runFallbackScan()` (manifest-based scanner filtering by mode) if DeepSeek is unreachable.

### Key Files

| File | Purpose |
|------|---------|
| `registry.ts` | All 27 scanner definitions with `isAvailable()` checks |
| `manifest.ts` | Scanner metadata (description, scanTypes, duration, priority, techIndicators, limitations) — drives AI orchestrator decisions |
| `orchestrator.ts` | DeepSeek-powered scan plan generator with 5-step decision prompt |
| `composite.ts` | Entry point: orchestrator → execution → aggregation, progress tracking |
| `ai-aggregator.ts` | DeepSeek-based cross-correlation and false positive elimination |
| `scan-store.ts` | File-based CRUD for scan sessions (`.scans/` or `data/scans/`) |
| `types.ts` | `Scanner`, `ScanResult`, `AggregationReport`, `AggregatedFinding`, `Confidence` |

### Data Flow

```
Frontend                         API                          Scanner Engine
───────                          ───                           ─────────────
POST /api/scans ──────────────→  createSession() ──→ .scans/{id}.json
                                  runCompositeScan() (bg)
                                    ├─ createOrchestratorPlan() → DeepSeek API
                                    ├─ executeScannersByPlan()
                                    │   ├─ dns-scanners (subfinder, amass, ...)
                                    │   ├─ web-probes (httpx, wafw00f)
                                    │   ├─ web-fuzzers (ffuf, gobuster, ...)
                                    │   ├─ http-analyzer (headers, cors, ...)
                                    │   ├─ tls-analyzer
                                    │   ├─ gitdumper
                                    │   ├─ osint-scanners (gau, waybackurls)
                                    │   └─ npmap-scan
                                    └─ aggregateScanResults() → DeepSeek API
                                  ← CompositeResult

GET /api/scans/[id] (poll 1s) ─→  readSession() ──→ progress { percent, currentScanner, eta, scannerStatuses[] }
```

### Tool Binary Management

- CLI tool `.exe` files live in `tools/bin/` and are gitignored
- Node.js native scanners have no binary dependency
- `isAvailable()` checks binary presence at scan time — missing tools are skipped gracefully
- Wordlist for fuzzers: `tools/wordlists/common.txt`

### Environment Variables

```
DEEPSEEK_API_KEY=sk-...   # Required for AI scanner + orchestrator + aggregation
DEEPSEEK_BASE_URL=...     # Optional, default https://api.deekseek.com
DEEPSEEK_MODEL=...        # Optional, default deepseek-v4-flash
HTTP_PROXY=...            # For Go tool downloads
```

### Frontend

- Pages: `/` (dashboard), `/scan/new`, `/scan/[id]` (detail + progress polling), `/scan/history`, `/reports`, `/settings`
- UI: shadcn/ui components in `src/components/ui/`, layout in `src/components/layout/`
- State: React Query (`@tanstack/react-query`)
- i18n: Custom context-based system in `src/lib/i18n/`, defaults to Chinese with English fallback
- Charts: Recharts for dashboard trend visualization
