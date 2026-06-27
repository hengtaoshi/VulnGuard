# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Start

```bash
git clone <repo-url>
cd vulnguard
npm install         # Install Node.js dependencies
npm run setup       # Auto-download scanner binaries + Python packages
npm run dev         # Start dev server at http://localhost:3000
```

## Versioning

Follow SemVer (`MAJOR.MINOR.PATCH`):
- **Major**: Breaking API / architecture changes
- **Minor**: New features, pages, UI refactors (backward-compatible)
- **Patch**: Bug fixes, perf improvements (backward-compatible)
- Never overwrite a published release. Each release = one Git tag (`vX.Y.Z`).

## Commands

```bash
npm run setup      # Install all scanner dependencies (pip & binary downloads)
npm run dev        # Start Next.js dev server on port 3000
npm run build      # Production build (standalone output)
npm run test       # Run all tests (vitest)
npm run lint       # next lint
npx tsc --noEmit   # TypeScript type-check without building
```

## Project Overview

VulnGuard is a **source code security vulnerability scanner** with 9 built-in scanners, AI-driven orchestration via DeepSeek, and a bilingual (zh/en) Next.js frontend. It exclusively supports source code (SAST/SCA) scanning — URL/DAST scanning has been removed.

## Architecture

### Scanner Engine (`src/lib/scanner/`)

Every scanner implements the `Scanner` interface with `category` as a free-form string:

```typescript
interface Scanner {
  name: string
  displayName: string
  category: string   // "sast" | "secret" | "dependency" | "filesystem" | "ai"
  isAvailable(): boolean
  scan(targetPath: string): Promise<ScanResult>
}
```

**10 scanners** registered in `registry.ts`:

| Scanner | Category | Type | Availability |
|---------|----------|------|-------------|
| semgrep | sast | Multi-language SAST | Binary (`semgrep.exe`) |
| bandit | sast | Python SAST | Pip-installed |
| gitleaks | secret | Secret detection | Binary (`gitleaks.exe`) |
| npm-audit | dependency | JS/TS dependency audit | Requires `npm` |
| pip-audit | dependency | Python dependency audit | Pip-installed |
| dependency-check | dependency | Java/Maven/Gradle/Go/Rust SCA | Requires Java 8+ (tools/bin/) |
| trivy | filesystem | OS/pkg/IoC CVE scan | Binary (`trivy.exe`) |
| checkov | filesystem | IaC security scan | Pip-installed |
| nuclei | filesystem | Template-based vuln scan | Binary (`nuclei.exe`) |
| ai-scanner | ai | DeepSeek LLM code audit | Requires `DEEPSEEK_API_KEY` |

### Scanner Categories

- **sast**: semgrep, bandit — source code static analysis
- **secret**: gitleaks — hardcoded secrets detection
- **dependency**: npm-audit, pip-audit, dependency-check — dependency CVE scanning
- **filesystem**: checkov, trivy, nuclei — IaC, OS packages, template-based CVE
- **ai**: ai-scanner — DeepSeek LLM analysis

### Execution Flow

```
POST /api/scans { target, mode, engine }
  → createSession() (writes JSON to .scans/{id}.json)
  → runCompositeScan() (background, not awaited — returns { id, status: "pending" } immediately)
```

The composite scan has 3 phases:

**Phase 1 — AI Orchestrator Planning**: `createOrchestratorPlan()` calls DeepSeek with a system prompt that analyzes the target across 5 steps (target analysis → scanner category selection → engine mode rules → 3-phase parallel grouping → priority adjustment). Returns a `ScanPlan` with `selectedScanners`, `parallelGroups`, `scanPriority`, and `aiReview` flag.

**Phase 2 — Scanner Execution**: `executeScannersByPlan()` runs scanners following the plan's `parallelGroups` (groups run sequentially, scanners within a group run concurrently). Progress is tracked via `updateSession()` which the frontend polls every 1s.

**Phase 3 — AI Aggregation** (optional, for "ai"/"all" engines): `aggregateScanResults()` calls DeepSeek to cross-correlate findings across all scanners, eliminate false positives, merge duplicate findings, and produce a unified report with confidence levels and priority actions. Falls back to simple dedup by `name:location:description(80chars)` if AI is unavailable.

### Engine Modes

- **`ai`**: Efficient — orchestrator selects the optimal subset of scanners based on target analysis, uses 3-phase parallel grouping for speed
- **`all`**: Full coverage — orchestrator selects all available scanners, forces AI code review, max depth priority

Both modes fall back to `runFallbackScan()` (manifest-based scanner filtering by mode) if DeepSeek is unreachable.

### Key Files

| File | Purpose |
|------|---------|
| `registry.ts` | All 9 scanner definitions with `isAvailable()` checks |
| `manifest.ts` | Scanner metadata — drives AI orchestrator decisions |
| `orchestrator.ts` | DeepSeek-powered scan plan generator with source-code-focused decision prompt |
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
                                    │   ├─ Phase 1: gitleaks, npm-audit, pip-audit, bandit
                                    │   ├─ Phase 2: semgrep, trivy, checkov, nuclei
                                    │   └─ Phase 3: ai-scanner
                                    └─ aggregateScanResults() → DeepSeek API
                                  ← CompositeResult

GET /api/scans/[id] (poll 1s) ─→  readSession() ──→ progress { percent, currentScanner, eta, scannerStatuses[] }
```

### Environment Variables

```
DEEPSEEK_API_KEY=sk-...   # Required for AI scanner + orchestrator + aggregation
DEEPSEEK_BASE_URL=...     # Optional, default https://api.deepseek.com
DEEPSEEK_MODEL=...        # Optional, default deepseek-v4-flash
```

### Frontend

- Pages: `/` (dashboard), `/scan/new`, `/scan/[id]` (detail + progress polling), `/scan/history`, `/reports`, `/settings`
- UI: shadcn/ui components in `src/components/ui/`, layout in `src/components/layout/`
- State: React Query (`@tanstack/react-query`)
- i18n: Custom context-based system in `src/lib/i18n/`, defaults to Chinese with English fallback
- Charts: Recharts for dashboard trend visualization
