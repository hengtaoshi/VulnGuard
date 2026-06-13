<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16.2-black?logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/TypeScript-5.9-blue?logo=typescript" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Tailwind_CSS-3.4-06B6D4?logo=tailwindcss" alt="Tailwind CSS" />
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License" />
</p>

# VulnGuard

**AI-Orchestrated Source Code Security Vulnerability Scanner**

VulnGuard 是一个由 AI 编排的多引擎源代码安全漏洞扫描平台。它集成 10+ 个业界领先的扫描器，通过 DeepSeek AI 智能选择扫描策略、聚合分析结果，并消除误报。

> English | [中文](#中文)

---

## Features

- 🤖 **AI Orchestrated** — DeepSeek 分析目标代码结构，自动选择最优扫描器组合与并行策略
- 🔬 **10+ Built-in Scanners** — 覆盖 SAST、Secret 检测、SCA 依赖扫描、IaC 安全、文件系统 CVE
- 🧠 **AI False Positive Elimination** — 跨扫描器关联分析，自动合并重复、标记误报
- ⚡ **Parallel Execution** — 三级并行分组（fast/medium/slow），最大化扫描效率
- 🌐 **Bilingual (zh/en)** — 中英双语界面与漏洞描述
- 📊 **Rich Reports** — 一键生成 PDF 安全报告，支持漏洞分类、风险评分、修复建议
- 🔌 **Extensible** — 实现 `Scanner` 接口即可添加新扫描器

## Architecture

```
User Upload / Path Input
        │
        ▼
  ┌─────────────┐
  │  Target      │  File type detection, language identification,
  │  Analysis    │  framework recognition (React/Vue/Django...)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │  AI         │  DeepSeek selects scanners, plans parallel groups,
  │  Planner    │  sets priority (speed / depth)
  └──────┬──────┘
         │
         ▼
  ┌──────────────────────────────────┐
  │  Phase 1: Fast (parallel)        │
  │  ├─ gitleaks (secret detection)   │
  │  └─ semgrep (pattern SAST)       │
  ├──────────────────────────────────┤
  │  Phase 2: Medium (parallel)      │
  │  ├─ bandit (Python SAST)         │
  │  ├─ npm-audit / pip-audit        │
  │  └─ dependency-check / osv       │
  ├──────────────────────────────────┤
  │  Phase 3: Slow (parallel)        │
  │  ├─ codeql (semantic analysis)   │
  │  ├─ trivy (OS/pkg CVE)          │
  │  └─ nuclei (template vuln scan) │
  └──────────────┬───────────────────┘
                 │
                 ▼
  ┌─────────────────┐
  │  AI Aggregator  │  Cross-correlate findings,
  │                 │  remove false positives,
  │                 │  generate unified report
  └─────────────────┘
```

## Scanner Inventory

| Scanner | Category | Description |
|---------|----------|-------------|
| **Semgrep** | SAST | Multi-language pattern-based static analysis |
| **CodeQL** | SAST | GitHub's semantic code analysis engine |
| **Bandit** | SAST | Python AST-based security linter |
| **Gitleaks** | Secret | Hardcoded credentials & secret detection |
| **Trivy** | Filesystem | OS package & dependency CVE scanner |
| **Checkov** | Filesystem | Infrastructure-as-Code security scan |
| **Nuclei** | Filesystem | Template-based vulnerability scanner |
| **npm audit** | Dependency | JavaScript/TypeScript dependency audit |
| **pip-audit** | Dependency | Python dependency vulnerability audit |
| **Dependency-Check** | Dependency | OWASP dependency scanner (Java/Go/Rust/C#) |
| **OSV-Scanner** | Dependency | Multi-ecosystem open source vulnerability scanner |
| **CVE-CPP** | Dependency | C/C++ Conan/vcpkg CVE scanner |
| **TruffleHog** | Secret | Deep secret scanning with multiple detectors |

## Quick Start

### Prerequisites

- **Node.js** >= 18
- **Python** >= 3.8 (for bandit, pip-audit, checkov)
- **Java** >= 8 (for Dependency-Check)
- **Git** (for CodeQL pack management)

### Installation

```bash
# Clone the repository
git clone https://github.com/hengtaoshi/VulnGuard.git
cd VulnGuard

# Install Node.js dependencies
npm install

# Download & install scanner binaries and Python packages
npm run setup
```

### Configuration (Required)

> ⚠️ **You must configure at least `DEEPSEEK_API_KEY`** for AI orchestration to work.
> Get one for free at [platform.deepseek.com](https://platform.deepseek.com/) → API Keys.

```bash
# 1. Copy the template
cp .env.example .env.local

# 2. Edit .env.local and replace the placeholder
#    DEEPSEEK_API_KEY=your_deepseek_api_key_here
#    ↓
#    DEEPSEEK_API_KEY=sk-your_actual_key_here
```

| Variable | Required | Description |
|----------|----------|-------------|
| `DEEPSEEK_API_KEY` | ✅ | DeepSeek API key ([get one here](https://platform.deepseek.com/)) |
| `DEEPSEEK_BASE_URL` | ❌ | Custom API endpoint (default: `https://api.deepseek.com`) |
| `DEEPSEEK_MODEL` | ❌ | Model name (default: `deepseek-chat`) |
| `DATABASE_URL` | ❌ | PostgreSQL connection (optional, for scan persistence) |
| `SCAN_AUTH_TOKEN` | ❌ | API authentication token (optional, for production) |

### Development

```bash
# Start dev server
npm run dev

# Open http://localhost:3000
```

### Production Build

```bash
npm run build
npm start
```

## Usage

1. **Open** http://localhost:3000
2. **Upload** your source code directory (drag & drop or select folder)
3. **Select engine**: `AI` (intelligent scanner selection) or `Full` (all scanners)
4. **Review findings** — categorized by severity, with AI-generated remediation
5. **Export** as PDF report

## Environment Variables

Full reference:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEEPSEEK_API_KEY` | — | DeepSeek API key |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Custom API base URL |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model identifier |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `SCAN_AUTH_TOKEN` | — | Bearer token for API protection |
| `HTTP_PROXY` | — | Proxy for scanner binary downloads |
| `HTTPS_PROXY` | — | HTTPS proxy for scanner binary downloads |

> **Note**: Without `DEEPSEEK_API_KEY`, the AI orchestrator and aggregator will fall back to rule-based scanner selection and simple deduplication. All scanners still work independently.

## Tech Stack

- **Framework**: [Next.js](https://nextjs.org/) 16 (App Router + Turbopack)
- **Language**: [TypeScript](https://www.typescriptlang.org/) 5.9
- **Styling**: [Tailwind CSS](https://tailwindcss.com/) 3.4 + shadcn/ui
- **Charts**: [Recharts](https://recharts.org/)
- **PDF**: [jsPDF](https://github.com/parallax/jsPDF) + [html2canvas](https://html2canvas.hertzen.com/)
- **State**: [TanStack React Query](https://tanstack.com/query/latest)
- **AI**: [DeepSeek API](https://platform.deepseek.com/)
- **Icons**: [Lucide](https://lucide.dev/)

## License

[MIT](LICENSE)

---

## 中文

### 简介

VulnGuard 是一个由 AI 编排的多引擎源代码安全漏洞扫描平台。上传源码目录，系统自动分析项目结构、选择最合适的扫描器组合，并在扫描完成后提供 AI 聚合分析报告。

### 核心功能

| 功能 | 说明 |
|------|------|
| 🤖 AI 智能编排 | DeepSeek 分析目标代码 → 自动选择扫描器 + 规划并行策略 |
| 🔬 10+ 内置扫描器 | 涵盖 SAST、密钥检测、SCA 依赖扫描、IaC、文件系统 CVE |
| 🧠 误报消除 | AI 跨扫描器关联分析，自动去重、标记误报 |
| ⚡ 并行执行 | 三级并行分组，最大化扫描速度 |
| 🌐 中英双语 | 界面与漏洞描述支持中文 / English 切换 |
| 📊 报告导出 | 一键生成 PDF，含漏洞详情、风险评分、修复建议 |

### 快速开始

```bash
# 克隆
git clone https://github.com/hengtaoshi/VulnGuard.git
cd VulnGuard

# 安装依赖 & 扫描器
npm install
npm run setup

# 配置 API Key
cp .env.example .env.local
# 编辑 .env.local，把 DEEPSEEK_API_KEY 替换为你的真实密钥
# 申请地址: https://platform.deepseek.com/

# 启动
npm run dev
```

浏览器打开 **http://localhost:3000**，上传源码目录即可开始扫描。
