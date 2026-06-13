<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16.2-black?style=flat-square&logo=next.js" alt="Next.js">
  <img src="https://img.shields.io/badge/TypeScript-5.9-blue?style=flat-square&logo=typescript" alt="TypeScript">
  <img src="https://img.shields.io/badge/Tailwind_CSS-3.4-06B6D4?style=flat-square&logo=tailwindcss" alt="Tailwind CSS">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs Welcome">
</p>

<h1 align="center">VulnGuard · 源码安全漏洞扫描</h1>

<p align="center">
  AI 编排的多引擎源码安全漏洞扫描平台 — 10+ 内置扫描器，智能聚合分析，一键 PDF 报告<br>
  上传源码目录，自动选择最优扫描策略，精准定位安全漏洞。
</p>

<p align="center">
  <a href="#features">功能</a> ·
  <a href="#quick-start">快速开始</a> ·
  <a href="#configuration">配置</a> ·
  <a href="#development">开发</a> ·
  <a href="#scanners">扫描器</a> ·
  <a href="#architecture">架构</a>
</p>

---

## Features

<table>
  <tr>
    <td width="50%">
      <h3>🤖 AI 智能编排</h3>
      <ul>
        <li>DeepSeek 分析目标代码结构，自动选择扫描器组合</li>
        <li>三级并行策略（fast/medium/slow），最大化效率</li>
        <li>AI 聚合分析，跨扫描器关联去重，消除误报</li>
      </ul>
    </td>
    <td width="50%">
      <h3>🔬 10+ 内置扫描器</h3>
      <ul>
        <li>SAST：Semgrep、CodeQL、Bandit</li>
        <li>Secret：Gitleaks、TruffleHog</li>
        <li>SCA：npm-audit、pip-audit、Dependency-Check、OSV-Scanner</li>
        <li>文件系统：Trivy、Checkov、Nuclei</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h3>📊 可视化报告</h3>
      <ul>
        <li>漏洞按严重等级分类（Critical/High/Medium/Low）</li>
        <li>风险评分（A–F），一键导出 PDF</li>
        <li>中英文双语界面 + 漏洞描述中文注释</li>
      </ul>
    </td>
    <td>
      <h3>⚡ 开发体验</h3>
      <ul>
        <li>拖拽上传源码目录，自动过滤非源码文件</li>
        <li>实时进度推送（SSE + 轮询降级）</li>
        <li>Turbopack 极速热更新</li>
      </ul>
    </td>
  </tr>
</table>

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Framework** | Next.js 16 (App Router + Turbopack) |
| **Language** | TypeScript 5.9 |
| **Styling** | Tailwind CSS 3.4 + shadcn/ui |
| **Charts** | Recharts |
| **PDF** | jsPDF + html2canvas |
| **State** | TanStack React Query |
| **AI** | DeepSeek API |
| **Icons** | Lucide |

## Quick Start

### Prerequisites

- **Node.js** >= 18
- **Python** >= 3.8（bandit、pip-audit、checkov 需要）
- **Java** >= 8（Dependency-Check 需要）
- **Docker** & **Docker Compose**（可选，用于容器化部署）

### 1. 克隆仓库

```bash
git clone https://github.com/hengtaoshi/VulnGuard.git
cd VulnGuard
```

### 2. 安装依赖

```bash
# Node.js 依赖
npm install

# 下载扫描器二进制 & Python 包
npm run setup
```

### 3. 配置环境变量（必须）

> ⚠️ **必须配置 `DEEPSEEK_API_KEY`**，否则 AI 编排和聚合功能不可用。
> 免费申请：[platform.deepseek.com](https://platform.deepseek.com/) → API Keys

```bash
cp .env.example .env.local
```

然后编辑 `.env.local`，至少修改以下项：

| 变量 | 必须 | 说明 |
|------|------|------|
| `DEEPSEEK_API_KEY` | **是** | DeepSeek API 密钥，[点此申请](https://platform.deepseek.com/) |
| `DATABASE_URL` | 否 | PostgreSQL 连接串（可选，扫描记录持久化） |
| `SCAN_AUTH_TOKEN` | 否 | API 认证令牌（可选，生产环境建议设置） |

> 🔒 `.env.local` 已在 `.gitignore` 中，不会提交到 Git。

### 4. 启动

```bash
npm run dev
```

访问 **http://localhost:3000**

---

### 你需要关注的文件

首次使用只需关注以下 **2 个文件**：

#### 📄 `.env.local` — 配置密钥
所有 API Key 和敏感配置写在这里。模板 `.env.example` 已注释每个字段。

| 配置项 | 怎么填 |
|--------|--------|
| `DEEPSEEK_API_KEY` | DeepSeek 平台的 API Key，[申请地址](https://platform.deepseek.com/) |
| `HTTP_PROXY` / `HTTPS_PROXY` | 如果你的网络需要代理（格式 `http://127.0.0.1:7897`） |

#### ⚙️ `next.config.mjs` — 按需修改
- **上传大小限制**：默认 100MB，可在 `experimental.proxyClientMaxBodySize` 调整
- **CSP 策略**：如需接入外部 CDN，修改 `Content-Security-Policy` 头

---

## Configuration

完整环境变量参考：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DEEPSEEK_API_KEY` | — | DeepSeek API 密钥（AI 功能必需） |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | 自定义 API 端点 |
| `DEEPSEEK_MODEL` | `deepseek-chat` | 模型名称 |
| `DATABASE_URL` | — | PostgreSQL 连接串 |
| `SCAN_AUTH_TOKEN` | — | API Bearer 认证令牌 |
| `HTTP_PROXY` | — | HTTP 代理（扫描器下载用） |
| `HTTPS_PROXY` | — | HTTPS 代理 |

> **未配置 `DEEPSEEK_API_KEY` 时的行为**：AI 编排降级为规则选择，AI 聚合降级为简单去重。所有扫描器仍然独立工作。

## Development

```bash
# 开发服务器（热更新）
npm run dev

# 类型检查
npx tsc --noEmit

# 代码检查
npm run lint

# 测试
npm run test
```

### Project Structure

```
VulnGuard/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── upload/          # 文件上传 API
│   │   │   ├── scans/           # 扫描 CRUD API
│   │   │   ├── scan-progress/   # 实时进度 SSE API
│   │   │   ├── stats/           # 统计 API
│   │   │   └── llm/             # DeepSeek AI API
│   │   ├── scan/new/            # 新建扫描页
│   │   ├── scan/[id]/           # 扫描详情页
│   │   ├── scan/history/        # 扫描历史页
│   │   ├── reports/             # 报告页
│   │   └── settings/            # 设置页
│   ├── components/
│   │   ├── ui/                  # shadcn/ui 组件
│   │   ├── layout/              # 布局组件
│   │   ├── scan/                # 扫描进度组件
│   │   ├── dashboard/           # 仪表盘组件
│   │   └── report/              # 报告导出组件
│   └── lib/
│       ├── scanner/             # 扫描引擎核心
│       │   ├── composite.ts     # 主编排入口
│       │   ├── orchestrator.ts  # AI 编排器
│       │   ├── registry.ts      # 扫描器注册
│       │   ├── ai-aggregator.ts # AI 聚合分析
│       │   ├── chinese-descriptions.ts # 中文描述映射
│       │   └── *.ts             # 各扫描器实现
│       ├── api/                  # API 客户端 & 类型
│       └── i18n/                # 中英文国际化
├── tools/
│   └── bin/                     # 扫描器二进制（npm run setup 下载）
├── .env.example                 # 环境变量模板
├── next.config.mjs
└── package.json
```

## Scanners

| 扫描器 | 分类 | 说明 |
|--------|------|------|
| **Semgrep** | SAST | 多语言模式匹配静态分析 |
| **CodeQL** | SAST | GitHub 语义代码分析引擎（104 条安全查询） |
| **Bandit** | SAST | Python AST 安全检测 |
| **Gitleaks** | Secret | Git 历史密钥检测 |
| **TruffleHog** | Secret | 深度密钥扫描（多检测器） |
| **Trivy** | 文件系统 | OS 包 & 依赖 CVE 扫描 |
| **Checkov** | 文件系统 | IaC 安全配置检查 |
| **Nuclei** | 文件系统 | 模板化漏洞扫描 |
| **npm audit** | 依赖 | JS/TS npm 依赖审计 |
| **pip-audit** | 依赖 | Python pip 依赖审计 |
| **Dependency-Check** | 依赖 | OWASP SCA（Java/Go/Rust/C#） |
| **OSV-Scanner** | 依赖 | 多生态开源漏洞扫描 |
| **CVE-CPP** | 依赖 | C/C++ Conan/vcpkg CVE 扫描 |
| **Swift** | 依赖 | Swift Package 扫描 |

## Architecture

```
用户上传源码目录
        │
        ▼
┌─────────────┐
│  目标分析    │  语言检测、框架识别、文件统计
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  AI 编排    │  DeepSeek 选择扫描器 + 规划并行分组
└──────┬──────┘
       │
       ▼
┌──────────────────────────────┐
│  Phase 1: Fast（并行）       │
│  ├ gitleaks（密钥检测）       │
│  └ semgrep（模式匹配 SAST） │
├──────────────────────────────┤
│  Phase 2: Medium（并行）      │
│  ├ bandit / npm-audit        │
│  └ dependency-check / osv    │
├──────────────────────────────┤
│  Phase 3: Slow（并行）        │
│  ├ codeql（语义分析）        │
│  ├ trivy（OS CVE）           │
│  └ nuclei（模板扫描）        │
└──────────────┬───────────────┘
               │
               ▼
┌─────────────────┐
│  AI 聚合分析    │  跨扫描器关联、去重、误报消除
│                 │  生成统一报告 + 修复建议
└─────────────────┘
```

## Deployment

### Docker 部署

项目内置 Docker 支持：

```bash
docker compose up -d --build
```

服务说明：

| 服务 | 端口 | 说明 |
|------|------|------|
| PostgreSQL | 5432 | 扫描记录持久化 |
| Redis | 6379 | 扫描引擎队列 |
| Scan Engine | 8000 | Python 扫描引擎 |

### 生产构建

```bash
npm run build
npm start
```

> 生产环境建议设置 `SCAN_AUTH_TOKEN` 保护 API 端点，并配合 Nginx 反向代理 + HTTPS。

## Data Source

- 漏洞数据来源于各扫描器内置数据库（Trivy DB、NVD、GitHub Advisory、OSV.dev 等）
- NVD 数据库通过 `npm run setup` 自动同步，缓存至 `.nvd-cache/`

## License

[MIT](LICENSE)

---

<p align="center">
  Built with ❤️ for open source security
</p>
