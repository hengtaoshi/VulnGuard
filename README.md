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
        <li>AI 聚合分析 — 跨扫描器关联去重、误报消除、置信度评分</li>
        <li>AI 修复代码示例 — DeepSeek 为漏洞生成具体修复代码</li>
      </ul>
    </td>
    <td width="50%">
      <h3>🔬 10+ 内置扫描器</h3>
      <ul>
        <li>SAST：Semgrep、CodeQL（104+ 安全查询）、Bandit、OpenSSF Scorecard</li>
        <li>Secret：Gitleaks、TruffleHog（800+ 检测器）</li>
        <li>SCA：npm-audit、pip-audit、Dependency-Check、OSV-Scanner</li>
        <li>文件系统：Trivy、Checkov、Nuclei</li>
        <li>语言专项：C/C++ CVE Scanner、Swift Package Scanner</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h3>📊 安全仪表盘</h3>
      <ul>
        <li>趋势图表（Recharts）— 漏洞数量变化趋势</li>
        <li>风险概览卡片 — 总扫描数、漏洞发现、通过率、风险评分</li>
        <li>最近扫描列表 — 快速查看最新扫描状态</li>
      </ul>
    </td>
    <td>
      <h3>📋 扫描历史</h3>
      <ul>
        <li>搜索与筛选 — 按目标名、风险等级过滤</li>
        <li>基线对比 — 同一目标前后扫描对比，标记新增/回归漏洞</li>
        <li>详细日志 — 结构化扫描活动日志，按阶段展示</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h3>📄 报告与导出</h3>
      <ul>
        <li>HTML 报告预览 + 浏览器打印/PDF 导出</li>
        <li>SARIF 2.1.0 标准导出 — 兼容 GitHub、VSCode、SonarQube</li>
        <li>SBOM 自动生成 — CycloneDX 格式软件物料清单</li>
        <li>风险评分 A–F 六级体系</li>
      </ul>
    </td>
    <td>
      <h3>🎯 多扫描模式</h3>
      <ul>
        <li><strong>智能扫描</strong> — AI 分析目标结构，自动选择最合适的扫描器组合</li>
        <li><strong>全量扫描</strong> — 所有可用扫描器全部执行，最大化覆盖</li>
        <li>两级并行 — 扫描器内部并行 + 阶段间串行，资源可控</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h3>🚫 误报管理</h3>
      <ul>
        <li><code>.vulnguard-ignore</code> 文件（类似 .gitignore 语法，可提交仓库）</li>
        <li>Web UI 标记误报，持久化保存</li>
        <li>AI 假阳性检测 — DeepSeek 自动识别误报并标注原因</li>
        <li>可达性分析 — 判断依赖是否被实际调用，降低 SCA 误报</li>
      </ul>
    </td>
    <td>
      <h3>🌐 国际化</h3>
      <ul>
        <li>中英文双语界面，一键切换</li>
        <li>漏洞描述中文自动翻译 + 中文修复建议</li>
        <li>所有 UI 字符串完整 i18n</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>
      <h3>⚡ 开发体验</h3>
      <ul>
        <li>拖拽上传源码目录，自动过滤非源码文件（node_modules、.git等）</li>
        <li>实时进度推送（SSE + 轮询降级）</li>
        <li>Turbopack 极速热更新</li>
        <li>一键安装 — <code>npm run setup</code> 自动下载所有扫描器二进制</li>
        <li>Release 构建 — <code>npm run release</code> 全量打包</li>
      </ul>
    </td>
    <td>
      <h3>⚙️ 系统配置</h3>
      <ul>
        <li>扫描时长上限设置</li>
        <li>自动报告生成开关</li>
        <li>API 认证令牌保护</li>
        <li>Docker 一键部署</li>
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
| **Format** | SARIF 2.1.0, CycloneDX |
| **Database** | PostgreSQL (Prisma) / 文件系统存储 |

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

> **未配置 `DEEPSEEK_API_KEY` 时的行为**：AI 编排降级为规则选择，AI 聚合降级为确定性去重。所有扫描器仍然独立工作。

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

# Release 构建（全量打包）
npm run release
```

### Project Structure

```
VulnGuard/
├── src/
│   ├── app/
│   │   ├── page.tsx                    # 安全仪表盘（趋势图 + 概览）
│   │   ├── api/
│   │   │   ├── upload/          # 文件上传 API
│   │   │   ├── scans/           # 扫描 CRUD API
│   │   │   ├── scan-progress/   # 实时进度 SSE API
│   │   │   ├── stats/           # 统计 API
│   │   │   └── llm/             # DeepSeek AI API
│   │   ├── scan/new/            # 新建扫描页（拖拽上传）
│   │   ├── scan/[id]/           # 扫描详情页
│   │   ├── scan/history/        # 扫描历史页
│   │   ├── reports/             # 安全报告页
│   │   └── settings/            # 设置页
│   ├── components/
│   │   ├── ui/                  # shadcn/ui 基础组件
│   │   ├── layout/              # 布局组件（侧边栏、顶栏）
│   │   ├── scan/                # 扫描进度组件
│   │   ├── dashboard/           # 仪表盘图表组件
│   │   └── report/              # 报告导出组件（PDF下载按钮）
│   └── lib/
│       ├── scanner/             # 扫描引擎核心
│       │   ├── composite.ts     # 主编排入口
│       │   ├── orchestrator.ts  # AI 编排器
│       │   ├── registry.ts      # 扫描器注册与可用性检测
│       │   ├── manifest.ts      # 扫描器清单描述
│       │   ├── ai-aggregator.ts # AI 聚合分析（关联/去重/误报检测）
│       │   ├── target-analyzer.ts # 预扫描目标分析
│       │   ├── reachability.ts  # 依赖可达性分析
│       │   ├── baseline.ts      # 基线/回归对比
│       │   ├── chinese-descriptions.ts # 中文描述映射（526+ 规则）
│       │   ├── scan-store.ts    # 扫描会话持久化
│       │   ├── scan-log.ts     # 结构化扫描日志
│       │   └── *.ts             # 各扫描器实现
│       ├── api/                 # API 客户端 & React Query hooks
│       ├── i18n/                # 中英文国际化（193+ 翻译键）
│       ├── report-html.ts       # HTML 报告生成
│       ├── sarif-converter.ts   # SARIF 2.1.0 格式导出
│       ├── scan-utils.ts        # 工具函数
│       └── ignore-rules.ts      # 误报忽略规则管理
├── tools/
│   └── bin/                     # 扫描器二进制（npm run setup 下载）
├── .scans/                      # 扫描数据持久化目录
│   ├── sbom/                    # CycloneDX SBOM 文件
│   └── ignore-rules.json        # UI 标记的误报忽略规则
├── .nvd-cache/                  # NVD 数据库缓存
├── .env.example                 # 环境变量模板
├── next.config.mjs
└── package.json
```

## Scanners

| 扫描器 | 分类 | 说明 |
|--------|------|------|
| **Semgrep** | SAST | 多语言模式匹配静态分析，2000+ 安全规则 |
| **CodeQL** | SAST | GitHub 语义代码分析引擎，104+ 安全查询（支持 JS/TS/Python/Java/Go/C#/C++/Ruby/Swift） |
| **Bandit** | SAST | Python AST 安全检测 |
| **OpenSSF Scorecard** | SAST | 开源安全实践评分（代码审查、CI/CD、依赖更新等 8 大维度） |
| **Gitleaks** | Secret | Git 历史密钥检测 |
| **TruffleHog** | Secret | 深度密钥扫描，800+ 检测器类型 |
| **Trivy** | 文件系统 | OS 包 & 依赖 CVE 扫描 + IaC 配置检查 |
| **Checkov** | 文件系统 | IaC 安全配置检查（Terraform/K8s/Docker/CloudFormation） |
| **Nuclei** | 文件系统 | 模板化漏洞扫描，数千 YAML 模板 |
| **npm audit** | 依赖 | JS/TS npm 依赖审计 |
| **pip-audit** | 依赖 | Python pip 依赖审计 |
| **Dependency-Check** | 依赖 | OWASP SCA（Java/Go/Rust/C#/.NET/C/C++，NVD 数据库） |
| **OSV-Scanner** | 依赖 | Google 多生态开源漏洞扫描（JS/Python/Java/Go/Rust/C/C++/Ruby/PHP/Swift/.NET） |
| **CVE-CPP** | 依赖 | C/C++ Conan/vcpkg CVE 扫描（OSV.dev API） |
| **Swift** | 依赖 | Swift Package 扫描（OSV.dev API） |

所有扫描器自动检测可用性（tools/bin/ 或系统 PATH），未安装则跳过。

## Architecture

```
用户上传源码目录
        │
        ▼
┌─────────────────┐
│  目标分析器      │  语言检测、框架识别、配置文件扫描、文件统计
│ (Target Analyzer)│
└────────┬────────┘
         │ target analysis
         ▼
┌─────────────────┐
│  AI 编排 / 规则  │  DeepSeek 分析选择扫描器 + 规划并行分组
│ (Orchestrator)   │  （AI 不可用时回退规则引擎）
└────────┬────────┘
         │ scan plan
         ▼
┌──────────────────────────────────────┐
│  Phase 1: Fast（并行）                │
│  ├ gitleaks / trufflehog（密钥检测）  │
│  └ semgrep（模式匹配 SAST）           │
├──────────────────────────────────────┤
│  Phase 2: Medium（并行）               │
│  ├ bandit / npm-audit / pip-audit     │
│  ├ dependency-check / osv-scanner     │
│  └ checkov（IaC 检查）                │
├──────────────────────────────────────┤
│  Phase 3: Slow（并行）                 │
│  ├ codeql（语义分析）                 │
│  ├ trivy（OS CVE + 文件系统）         │
│  └ nuclei（模板扫描）                 │
└──────────────────┬───────────────────┘
                   │ raw results
                   ▼
┌──────────────────────────────────────────┐
│  误报过滤                                │
│  ├ .vulnguard-ignore 文件规则            │
│  └ UI 标记的忽略规则                     │
├──────────────────────────────────────────┤
│  可达性分析                              │
│  └ 分析 import/require → 标记不可达依赖  │
├──────────────────────────────────────────┤
│  基线对比                                │
│  └ 与上次扫描对比 → 标记 NEW/REGRESSION  │
└──────────────────┬───────────────────────┘
                   │ filtered results
                   ▼
┌──────────────────────────────────────────┐
│  AI 聚合分析（DeepSeek）                  │
│  ├ 跨扫描器关联 — 同一漏洞合并            │
│  ├ 假阳性检测 — 自动识别误报并标注原因    │
│  ├ 置信度评分 — 高/中/低                 │
│  ├ 优先级排序 — 生成修复建议排序          │
│  └ 修复代码示例 — 为漏洞生成具体修复代码  │
└──────────────────┬───────────────────────┘
                   │ unified results
                   ▼
┌──────────────────────────────────────────┐
│  报告生成                                 │
│  ├ HTML 报告（浏览器预览 + 打印 PDF）     │
│  ├ SARIF 2.1.0（GitHub/VSCode 兼容）     │
│  ├ CycloneDX SBOM（软件物料清单）         │
│  └ 风险评分 A–F                          │
└──────────────────────────────────────────┘
```

## API Endpoints

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/upload` | POST | 上传源码 ZIP 文件 |
| `/api/scans` | GET | 获取扫描列表 |
| `/api/scans/:id` | GET | 获取扫描详情 |
| `/api/scans/:id` | DELETE | 删除扫描记录 |
| `/api/scans` | POST | 创建新扫描 |
| `/api/scan-progress/:id` | GET | 获取扫描实时进度（SSE 推送） |
| `/api/stats` | GET | 获取仪表盘统计 |
| `/api/llm/analyze` | POST | AI 安全分析 |

## Data Sources

- 漏洞数据来源于各扫描器内置数据库（Trivy DB、NVD、GitHub Advisory、OSV.dev 等）
- NVD 数据库通过 `npm run setup` 自动同步，缓存至 `.nvd-cache/`
- SBOM 生成于 `.scans/sbom/` 目录

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

## License

[MIT](LICENSE)

---

<p align="center">
  Built with ❤️ for open source security
</p>
