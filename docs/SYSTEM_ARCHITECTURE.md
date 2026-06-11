# VulnGuard 系统运行原理

> 版本: 1.0 | 最后更新: 2026-06-11

---

## 目录

1. [系统概述](#1-系统概述)
2. [技术架构](#2-技术架构)
3. [完整扫描流程](#3-完整扫描流程)
4. [AI 的职责](#4-ai-的职责)
5. [扫描器清单](#5-扫描器清单)
6. [规则引擎：扫描器选择逻辑](#6-规则引擎扫描器选择逻辑)
7. [执行策略：分组与并发](#7-执行策略分组与并发)
8. [结果处理](#8-结果处理)
9. [前端交互](#9-前端交互)
10. [存储与数据流](#10-存储与数据流)

---

## 1. 系统概述

VulnGuard 是一个**源码安全漏洞扫描平台**，采用 B/S 架构，专注于 **SAST（静态代码分析）** 和 **SCA（软件组成分析）**。

核心设计理念：

- **规则驱动 + AI 增强**：扫描器选择由硬编码规则决定，AI 仅做代码审计和结果分析
- **即扫即走**：扫描在后台异步执行，前端通过 SSE 实时推送进度
- **模块化扫描器**：每个扫描器独立注册，`isAvailable()` 检测环境决定是否启用

---

## 2. 技术架构

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  浏览器      │     │  Next.js 14  │     │  扫描引擎        │
│  React 18    │ ←─→ │  App Router  │ ←─→ │  (后台异步)      │
│  TailwindCSS │     │  REST + SSE  │     │  12 个扫描器     │
│  shadcn/ui   │     │  React Query │     │  + 规则选择器    │
└──────────────┘     └──────┬───────┘     └──────────────────┘
                            │
                     ┌──────▼───────┐
                     │  .scans/*.json│
                     │  (文件存储)   │
                     └──────────────┘
```

### 核心依赖

| 类别 | 技术 |
|---|---|
| 前端框架 | Next.js 14 + React 18 |
| UI | Tailwind CSS + shadcn/ui + Lucide icons |
| 图表 | Recharts |
| 状态管理 | @tanstack/react-query |
| 后端运行时 | Next.js API Routes (Node.js) |
| 数据存储 | 文件系统 (JSON) |
| 实时推送 | Server-Sent Events |
| AI | DeepSeek API |

---

## 3. 完整扫描流程

### 3.1 流程全景图

```
用户操作              API 层                    扫描引擎                     存储
─────────            ──────                    ────────                     ────
                     
① 选引擎 + 提交目标
      │
      ▼
② POST /api/scans ──→ createSession() ──────────────────────────────→ .scans/{id}.json
      │                  │                                              status: "pending"
      │                  ▼
      │              runCompositeScan()  ← 后台启动，不 await
      │                  │
      ▼                  ▼
  { id, status:     Phase 0 — 目标分析
   "pending" }           analyzeTarget()
                          ├─ 递归遍历目录
   ↑ 立即返回              ├─ 按扩展名统计语言
                           ├─ 检测 20+ 种配置文件
                           └─ 推断项目类型
                               │
                               ▼
                        Phase 1 — 规则选择扫描器
                          selectScannersByRules()
                          ├─ 根据语言/配置文件匹配规则
                          ├─ AI 模式 → 精选（约 6-10 个）
                          └─ 全量模式 → 所有可用扫描器
                               │
                               ▼
                        Phase 2 — 并发执行
                          executeScanners()
                          ├─ 快组 (secret/sast)      ← 并发 5 个
                          ├─ 中组 (dependency/sast)  ← 并发 5 个
                          ├─ 慢组 (filesystem)       ← 并发 5 个
                          └─ AI 组 (ai-scanner)      ← 最后单独跑
                               │
                               │   每完成一个 → updateSession()
                               │   ──────────────────────────→ 前端 SSE 推送
                               ▼
                        确定性去重
                          按 name:location:description(80chars) 去重
                               │
                               ▼
                        Phase 3 — 完成
                          ├─ 按严重等级统计: C/H/M/L
                          ├─ 计算风险评分 A~F
                          ├─ 写入 session → status: "completed"
                          ├─ 自动删除上传的源码目录
                          │
                          ▼
                        Phase 4 — SBOM 生成 (可选)
                          用 Trivy 生成 CycloneDX SBOM
                          → .scans/sbom/{id}.cdx.json
                               │
                               ▼
                        Phase 5 — Webhook 通知 (可选)
                          若设了 WEBHOOK_URL
                          → POST JSON 到外部地址
```

### 3.2 详细阶段说明

#### Phase 0 — 目标分析（纯本地，不调外部工具）

文件: `src/lib/scanner/target-analyzer.ts`

在扫描任何代码之前，先对目标目录做快速静态分析：

```
输入: 目标目录路径
输出: TargetAnalysis 对象

包含:
  - totalFiles / totalDirs     ← 文件和目录总数
  - languages                  ← 语言分布统计 (扩展名 → 文件数)
    { "javascript": { count: 119, percentage: 38, sampleFiles: [...] }, ... }
  - configFiles                ← 检测到的配置文件
    { hasPackageJson: true, hasDockerfile: true, ... }
  - configDetails              ← 配置文件的详细信息
  - projectTypes               ← 推断的项目类型 ["javascript/typescript", "python"]
  - hasIaC                     ← 是否包含 IaC 文件
  - sizeCategory               ← 项目规模: tiny / small / medium / large / huge
  - fileTreeSample             ← 目录结构样本 (最多 50 个)
```

跳过的目录: `node_modules`, `.git`, `dist`, `build`, `.next`, `__pycache__`, `.venv` 等 20+ 种。

#### Phase 1 — 规则选择扫描器

文件: `src/lib/scanner/composite.ts` → `selectScannersByRules()`

根据 Phase 0 的分析结果，用**硬编码规则**决定运行哪些扫描器。**AI 不参与决策。**

```
AI 模式 (engine="ai"):
  任何项目:         semgrep + gitleaks + trivy + ai-scanner
  + Python:        bandit + pip-audit
  + JS/TS:         npm-audit
  + Docker/TF:     checkov
  + Java/Go/Rust:  dependency-check (暂时移除)
  + C/C++:         cve-cpp
  + Swift:         swift
  + 文件 > 20:     nuclei

全量模式 (engine="all"):
  所有 isAvailable() === true 的扫描器全上
```

#### Phase 2 — 并发执行策略

文件: `src/lib/scanner/composite.ts` → `executeScanners()`

```
分组原则:
  快组: semgrep, gitleaks, trufflehog (一般 < 5 秒)
  中组: bandit, npm-audit, pip-audit, checkov, cve-cpp, swift, osv-scanner (5-30 秒)
  慢组: trivy, nuclei, scorecard (30 秒 - 2 分钟)
  AI组: ai-scanner (最后跑, 取决于 API 响应)

执行规则:
  - 组间串行: 快组 → 中组 → 慢组 → AI组
  - 组内并发: 最多 5 个扫描器同时运行
  - ai-scanner 总是最后一个执行
```

进度更新机制：每完成一个扫描器，更新 `scannerStatuses[]` → 写入 `session.progress` → SSE 推送到前端。

#### Phase 3 — 结果处理

```
去重:
  按 name:location:description(前80字符) 做确定性去重

统计:
  Critical / High / Medium / Low 分别计数

风险评分 (A~F):
  Critical > 0  → F
  High > 2      → D  
  High > 0      → C
  Medium > 3    → B
  其他          → A
```

---

## 4. AI 的职责

### 4.1 AI 做什么（两个场景）

#### 场景一：AI 代码审计（ai-scanner）

文件: `src/lib/scanner/ai-scanner.ts`

将源码发送到 DeepSeek API，让大模型做**深度逻辑分析**——找出规则引擎发现不了的复合漏洞：

```
输入: 目标源码（最多 80,000 字符）
调用: DeepSeek Chat API
输出: AIScanResponse
  {
    vulnerabilities: [
      {
        name: "命令注入风险",
        severity: "High",
        location: "src/app.js:42",
        description: "...",
        recommendation: "...",
        code: "有问题的代码片段",
        codeFix: "修复后的代码"
      }
    ],
    analysis_summary: "综合分析总结"
  }
```

AI 专门查**规则引擎覆盖不到**的深层问题：
- 业务逻辑漏洞（绕过支付、越权）
- 跨文件复合漏洞（单独看安全，组合有风险）
- 认证/授权逻辑缺陷
- 架构设计缺陷

AI **不查** Semgrep/Gitleaks 已覆盖的类型（SQL注入、XSS、密钥泄露等）。

#### 场景二：AI 聚合分析（可选后处理）

文件: `src/lib/scanner/ai-aggregator.ts`

将所有扫描器的结果发给 DeepSeek，做：
- 交叉关联（多个扫描器检出同一问题 → 合并）
- 误报剔除（AI 判断不可利用 → 标记）
- 置信度评估（high/medium/low）
- 优先级排序

### 4.2 AI 不做什么

- ❌ **不决定运行哪些扫描器** — 那是规则引擎的事
- ❌ **不自动修复代码** — 只输出 `codeFix` 建议，不自动提 PR
- ❌ **不直接访问代码仓库** — 只分析上传的源码文件

### 4.3 AI 的局限性

- 受文件大小限制（最多 80,000 字符）
- 依赖 DeepSeek API 可用性
- 无 DeepSeek API Key 时自动跳过，不影响其他扫描器

---

## 5. 扫描器清单

| # | 扫描器 | 分类 | 检测方式 | 安装检测 |
|---|--------|------|----------|----------|
| 1 | **Semgrep** | SAST | 模式匹配，30+ 语言 | `semgrep --version` |
| 2 | **Gitleaks** | 密钥检测 | 正则+熵检测，扫描文件内容 | `gitleaks version` |
| 3 | **TruffleHog** | 密钥检测 | 800+ 检测器，文件系统扫描 | `trufflehog.exe` 存在 |
| 4 | **Bandit** | SAST | Python 专用安全分析 | `bandit --version` |
| 5 | **npm audit** | SCA | JS 依赖 CVE 查询 | `npm --version` |
| 6 | **pip-audit** | SCA | Python 依赖 CVE 查询 | `pip-audit --version` |
| 7 | **Checkov** | IaC | Terraform/Docker 配置安全 | `checkov --version` |
| 8 | **Trivy** | 文件系统 | OS 包/文件系统 CVE | `trivy.exe --version` |
| 9 | **Nuclei** | 文件系统 | 模板化文件安全扫描 | `nuclei.exe -version` |
| 10 | **CVE-C++** | SCA | C/C++ 已知 CVE 匹配 | 始终可用 (内置) |
| 11 | **Swift Scanner** | SCA | Swift Package 安全 | 始终可用 (内置) |
| 12 | **OSV-Scanner** | SCA | Google OSV.dev 数据库 | `osv-scanner.exe` 存在 |
| 13 | **OpenSSF Scorecard** | SAST | 10+ 维安全实践评分 | `scorecard.exe` 存在 |
| 14 | **AI Scanner** | AI | DeepSeek LLM 代码审计 | `DEEPSEEK_API_KEY` 存在 |
| — | ~~Dependency-Check~~ | SCA | Java/Go/Rust/Maven SCA | 暂时移除 (NVD 下载中) |
| — | ~~CodeQL~~ | SAST | GitHub 语义分析 | 暂时移除 (内存占用高) |

---

## 6. 规则引擎：扫描器选择逻辑

文件: `src/lib/scanner/composite.ts` → `selectScannersByRules()`

```
输入: TargetAnalysis + engine 模式 + 可用扫描器列表
输出: 选中的扫描器名称列表

匹配规则 (按优先级):
  1. 无条件:         semgrep, gitleaks, trivy
  2. Python 检测到:  bandit, pip-audit
  3. JS/TS 检测到:   npm-audit
  4. Docker/TF:      checkov
  5. Java/Maven:     dependency-check (暂不可用)
  6. Go:             dependency-check
  7. Rust:           dependency-check
  8. C/C++:          cve-cpp
  9. Swift:          swift
  10. .NET:          dependency-check
  11. 文件 > 20:     nuclei
  12. 总是:          ai-scanner (最后)
```

**注意**：TruffleHog、Scorecard、OSV-Scanner 目前只在「全量模式」下生效，AI 模式不会自动选中它们。

---

## 7. 执行策略：分组与并发

文件: `src/lib/scanner/composite.ts` → `buildParallelGroups()`

```
快组 (secret + semgrep):
  ├─ semgrep
  ├─ gitleaks
  ├─ trufflehog (全量模式)
  └─ scorecard (全量模式)

中组 (dependency + sast + checkov):
  ├─ bandit
  ├─ npm-audit
  ├─ pip-audit
  ├─ checkov
  ├─ cve-cpp
  ├─ swift
  └─ osv-scanner (全量模式)

慢组 (filesystem):
  ├─ trivy
  └─ nuclei

AI 组 (最后):
  └─ ai-scanner
```

执行约束：
- 每组内部：滑动窗口，**最多 5 个并发**
- 组之间：**串行**（前一组全部完成才启动下一组）
- 总超时：单个扫描器 60s~600s 不等（取决于扫描器类型）
- 失败处理：单个扫描器失败不影响其他扫描器

---

## 8. 结果处理

### 8.1 漏洞去重

```typescript
// 按 name:location:description(80字符) 做 key
const key = `${vuln.name}:${vuln.location}:${vuln.description.slice(0, 80)}`
```

### 8.2 风险评分公式

```
F: Critical > 0          → 有严重漏洞
D: High > 2              → 多处高危
C: High > 0              → 存在高危
B: Medium > 3            → 多处中危
A: 以上都不满足          → 安全
```

### 8.3 自动清理

- 上传的源码目录 (`data/uploads/`) 扫描完成后**自动删除**
- 扫描会话 JSON 保留在 `.scans/` 中

---

## 9. 前端交互

### 9.1 页面路由

| 路由 | 页面 | 说明 |
|---|---|---|
| `/` | 安全中心 | 统计卡片 + 漏洞趋势图 + 最近扫描 |
| `/scan/new` | 新建扫描 | 选引擎 → 选/传目标 → 启动 |
| `/scan/[id]` | 扫描详情 | SSE 实时进度 → 结果展示 + SARIF/PDF 导出 |
| `/scan/history` | 扫描历史 | 搜索、筛选过往记录 |
| `/reports` | 安全报告 | AI 聚合报告 |
| `/settings` | 设置 | 扫描配置项 |

### 9.2 实时推送

**当前方案**: Server-Sent Events (SSE)

```
GET /api/scan-progress/[id]
  → 流式返回 text/event-stream
  → 服务端 500ms 轮询 scan-store, 有变化即推送
  → 扫描完成推送 done 事件后关闭

降级方案: 若 SSE 不可用, 自动回退到 1s HTTP 轮询
```

**旧的方案（已替换）**: 前端 `setInterval(fetchScan, 1000)` 每 1 秒轮询

### 9.3 报告导出

| 格式 | 说明 |
|---|---|
| **SARIF** | 标准静态分析结果格式，GitHub/VSCode 原生支持 |
| **PDF** | 生成独立 HTML → 浏览器打印 |

---

## 10. 存储与数据流

### 10.1 数据存储

所有扫描数据以 **JSON 文件** 形式存储在 `.scans/` 目录：

```
.scans/
  ├── scan-1234567890-abcd.json    ← 扫描会话 (进度+结果+漏洞)
  └── sbom/
      └── scan-1234567890-abcd.cdx.json  ← CycloneDX SBOM (可选)
```

### 10.2 扫描会话结构

```typescript
interface ScanSession {
  id: string                    // scan-{timestamp}-{random}
  target: string                // 扫描目标路径
  type: "source"
  status: "pending" | "scanning" | "completed" | "failed"
  riskScore: string             // A~F
  totalChecks: number
  scannerEngine?: "ai" | "all"
  summary: {
    critical: number
    high: number
    medium: number
    low: number
    passed: number
  }
  vulnerabilities: Vulnerability[]
  scanners?: ScannerInfo[]       // 各扫描器结果
  progress?: ScanProgress        // 进度 + scannerStatuses
  aiAggregation?: { ... }        // AI 聚合分析结果
  logs?: LogEntry[]              // 扫描日志
  createdAt: string
}
```

### 10.3 API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/scans` | 创建扫描 (后台异步执行) |
| `GET` | `/api/scans` | 获取所有扫描摘要 |
| `GET` | `/api/scans/[id]` | 获取扫描详情 |
| `DELETE` | `/api/scans` | 清除全部扫描 |
| `GET` | `/api/scan-progress/[id]` | **SSE 实时推送** |
| `POST` | `/api/upload` | 上传源码 ZIP/文件夹 |
| `GET` | `/api/stats` | 仪表盘统计数据 |
| `POST` | `/api/llm/analyze` | AI 深度分析 |

---

## 附录：关键文件映射

| 文件 | 职责 |
|---|---|
| `src/lib/scanner/composite.ts` | 扫描编排主入口：目标分析→选扫描器→执行→去重 |
| `src/lib/scanner/target-analyzer.ts` | 预扫描目录分析器 |
| `src/lib/scanner/registry.ts` | 所有扫描器的注册表 |
| `src/lib/scanner/scan-store.ts` | 文件存储 CRUD |
| `src/lib/scanner/reachability.ts` | 依赖可达性分析 |
| `src/lib/sarif-converter.ts` | SARIF 格式转换 |
| `src/app/api/scans/route.ts` | REST API |
| `src/app/api/scan-progress/[id]/route.ts` | SSE 实时推送 |
| `src/app/scan/[id]/page.tsx` | 扫描详情前端页面 |
| `src/lib/scanner/types.ts` | Scanner / ScanResult / AggregationReport 类型 |
| `src/lib/api/types.ts` | Vulnerability / ScanDetail / ScanSummary 类型 |
