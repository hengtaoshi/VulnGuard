# VulnGuard 系统运行原理

> 版本: 1.1 | 最后更新: 2026-06-11
>
> ⚠️ 本文档基于实际代码 (src/lib/scanner/) 生成，与 CLAUDE.md（可能描述旧架构）存在差异。

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
11. [未集成的模块](#11-未集成的模块)

---

## 1. 系统概述

VulnGuard 是一个**源码安全漏洞扫描平台**，采用 B/S 架构，专注于 **SAST（静态代码分析）** 和 **SCA（软件组成分析）**。

核心设计理念：

- **规则驱动 + AI 增强**：扫描器选择由硬编码规则决定（非 AI），AI 仅做代码审计和结果分析
- **即扫即走**：扫描在后台异步执行，前端通过 SSE 实时推送进度
- **模块化扫描器**：每个扫描器独立注册，`isAvailable()` 检测环境决定是否启用

---

## 2. 技术架构

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────┐
│  浏览器      │     │  Next.js 14  │     │  扫描引擎        │
│  React 18    │ ←─→ │  App Router  │ ←─→ │  (后台异步)      │
│  TailwindCSS │     │  REST + SSE  │     │  15 个扫描器     │
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
                          ├─ 递归遍历目录（跳过 node_modules, .git 等 20+）
                          ├─ 按扩展名统计语言 (35+ 种)
                          ├─ 检测 20+ 种配置文件
                          └─ 推断项目类型
                               │
                               ▼
                        Phase 1 — 规则选择扫描器 ★
                          selectScannersByRules()
                          ├─ 硬编码规则匹配（语言/配置文件）
                          │   AI 不参与决策
                          ├─ ai 模式 → 按规则精选
                          └─ all 模式 → 所有可用扫描器
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
                        确定性去重（非 AI）
                          按 name:location:description(80chars) 去重
                          无 AI 交叉关联 / 误报剔除
                               │
                               ▼
                        返回到 API route 中完成
                          ├─ 按严重等级统计: C/H/M/L
                          ├─ 计算风险评分 A~F  ← 在 API route 中计算
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
                          → POST JSON 到外部地址 (10s 超时)
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
  - hasPython                  ← 是否存在 Python 文件
  - hasSourceCode              ← 是否存在源码文件
  - sizeCategory               ← 项目规模: tiny / small / medium / large / huge
  - fileTreeSample             ← 目录结构样本 (最多 50 个)
  - analysisTimeMs             ← 分析用时
```

跳过的目录: `node_modules`, `.git`, `dist`, `build`, `.next`, `__pycache__`, `.venv` 等 20+ 种。

#### Phase 1 — 规则选择扫描器（★ 非 AI）

文件: `src/lib/scanner/composite.ts` → `selectScannersByRules()`

根据 Phase 0 的分析结果，用**硬编码规则**决定运行哪些扫描器。**AI 不参与决策。**

```
ai 模式 (engine="ai"):
  总是选中:           semgrep, gitleaks, trivy, ai-scanner
  + Python:           bandit, pip-audit
  + JS/TS:            npm-audit
  + Docker/TF:        checkov
  + C/C++:            cve-cpp
  + Swift:            swift
  + 文件 > 20:        nuclei
  注意:               trufflehog, bearer, scorecard, osv-scanner
                      在 ai 模式下不会被自动选中
  注意:               dependency-check 已从 registry 中移除，
                      虽然规则仍会尝试选中，但实际永不生效

全量模式 (engine="all"):
  所有 isAvailable() === true 的扫描器全上
```

#### Phase 2 — 并发执行策略

文件: `src/lib/scanner/composite.ts` → `executeScanners()` + `buildParallelGroups()`

```
分组原则:
  快组: semgrep, gitleaks, trufflehog, scorecard (一般 < 5 秒)
  中组: bandit, npm-audit, pip-audit, checkov, cve-cpp, swift, osv-scanner, bearer (5-30 秒)
  慢组: trivy, nuclei (30 秒 - 2 分钟)
  AI组: ai-scanner (最后跑, 取决于 API 响应)

执行规则:
  - 组间串行: 快组 → 中组 → 慢组 → AI组
  - 组内并发: 滑动窗口，最多 5 个扫描器同时运行
  - ai-scanner 总是最后一个执行
  - 单个扫描器失败 (catch → errors[]) 不影响其他扫描器
  - 扫描器超时: 60s~600s 不等（取决于类型）
```

进度更新机制：每完成一个扫描器，更新 `scannerStatuses[]` → 写入 `session.progress` → SSE 推送到前端（服务端 500ms 轮询 scan-store，有变化即推送）。

#### Phase 3 — 结果处理（在 API route 中完成）

文件: `src/app/api/scans/route.ts` (POST handler 的 `.then()` 回调)

```
去重:
  按 name:location:description(前80字符) 做确定性去重
  ⚠️ 无 AI 交叉关联 / 误报剔除

统计:
  Critical / High / Medium / Low 分别计数

风险评分 (A~F):
  Critical > 0  → F
  High > 2      → D  
  High > 0      → C
  Medium > 3    → B
  其他          → A

清理:
  上传的源码目录 (data/uploads/) 扫描完成后自动删除
```

#### Phase 4 — SBOM 生成（可选）

用 Trivy 生成 CycloneDX SBOM：

```
execSync(`"${trivyPath}" fs --format cyclonedx --output "${sbomFile}" "${targetPath}"`)
→ .scans/sbom/{id}.cdx.json
```

#### Phase 5 — Webhook 通知（可选）

若设置了 `WEBHOOK_URL` 环境变量，扫描完成后异步 POST JSON 到外部地址（10s 超时，失败不阻塞）。

---

## 4. AI 的职责

### 4.1 AI 做什么（仅一个场景）

#### AI 代码审计（ai-scanner）

文件: `src/lib/scanner/ai-scanner.ts`

将源码发送到 DeepSeek API，让大模型做**深度逻辑分析**——找出规则引擎发现不了的复合漏洞：

```
输入: 目标源码（最多 80,000 字符，单文件最多 15,000 字符）
调用: DeepSeek Chat API (model: deepseek-v4-flash, temperature: 0.2)
输出: AIScanResponse
  {
    vulnerabilities: [
      {
        name: "命令注入风险",
        severity: "High",
        location: "src/app.js:42",
        cwe: "CWE-xxx",
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

⚠️ **注意**：本文档的上一版（v1.0）提到 AI 聚合分析（AI Aggregation），但该模块实际**未实现**。当前只有确定性去重。

### 4.2 AI 不做什么

- ❌ **不决定运行哪些扫描器** — 那是规则引擎的事
- ❌ **不自动修复代码** — 只输出 `codeFix` 建议，不自动提 PR
- ❌ **不直接访问代码仓库** — 只分析上传的源码文件
- ❌ **不做结果聚合** — 去重是确定性的，无 AI 交叉关联

### 4.3 AI 的局限性

- 受文件大小限制（最多 80,000 字符）
- 依赖 DeepSeek API 可用性
- 无 DeepSeek API Key 时自动跳过，不影响其他扫描器

---

## 5. 扫描器清单

| # | 扫描器 | 分类 | 检测方式 | 安装检测 | AI 模式 |
|---|--------|------|----------|----------|---------|
| 1 | **Semgrep** | SAST | 模式匹配，30+ 语言 | `semgrep --version` | ✅ |
| 2 | **Gitleaks** | 密钥检测 | 正则+熵检测，扫描文件内容 | `gitleaks version` | ✅ |
| 3 | **TruffleHog** | 密钥检测 | 800+ 检测器，文件系统扫描 | `trufflehog.exe` 存在 | ❌* |
| 4 | **Bandit** | SAST | Python 专用安全分析 | `bandit --version` | ✅ |
| 5 | **npm audit** | SCA | JS 依赖 CVE 查询 | `npm --version` | ✅ |
| 6 | **pip-audit** | SCA | Python 依赖 CVE 查询 | `pip-audit --version` | ✅ |
| 7 | **Checkov** | IaC | Terraform/Docker 配置安全 | `checkov --version` | ✅ |
| 8 | **Trivy** | 文件系统 | OS 包/文件系统 CVE | `trivy.exe --version` | ✅ |
| 9 | **Nuclei** | 文件系统 | 模板化文件安全扫描 | `nuclei.exe -version` | ✅ |
| 10 | **CVE-C++** | SCA | C/C++ 已知 CVE 匹配 | 始终可用 (内置) | ✅ |
| 11 | **Swift Scanner** | SCA | Swift Package 安全 | 始终可用 (内置) | ✅ |
| 12 | **OSV-Scanner** | SCA | Google OSV.dev 数据库 | `osv-scanner.exe` 存在 | ❌* |
| 13 | **OpenSSF Scorecard** | SAST | 10+ 维安全实践评分 | `scorecard.exe` 存在 | ❌* |
| 14 | **AI Scanner** | AI | DeepSeek LLM 代码审计 | `DEEPSEEK_API_KEY` 存在 | ✅ |
| 15 | **Bearer** | SAST | 通用 SAST（仅 Linux/macOS） | `process.platform !== "win32"` | ❌* |

> `❌*` = ai 模式下不会被规则自动选中，仅在 `all` 模式下生效

**已移除的扫描器：**

| 扫描器 | 原因 | 状态 |
|--------|------|------|
| Dependency-Check | Java/Go/Rust SCA, 依赖 Java 8+ | 从 registry 中移除，仅 manifest.ts 有元数据 |
| CodeQL | GitHub 语义分析, 内存占用高 | 完全移除 |

---

## 6. 规则引擎：扫描器选择逻辑

文件: `src/lib/scanner/composite.ts` → `selectScannersByRules()`

```
输入: TargetAnalysis + engine 模式 + 可用扫描器列表
输出: 选中的扫描器名称列表

匹配规则 (按优先级):
  1. 无条件:          semgrep, gitleaks, trivy, ai-scanner
  2. Python:          bandit, pip-audit
  3. JS/TS:           npm-audit
  4. Docker/TF:       checkov
  5. Java/Maven:      dependency-check ⚠️ 已从 registry 移除
  6. Go:              dependency-check ⚠️
  7. Rust:            dependency-check ⚠️
  8. C/C++:           cve-cpp
  9. Swift:           swift
  10. .NET:           dependency-check ⚠️
  11. 文件 > 20:      nuclei
  12. 总是:           ai-scanner (最后)
```

**注意**：
- dependency-check 已被从 `registry.ts` 中移除，即使规则选中也会被 `availableNames.includes()` 过滤掉
- TruffleHog、Bearer、Scorecard、OSV-Scanner 只在「全量模式」下生效，ai 模式不会自动选中它们
- Bearer 仅在非 Windows 平台可用

---

## 7. 执行策略：分组与并发

文件: `src/lib/scanner/composite.ts` → `buildParallelGroups()`

```
快组 (secret + semgrep):
  ├─ semgrep
  ├─ gitleaks
  ├─ trufflehog (全量模式)
  └─ scorecard (全量模式)

中组 (dependency + sast + others):
  ├─ bandit
  ├─ npm-audit
  ├─ pip-audit
  ├─ checkov
  ├─ cve-cpp
  ├─ swift
  ├─ osv-scanner (全量模式)
  └─ bearer (全量模式, 仅非 Win)

慢组 (filesystem):
  ├─ trivy
  └─ nuclei

AI 组 (最后):
  └─ ai-scanner
```

执行约束：
- 每组内部：滑动窗口，**最多 5 个并发**
- 组之间：**串行**（前一组全部完成才启动下一组）
- 扫描器总超时：60s~600s 不等（取决于扫描器类型）
- 失败处理：单个扫描器失败不影响其他扫描器

---

## 8. 结果处理

### 8.1 漏洞去重

```typescript
// 按 name:location:description(80字符) 做 key
const key = `${vuln.name}:${vuln.location}:${vuln.description.slice(0, 80)}`
```

**⚠️ 仅确定性去重**，无 AI 交叉关联/误报剔除。

### 8.2 风险评分公式

```
F: Critical > 0          → 有严重漏洞
D: High > 2              → 多处高危
C: High > 0              → 存在高危
B: Medium > 3            → 多处中危
A: 以上都不满足          → 安全
```

评分在 API route (`src/app/api/scans/route.ts`) 中计算，而非扫描引擎内。

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
| `/reports` | 安全报告 | 报告查看 |
| `/settings` | 设置 | 扫描配置项 |

### 9.2 实时推送

**方案**: Server-Sent Events (SSE)

```
GET /api/scan-progress/[id]
  → 流式返回 text/event-stream
  → 立即发送当前 session 状态
  → 服务端 500ms 轮询 scan-store, 有变化即推送 data 事件
  → 扫描完成推送 done 事件后关闭
  → 客户端断开 → 清理 interval

降级方案: 若 SSE 不可用, 前端回退到 1s HTTP 轮询
```

### 9.3 报告导出

| 格式 | 说明 |
|---|---|
| **SARIF** | 标准静态分析结果格式，GitHub/VSCode 原生支持 |
| **PDF** | 生成独立 HTML → 浏览器打印 |

---

## 10. 存储与数据流

### 10.1 数据存储

所有扫描数据以 **JSON 文件** 形式存储：

```
.scans/
  ├── scan-1234567890-abcd.json    ← 扫描会话 (进度+结果+漏洞)
  └── sbom/
      └── scan-1234567890-abcd.cdx.json  ← CycloneDX SBOM (可选)
```

生产环境: `data/scans/`
开发环境: `.scans/`

### 10.2 扫描会话结构

文件: `src/lib/scanner/scan-store.ts`

```typescript
interface ScanSession {
  id: string                    // scan-{timestamp}-{random}
  target: string                // 扫描目标路径
  type: "url" | "source"
  status: "pending" | "scanning" | "completed" | "failed"
  riskScore: string             // A~F
  totalChecks: number
  scannerEngine?: ScannerEngine
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
  orchestratorPlan?: any         // 保留字段，当前未使用
  aiAggregationReport?: any      // 保留字段，当前未使用
  aiAggregation?: { ... }        // 保留字段，当前未使用
  logs?: LogEntry[]              // 扫描日志
  createdAt: string
}
```

### 10.3 API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/scans` | 创建扫描 (后台异步执行，立即返回 id) |
| `GET` | `/api/scans` | 获取所有扫描摘要 |
| `GET` | `/api/scans/[id]` | 获取扫描详情 |
| `DELETE` | `/api/scans` | 清除全部扫描 + 上传目录 |
| `DELETE` | `/api/scans/[id]` | 删除单个扫描 |
| `GET` | `/api/scan-progress/[id]` | **SSE 实时推送** |
| `POST` | `/api/upload` | 上传源码 ZIP/文件夹 |
| `GET` | `/api/stats` | 仪表盘统计数据 |
| `POST` | `/api/llm/analyze` | AI 深度分析 |

---

## 11. 未集成的模块

以下模块存在于代码库中但**未集成到主扫描流程**：

### 11.1 依赖可达性分析

文件: `src/lib/scanner/reachability.ts`

功能：解析源码中的 import/require 语句，判断 SCA 报告的 CVE 依赖是否实际被调用。

支持：
- JS/TS: `import X from 'y'`, `require('y')`
- Python: `import y`, `from y import x`
- Go: `import "y"`
- Java: `import y.x`

**当前状态**：功能完整但从未被 `composite.ts` 调用，不可达依赖的 CVE 仍会全部报告。

### 11.2 Scanner Manifest

文件: `src/lib/scanner/manifest.ts`

包含 12 个扫描器的详细元数据（描述、扫描类型、技术指标、优先级等）。

**当前状态**：未被任何执行代码引用，可能为未来 AI 驱动的扫描器选择做准备。

### 11.3 保留字段

`ScanSession` 中的 `orchestratorPlan`、`aiAggregationReport`、`aiAggregation` 字段为保留字段，当前**未被赋值**。

---

## 附录：关键文件映射

| 文件 | 职责 |
|---|---|
| `src/lib/scanner/composite.ts` | **主入口**：目标分析→规则选扫描器→并发执行→去重 |
| `src/lib/scanner/target-analyzer.ts` | 预扫描目录分析器 |
| `src/lib/scanner/registry.ts` | 所有 15 个扫描器的注册表 |
| `src/lib/scanner/types.ts` | Scanner / ScanResult / AggregationReport 类型 |
| `src/lib/scanner/scan-store.ts` | 文件存储 CRUD |
| `src/lib/scanner/scan-log.ts` | 结构化扫描日志 |
| `src/lib/scanner/manifest.ts` | 扫描器元数据（当前未使用） |
| `src/lib/scanner/reachability.ts` | 依赖可达性分析（当前未集成） |
| `src/lib/sarif-converter.ts` | SARIF 格式转换 |
| `src/app/api/scans/route.ts` | REST API — 创建/获取/清除扫描 |
| `src/app/api/scans/[id]/route.ts` | REST API — 获取/删除单条扫描 |
| `src/app/api/scan-progress/[id]/route.ts` | SSE 实时推送 |
| `src/app/scan/[id]/page.tsx` | 扫描详情前端页面 |
| `src/lib/api/types.ts` | Vulnerability / ScanDetail / ScanSummary 类型 |

---

> **修订记录**：
> - v1.1 (2026-06-11): 根据实际代码全面修订。修正扫描器清单（15 个）、删除 AI Orchestrator/Aggregator 描述、补充未集成模块说明、修正 Phase 3 位置、修正规则引擎说明。详见 [SYSTEM_FLOWCHART.md](./SYSTEM_FLOWCHART.md) 的疏漏清单。
> - v1.0 (2026-06-11): 初始版本。
