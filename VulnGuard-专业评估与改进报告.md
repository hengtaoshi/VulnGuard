# VulnGuard 安全扫描平台 — 专业评估与改进报告

> **评估人**：资深安全工程师  
> **评估版本**：v0.1.0  
> **评估日期**：2026-06-26  
> **定位**：单机版安全扫描聚合平台

---

## 目录

1. [产品概述](#1-产品概述)
2. [架构总览](#2-架构总览)
3. [亮点分析（做对了什么）](#3-亮点分析做对了什么)
4. [与专业扫描器的差距分析](#4-与专业扫描器的差距分析)
5. [代码级问题深度剖析](#5-代码级问题深度剖析)
6. [优化改进路线图](#6-优化改进路线图)
7. [总结](#7-总结)

---

## 1. 产品概述

**VulnGuard** 是一个基于 Next.js 14 构建的**安全漏洞扫描聚合平台**，其核心思路是：

1. **集成 15+ 安全扫描器**，统一调度
2. **AI 驱动编排**（DeepSeek API）——智能选择最合适的扫描器组合
3. **语言感知**——扫描前检测技术栈，避免无关扫描
4. **结果聚合**——AI 去重、误报标记、关联分析

覆盖的扫描类型：SAST（静态分析）、Secret（凭据检测）、SCA（依赖分析）、IaC（基础设施即代码）、供应链安全评估。

---

## 2. 架构总览

```
用户上传 ZIP 源码
       │
       ▼
┌──────────────────┐
│  上传 API         │  解压到 data/uploads/
│  (路径越界检查)   │  └─ ZIP Slip 防护 ✓
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  target-analyzer  │  快速扫描分析技术栈
│  (语言/配置文件)   │  输出：语言分布 + 框架 + 项目类型
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  orchestrator     │  AI 编排 + 规则回退
│  (扫描器选择)     │  输出：选定扫描器 + 并行分组 + 优先级
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  composite        │  按 fast/medium/slow 分组并行执行
│  (并行调度)       │  各扫描器独立运行，状态流式推送
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  ai-aggregator    │  AI 去重 + 关联分析 + 置信度打分
│  (结果聚合)       │  输出：最终发现列表 + 优先级建议
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  scan-store       │  JSON 文件持久化
│  (存储+展现)      │  Web UI 展示 + PDF/HTML 导出
└──────────────────┘
```

### 扫描器清单

| 扫描器 | 类型 | 适用语言/场景 | 速度 |
|--------|------|-------------|------|
| **Semgrep** | SAST | 多语言（2000+ 规则） | 中 |
| **Bandit** | SAST | Python | 快 |
| **CodeQL** | SAST | 多语言（语义分析） | 慢 |
| **Gitleaks** | Secret | 凭据泄露 | 快 |
| **TruffleHog** | Secret | 凭据泄露（800+ 检测器） | 中 |
| **npm-audit** | SCA | JavaScript/TypeScript | 快 |
| **pip-audit** | SCA | Python | 快 |
| **Dependency-Check** | SCA | Java/Go/Rust/.NET | 中 |
| **OSV-Scanner** | SCA | 多生态通用 | 快 |
| **CVE-CPP Scanner** | SCA | C/C++（Conan/vcpkg） | 中 |
| **Swift Scanner** | SCA | Swift | 中 |
| **Trivy** | 综合 | 文件系统/依赖/IaC | 中 |
| **Checkov** | IaC | Terraform/Docker/K8s | 中 |
| **Nuclei** | 模板化 | 模板匹配检测 | 中 |
| **Scorecard** | 供应链 | OpenSSF 安全实践评分 | 快 |

---

## 3. 亮点分析（做对了什么）

### 3.1 扫描器编排 — 行业领先思路

大多数单机工具（如 `trivy fs`、`semgrep --config auto`）都是用户手动指定扫描什么。VulnGuard 的 **AI + 规则双引擎选择器** 是一个真正的创新：

```typescript
// orchestrator.ts
// 1. 先通过 target-analyzer 收集技术栈证据
// 2. 调用 DeepSeek 生成扫描计划
// 3. AI 不可用时降级到规则回退
const plan = await createOrchestratorPlan(analysis, engine, ...)
  ?? createFallbackPlan(analysis, engine, ...)
```

这解决了行业痛点：**开发者不清楚自己项目该跑哪些扫描器**。

### 3.2 安全工程到位

- **CSP 安全头**：`default-src 'self'` + 严格策略
- **上传路径校验**：双重防护——`..` 检查 + `resolve()` 后验证路径仍在目标目录
- **ZIP Slip 防护**：`if (normalized.includes(".."))` 拒绝
- **文件大小限制**：单文件 20MB，总数 5000 个
- **扫描后自动清理**：`cleanupUploadDir()` 删除上传目录
- **全局认证机制**：`SCAN_AUTH_TOKEN` 通过 Bearer header 或 HttpOnly cookie 传递

### 3.3 基线对比模块

`baseline.ts` 已经实现了基于指纹的回归检测。

### 3.4 中英文双语 UI

i18n 系统完整，前台中文/英文全量覆盖。

### 3.5 UI 完整性

4 个页面（仪表盘/新建扫描/详情/历史）+ 报告页面，组件化良好（shadcn/ui 风格），比大多数单机扫描器的无头模式友好得多。

---

## 4. 与专业扫描器的差距分析

### 4.1 差距总览矩阵

| 对比维度 | VulnGuard 现状 | 专业扫描器做法 | 差距等级 |
|---------|---------------|---------------|---------|
| **假阳性管理** | AI 标记置信度，不持久化 | 用户"标记为 FP"→ 永久抑制 | 🔴 **P0** |
| **增量扫描** | 没有，每次全量重扫 | 只扫 git diff 文件 → 秒级 | 🔴 **P0** |
| **CLI 工具** | 无（只有 npm run dev） | snyk test / trivy fs / semgrep --ci | 🟡 P1 |
| **扫描性能** | 串行分组，中型项目 3-15 分钟 | Semgrep 百兆 < 2 分钟 | 🟡 P1 |
| **规则定制** | 依赖外部扫描器规则文件 | SonarQube UI 规则编辑器/Semgrep 自定义 YAML | 🟡 P1 |
| **修复指导** | AI codeFix（一次性） | 上下文感知渐进修复 + PR 自动创建 | 🟡 P1 |
| **IDE 集成** | 无 | SonarLint / Snyk 插件 | 🟡 P1 |
| **CI/CD 门禁** | 无 | 设阈值 → 阻止合并 | 🟡 P1 |
| **基线回归** | ✅ 已实现指纹对比 | SonarQube "New Code" 模式 | 🟢 已接近 |
| **CVE 时效性** | 依赖各扫描器 DB 更新 | Snyk/Trivy 按小时更新 | 🟢 可接受 |
| **结果导出** | HTML + JSON | SARIF/SPDX/CycloneDX/PDF | 🟢 已有 SARIF |
| **资源限制** | 无（可能 OOM） | cgroup/Docker 内存+CPU 配额 | 🟡 P1 |

### 4.2 P0 级别差距详解

#### 🔴 差距 #1：假阳性管理没有回路（最致命）

**现状**：
- AI 聚合器可以标记 `isFalsePositive` 和 `confidence`
- 但这些标记**不持久化**

**专业做法**：
```
用户审查发现 → 点击"标记为误报" → 写入 .vulnguard-ignore.json
                                 → 下次扫描自动过滤
                                 → 团队共享抑制规则
                                 → 可选上报 FP 帮助改进规则
```

**后果**：
没有假阳性管理的扫描器，每次扫出来的结果都一样。用户第一次看到 200 个告警会逐一审查，但到第三次就**不再看了**。这就是"扫描疲劳"——安全工具的致命伤。

#### 🔴 差距 #2：增量扫描缺失

**现状**：
- 每次扫描都是全量重扫
- CodeQL 每次都要重新 build database（中型项目 5-30 分钟）

**专业做法**：
```
git diff HEAD~1 → 提取变更文件列表 → 只扫描这些文件
                                        ↓
非专业：每次重新扫 10000 个文件，3 分钟变 2 秒
```

**VulnGuard 的影响**：
在当前架构下，扫描一个中型 React + Go 项目（5 万行代码）大概需要：
- Semgrep: 1-2 分钟
- CodeQL build: 3-5 分钟
- CodeQL query: 2-3 分钟
- Trivy: 1-2 分钟
- Dependency-Check: 2-5 分钟（含 NVD 同步）
- 其他扫描器: 2-4 分钟
- **合计：12-20 分钟**

没有增量扫描的话，开发者在 commit 前跑一次基本不可能——太慢了。

#### 🔴 差距 #3：缺少 CLI 工具

**现状**：
- 运行方式：`npm run dev` → 浏览器打开 → 上传 ZIP → 等结果
- 无法在 CI/CD 中调用

**专业做法**：
```bash
# CLI 工具
vulnguard scan .                          # 扫描当前目录
vulnguard scan ./src --format sarif       # 导出 SARIF
vulnguard scan ./src --output report.html # 导出 HTML
vulnguard baseline --diff HEAD~1          # 增量扫描

# CI/CD 集成
vulnguard scan . --threshold critical=0    # 有 critical 就失败
```

没有 CLI 的扫描器就像没有命令行的编译器——能用，但没人会喜欢用。

---

## 5. 代码级问题深度剖析

### 5.1 基线指纹匹配太脆弱

**文件**：`src/lib/scanner/baseline.ts` 第 62-70 行

```typescript
function buildFingerprintSet(vulnerabilities: Vulnerability[]): Set<string> {
  const set = new Set<string>()
  for (const v of vulnerabilities) {
    set.add(getVulnKey(v))           // CVE + location
    set.add(`${v.name}:${v.location}`) // name + location
  }
  return set
}
```

**问题**：
| 场景 | 指纹变化 | 结果 |
|------|---------|------|
| 文件头部加了 import，行号偏移 | `location` 变了 | 现有漏洞变"新增" |
| 扫描器版本升级，规则 ID 改了 | `name` 变了 | 现有漏洞变"新增" |
| 修了一半，只改了行号 | 旧指纹不匹配 | 同时报"已修复"和"新增" |

**修复方案**：指纹应基于 **ruleID + 文件相对路径 + 代码上下文 hash（附近 3 行代码的摘要）**。

### 5.2 AI 聚合的结果没有反馈到回路

**文件**：`src/lib/scanner/ai-aggregator.ts`

聚合器输出 `AggregationReport` 后，这些信息没有反哺到存储层：

- `isFalsePositive = true` → 但没有写入 ignore 规则
- `confidence: "high"` → 但没有自动调整 UI 展示优先级
- `isCorrelated = true` → 但没有在 UI 中突出显示

**专业做法**：
```mermaid
flowchart LR
  A[AI 聚合] --> B{置信度?}
  B -->|high| C[自动标记为 confirmed]
  B -->|medium| D[突出显示待审查]
  B -->|low| E[折叠/隐藏]
  C --> F[持久化到 ignore-rules]
  D --> G[UI 标记 "awaiting review"]
```

### 5.3 扫描器健康检查不充分

**文件**：`src/lib/scanner/registry.ts`

```typescript
isAvailable: () => {
  try { execSync("bandit --version", { stdio: "pipe", timeout: 5000 }); return true }
  catch { return false }
}
```

**问题**：
- `--version` 可执行 ≠ `scan` 能成功运行
- Python 版本不兼容、缺少运行时依赖、动态链接库缺失等都会导致运行时崩溃
- 应该在 `scan()` 执行时也捕获并报告环境错误

### 5.4 缺少 "noise 预算" 机制

专业扫描器（Semgrep AppSec Platform / Snyk）允许团队设置 noise budget：
```
Critical: 0  → 超过就 gating 失败
High:     ≤ 5  → 允许一定数量
Medium:   ≤ 20
Low:      不限
```

VulnGuard 目前是"全量报告"，没有阈值概念。

### 5.5 扫描器容错和超时处理

**文件**：`src/lib/scanner/exec.ts`

```typescript
export function execAsync(command: string, options = {}) {
  const { timeout = 30000, maxBuffer = 10 * 1024 * 1024 } = options
  // ...
}
```

- 默认 30 秒超时对 CodeQL（中型项目 5-30 分钟）直接不够
- 没有重试机制
- maxBuffer 10MB 对于 Semgrep 的大项目 JSON 输出可能不够

### 5.6 JS 依赖扫描只有 npm-audit

```typescript
// composite.ts
if (configNames.has("hasPackageLock")) {
  selected.push("npm-audit")
}
```

- 没有 `pnpm audit` 或 `yarn audit` 的 fallback
- `package-lock.json` 不存在时 npm-audit 直接报错
- 没有检测 `pnpm-lock.yaml`、`yarn.lock`

### 5.7 最遗憾的事：后端能力有，前端没入口

VulnGuard 的后端已经写了：

| 能力 | 后端文件 | 前端 UI |
|------|---------|---------|
| 基线对比 | `baseline.ts` ✅ | ❌ 没有入口展示 new/existing/regression |
| 误报抑制 | `ignore-rules.ts` ✅ | ❌ 没有"标记为误报"按钮 |
| AI 聚合置信度 | `ai-aggregator.ts` ✅ | ❌ 没有按置信度过滤 |
| 扫描日志 | `scan-log.ts` ✅ | ❌ 没有日志查看面板 |

这是最大的工程浪费——后端做好了，前端不集成等于没做。

---

## 6. 优化改进路线图

### 第 1 个月：快速见效（补齐 P0 差距）

#### 6.1 假阳性持久化抑制（3 天）

```
改动范围：
├── 前端: 扫描详情页每个 finding 加 "标记为误报" 按钮
├── API:  POST /api/scans/:id/suppress → 写入 .vulnguard-ignore.json
├── 扫描引擎: composite.ts 运行时加载 ignore-rules 过滤
└── 存储: 项目根目录下生成 .vulnguard-ignore.json
```

**预期效果**：用户标记过的误报不再出现，扫描疲劳度降低 80%。

#### 6.2 增量扫描（5 天）

```
改动范围：
├── 新增: git diff 检测模块
│   ├── 检测 .git 目录是否存在
│   ├── 执行 git diff --name-only HEAD~1
│   └── 提取变更文件列表
├── 修改: composite.ts
│   ├── 增量模式下只传递变更文件给扫描器
│   └── 标记为 "partial scan"
├── 修改: 前端
│   └── 显式展示 "增量扫描 (3 个文件变更)" vs "全量扫描"
└── 注意: CodeQL 不支持部分扫描 → 增量模式下跳过
```

**预期效果**：日常开发扫描从 15 分钟降低到 30 秒。

#### 6.3 CLI 工具（5 天）

```
改动范围：
├── 新增: cli/vulnguard.ts — Commander.js CLI
│   ├── vulnguard scan .
│   ├── vulnguard scan --format sarif
│   ├── vulnguard scan --output report.html
│   └── vulnguard baseline --diff HEAD~1
├── 新增: cli/ci.ts — CI 模式
│   └── --threshold critical=0,high=5
├── 修改: build-release.js — CLI 打包
└── 新增: GitHub Action action.yml
```

**预期效果**：开发者在终端直接使用，CI/CD 流水线可集成。

#### 6.4 前端基线集成（2 天）

```
改动范围：
├── 前端: 扫描详情页
│   ├── 新增 "新增 (N)" / "已存在 (M)" 标签
│   ├── 新增过滤下拉：全部 / 仅新增 / 仅已存在
│   └── 标记颜色：new=🔴、existing=🟡、排除=🟢
└── API: 复用 baseline.ts 的输出
```

**预期效果**：用户能清晰看到"这次改代码引入了什么新问题"。

### 第 2 个月：深度优化

#### 6.5 项目配置文件（3 天）

```yaml
# vulnguard.yaml
project:
  name: my-app
  languages: [typescript, go]

scanners:
  # 显式启用/禁用
  semgrep: enabled
  codeql: enabled
  trivy: disabled  # 太大，CI 里不跑

rules:
  # 自定义抑制
  suppress:
    - rule: "typescript/*"
      reason: "第三方代码不做检查"
      files: ["vendor/**"]
  thresholds:
    critical: 0
    high: 5
    medium: 20
```

#### 6.6 扫描队列 + 资源限制（5 天）

```typescript
interface ScanJob {
  id: string
  concurrencyLimit: number  // 并行扫描数（默认 2）
  memoryLimit: number       // MB
  timeout: number           // 单次扫描最长运行时间
}
```

#### 6.7 漏洞趋势图表（2 天）

已有 `VulnerabilityChart` 组件，补充时间序列数据即可。

#### 6.8 导出格式扩展（2 天）

- SARIF（已有 `sarif-converter.ts`，需要验证完整度）
- SPDX（依赖清单）
- CycloneDX

### 第 3 个月：专业级功能

| 功能 | 说明 | 预期效果 |
|------|------|---------|
| IDE 插件（VSCode） | 在编辑器中显示 inline 告警 | 开发者在写代码时即时发现 |
| 本地 LLM 模式 | Ollama/llama.cpp 替代 DeepSeek | 代码不出内网，合规 |
| GitHub Action | 开箱即用的 CI 集成 | 每个 PR 自动扫描 |
| 共享文件索引 | 扫描器共享文件解析缓存 | 性能提升 2-3 倍 |
| SARIF 完整导出 | 验证 + 补充缺失字段 | VS Code / GitHub TS 直接展示 |

---

## 7. 总结

### 7.1 一句话定位

> **VulnGuard 是"扫描器聚合器"而非"扫描器"**——它的价值不是自己有多强的检测能力，而是把 15+ 专业扫描器拧成一个有 UI、有 AI 编排、有基线对比的产品。

### 7.2 核心优势

- ✅ AI 驱动的扫描器编排（行业领先思路）
- ✅ 语言感知 + 技术栈自动识别
- ✅ 15+ 扫描器统一调度
- ✅ 完善的 Web UI（双语言）
- ✅ 基线对比（后端已实现）
- ✅ 安全头配置规范

### 7.3 核心短板（按修复优先级）

| 优先级 | 问题 | 状态 |
|--------|------|------|
| **P0** | 假阳性管理没有持久化回路 | ❌ |
| **P0** | 缺少增量扫描 | ❌ |
| **P0** | 缺少 CLI 工具 | ❌ |
| **P0** | 基线能力有后端但前端无入口 | ❌ |
| P1 | 扫描器健康检查不充分 | ⚠️ 部分 |
| P1 | 指纹匹配过于脆弱 | ⚠️ 部分 |
| P1 | 缺少 noise budget | ❌ |
| P1 | JS 依赖扫描缺少 pnpm/yarn fallback | ❌ |
| P1 | 扫描器无资源限制 | ❌ |
| P2 | IDE 集成 | ❌ |
| P2 | CI/CD 门禁 | ❌ |
| P2 | 本地 LLM 选项 | ❌ |

### 7.4 最终结论

> **如果把 P0 的四个问题修完（假阳性持久化抑制 / 增量扫描 / CLI 工具 / 前端基线入口），VulnGuard 在单机版定位下就超越了市面上所有同类工具。**
> 
> 它的架构设计比大多数商业产品更先进（AI 编排 + 规则回退双引擎），缺的只是最后 20% 的工程打磨。这 20% 就是把**后端已有的能力暴露到前端**，再加一个 CLI 入口。
