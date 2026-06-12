# VulnGuard 全面测试方案

## 一、现状总结

```
生产代码: 11,336 行 / 76 文件
测试代码:     91 行 / 3 文件
测试涵盖: ~6%（仅 i18n、cn()、mock-data 格式）
```

**瓶颈**: 扫描器依赖外部二进制，AI 功能依赖 DeepSeek API，这两项缺乏 mock 基础设施导致测试门槛高。

---

## 二、架构分析 — 可测试性评估

### 依赖关系图

```
┌────────────────────────────────────────────┐
│  API Routes (app/api/)                     │
│  POST /api/scans → start → composite.ts    │
└────────────┬───────────────────────────────┘
             │ calls
┌────────────▼──────────────────────────────┐
│  composite.ts                              │
│  → analyzeTarget()                         │
│  → createOrchestratorPlan() / fallback     │
│  → executeScanners()                       │
│  → filterIgnored()                         │
│  → aggregateScanResults() / fallback       │
└───────┬────────────────────┬──────────────┘
        │                    │
┌───────▼──────┐    ┌───────▼──────────┐
│  scanners/   │    │  llm-client.ts   │
│  (18个扫描器) │    │  → DeepSeek API  │
│  → exec.ts   │    └──────────────────┘
│  → 外部二进制  │
└──────────────┘
```

### 可测试性分级

| 层级 | 组件 | 测试方式 | 难度 |
|------|------|---------|------|
| **L0** | `utils.ts`, `types.ts`, `manifest.ts`, `ignore-rules.ts` | 纯函数，无依赖 | ★☆☆ |
| **L1** | `scan-store.ts`, `scan-log.ts`, `baseline.ts`, `sarif-converter.ts` | 文件系统/纯函数 | ★★☆ |
| **L2** | `target-analyzer.ts`, `semgrep.ts`, `bandit.ts`, `gitleaks.ts` ... | mock `execAsync` | ★★☆ |
| **L3** | `orchestrator.ts`, `ai-aggregator.ts`, `ai-scanner.ts` | mock `callLlmJson` | ★★★ |
| **L4** | `composite.ts`, `registry.ts` | mock 多个依赖 | ★★★ |
| **L5** | API Routes, Pages, Components | 集成测试 + 组件测试 | ★★★ |

---

## 三、分阶段实施方案

### 阶段 0 — 搭建测试基础设施（0.5 天）

**安装依赖**:
```bash
npm install -D @vitest/coverage-v8 @testing-library/react @testing-library/jest-dom msw
```

**创建 mock 工厂** — 这是最关键的一步，决定了后续所有测试的可写性：

```typescript
// src/__tests__/helpers/scanner-mock.ts
// 统一的 execAsync mock，让每个 scanner 测试都能注入假输出
import { vi } from "vitest"

// Mock child_process 模块
vi.mock("child_process", () => ({
  exec: vi.fn(),
  execSync: vi.fn(),
}))

// 辅助函数：让 execAsync 返回假输出
export function mockExecAsync(stdout: string) {
  const { exec } = require("child_process")
  exec.mockImplementation((cmd, opts, cb) => {
    cb(null, stdout, "")
    return { on: vi.fn() }
  })
}
```

**覆盖率配置**:
```typescript
// vitest.config.ts 补充
test: {
  coverage: {
    provider: "v8",
    include: ["src/lib/**", "src/app/api/**"],
    exclude: ["src/__tests__/**", "src/lib/api/mock-data.ts"],
    thresholds: {
      lines: 60,  // 阶段目标，逐步提高
    }
  }
}
```

### 阶段 1 — 核心逻辑测试（关键路径，2-3 天）

#### 1.1 `ignore-rules.ts` 误报过滤

这是最独立的模块之一，纯函数逻辑。

```typescript
// src/__tests__/ignore-rules.test.ts

// 测试内容：
// 1. globMatch("*", "anything") → true
// 2. globMatch("trivy:CVE-*", "trivy:CVE-2024-12345") → true
// 3. globMatch("semgrep:SG-*", "semgrep:SG-1") → true
// 4. filterIgnored — 按 scanner 过滤
// 5. filterIgnored — 按 CVE 过滤
// 6. filterIgnored — 通配符 scanner:*
// 7. getVulnKey — 生成正确 key 格式
// 8. parseIgnoreFile — 解析 # 注释、空行
// 9. 规则优先级：UI 规则覆盖文件规则
```

**预计行数**: ~80 行 / ~15 个用例  
**覆盖新文件**: `src/lib/ignore-rules.ts`（207 行）

#### 1.2 `scan-store.ts` 扫描存储

```typescript
// src/__tests__/scan-store.test.ts

// vitest 用 vi.mock("fs") 来 mock 文件系统
// 测试内容：
// 1. createSession — 生成唯一 id、正确初始状态
// 2. updateSession — 更新字段合并
// 3. getSession — 按 id 查找
// 4. getAllSessions — 返回排序列表
// 5. deleteSession — 删除会话
// 6. toScanSummary — 字段映射正确
// 7. toScanDetail — 完整详情包含 vulnerabilities
// 8. cleanupUploadDir — 清理逻辑
```

**预计行数**: ~100 行 / ~15 个用例  
**覆盖新文件**: `src/lib/scanner/scan-store.ts`

#### 1.3 `sarif-converter.ts` SARIF 转换

```typescript
// src/__tests__/sarif-converter.test.ts

// 测试内容：
// 1. convertToSarif — 基本漏洞转换
// 2. convertToSarif — 严重等级映射
// 3. convertToSarif — 位置解析 (file:line, file:line:col)
// 4. convertToSarif — 空列表
// 5. getSarifFilename — 文件名生成
```

**预计行数**: ~50 行 / ~8 个用例  
**覆盖新文件**: `src/lib/sarif-converter.ts`

### 阶段 2 — 扫描器单元测试（3-4 天）

#### 2.1 建立统一测试模式

每个扫描器都遵循相同的模式：

```
execAsync("scanner-command --json target")
  ↓ stdout (成功时)
  ↓ 或 stderr (非零退出时，如 gitleaks 找到 secret)
  ↓ 或 throw (出错时)
JSON.parse(stdout) → 扫描器特定格式
  ↓
.map() → Vulnerability[]
```

统一的测试夹具：

```typescript
// src/__tests__/fixtures/scanner-outputs.ts

// 每个扫描器的假 JSON 输出
export const gitleaksOutput = JSON.stringify([{
  Description: "Hardcoded password",
  File: "src/config.ts",
  StartLine: 42,
  RuleID: "hardcoded-password",
  Secret: "123456",
  Entropy: 4.5,
  // ...
}])

export const semgrepOutput = JSON.stringify({
  results: [{ check_id: "SG-1", path: "src/app.ts", ... }],
  paths: { scanned: ["src/app.ts"] },
})
```

#### 2.2 扫描器测试模板

```typescript
// src/__tests__/scanners/gitleaks.test.ts
// src/__tests__/scanners/semgrep.test.ts
// src/__tests__/scanners/trivy.test.ts
// src/__tests__/scanners/npm-audit.test.ts
// src/__tests__/scanners/bandit.test.ts
// ... 每个扫描器一个文件

// 每个扫描器测试覆盖：
// 1. 正常扫描 → 解析假 JSON → 验证 Vulnerability 数组
// 2. 空结果 → 返回空数组
// 3. 扫描器不可用 → 返回 errors
// 4. 非零退出但有 stdout → 提取输出（gitleaks 模式）
// 5. 超时 → 错误处理
// 6. JSON 解析失败 → 错误处理
// 7. 严重等级映射正确
```

#### 2.3 测试示例（以 gitleaks 为例）

```typescript
import { describe, it, expect, vi, beforeEach } from "vitest"

// Mock 在整个文件顶部
vi.mock("child_process")

// 或者 mock exec.ts 模块
vi.mock("@/lib/scanner/exec", () => ({
  execAsync: vi.fn(),
}))

describe("Gitleaks scanner", () => {
  beforeEach(() => { vi.clearAllMocks() })

  it("parses JSON output into vulnerabilities", async () => {
    const { execAsync } = await import("@/lib/scanner/exec")
    execAsync.mockResolvedValue({
      stdout: JSON.stringify([{
        Description: "Hardcoded credentials",
        File: "src/.env",
        StartLine: 1,
        RuleID: "hardcoded-password",
        Secret: "admin123",
        Entropy: 3.5,
      }]),
      stderr: "",
    })

    const { runGitleaksScan } = await import("@/lib/scanner/gitleaks")
    const result = await runGitleaksScan("/fake/path")

    expect(result.vulnerabilities).toHaveLength(1)
    expect(result.vulnerabilities[0].severity).toBe("High")
    expect(result.vulnerabilities[0].source).toBe("gitleaks")
    expect(result.errors).toHaveLength(0)
  })

  it("returns errors when scanner is unavailable", async () => {
    // mock isAvailable 返回 false
    // 验证返回 { vulnerabilities: [], errors: ["Gitleaks not found"] }
  })

  it("captures output from non-zero exit (gitleaks leak found)", async () => {
    const { execAsync } = await import("@/lib/scanner/exec")
    const error = new Error("leaks found")
    error.stdout = JSON.stringify([{ Description: "API Key", File: "config.js", StartLine: 10 }])
    execAsync.mockRejectedValue(error)

    const { runGitleaksScan } = await import("@/lib/scanner/gitleaks")
    const result = await runGitleaksScan("/fake/path")
    expect(result.vulnerabilities).toHaveLength(1)
  })
})
```

**预计行数**: 每个扫描器 ~50 行 × 14 个需 mock 的扫描器 = ~700 行  
**覆盖新文件**: 14 个扫描器文件

### 阶段 3 — AI 编排测试（1-2 天）

#### 3.1 mock LLM 客户端

```typescript
// src/__tests__/helpers/llm-mock.ts

vi.mock("@/lib/scanner/llm-client", () => ({
  isLlmAvailable: vi.fn(() => true),
  callLlmJson: vi.fn(),
  callLlm: vi.fn(),
}))
```

#### 3.2 `orchestrator.ts` 测试

```typescript
// src/__tests__/orchestrator.test.ts
// 1. createOrchestratorPlan — DeepSeek 返回有效 Plan
// 2. createOrchestratorPlan — DeepSeek 返回 null → fallback
// 3. createOrchestratorPlan — DeepSeek API 超时 → fallback
// 4. createFallbackPlan — 规则引擎选择
// 5. buildParallelGroups — 按类别分组
// 6. 决策 prompt 的构建
```

#### 3.3 `ai-aggregator.ts` 测试

```typescript
// src/__tests__/ai-aggregator.test.ts
// 1. aggregateScanResults — 正常聚合
// 2. aggregateScanResults — 假阳性检测
// 3. aggregateScanResults — AI 不可用 → fallback
// 4. createFallbackReport — 确定性去重
// 5. 80+ findings → 分批
```

#### 3.4 `ai-scanner.ts` 测试

```typescript
// src/__tests__/ai-scanner.test.ts
// 1. 文件收集 — 支持扩展名过滤
// 2. 文件收集 — SKIP_DIRS 跳过
// 3. 文件收集 — 大文件跳过
// 4. 文件收集 — 行数限制
// 5. 分批发送
// 6. 结果去重
// 7. getStrategy — 不同文件数策略
```

**预计行数**: ~300 行 / ~35 个用例  
**覆盖新文件**: `orchestrator.ts`, `ai-aggregator.ts`, `ai-scanner.ts`, `llm-client.ts`

### 阶段 4 — 编排引擎集成测试（2 天）

#### 4.1 `composite.ts` 测试

这是最复杂的模块，需要 mock：

```typescript
// src/__tests__/composite.test.ts

// Mock 所有依赖
vi.mock("@/lib/scanner/orchestrator")
vi.mock("@/lib/scanner/ai-aggregator")
vi.mock("@/lib/scanner/registry", () => ({
  getAvailableScanners: vi.fn(),
  getAllScanners: vi.fn(),
}))
vi.mock("@/lib/scanner/target-analyzer")
vi.mock("../ignore-rules")

// 测试内容：
// 1. runCompositeScan — AI 编排路径
// 2. runCompositeScan — 规则回退路径  
// 3. 三阶段并行执行
// 4. 进度跟踪更新
// 5. 误报过滤
// 6. selectScannersByRules — 语言检测匹配
// 7. selectScannersByRules — 引擎模式区别
// 8. buildParallelGroups — 分组
// 9. 结果聚合去重
// 10. isRealCve 标记
```

#### 4.2 `target-analyzer.ts` 测试

```typescript
// src/__tests__/target-analyzer.test.ts
// 1. 纯 TS 项目检测
// 2. 纯 Python 项目检测
// 3. 混合项目检测
// 4. IaC 文件检测
// 5. 语言统计
// 6. 空目录处理
// 7. 权限错误处理
```

**预计行数**: ~200 行 / ~25 个用例  
**覆盖新文件**: `composite.ts`, `target-analyzer.ts`, `registry.ts`

### 阶段 5 — API 集成测试（2 天）

#### 5.1 使用 MSW 搭建 mock 服务器

```bash
npm install -D msw
```

```typescript
// src/__tests__/helpers/api-server.ts
import { setupServer } from "msw/node"
import { http, HttpResponse } from "msw"

export const handlers = [
  // Mock DeepSeek API
  http.post("https://api.deepseek.com/chat/completions", () => {
    return HttpResponse.json({
      choices: [{ message: { content: JSON.stringify({ vulnerabilities: [] }) } }],
    })
  }),
]

export const server = setupServer(...handlers)
```

#### 5.2 API 路由测试

```typescript
// src/__tests__/api/scans.test.ts
// 1. POST /api/scans — 创建扫描
// 2. POST /api/scans — 缺少参数
// 3. GET /api/scans — 列表
// 4. GET /api/scans/[id] — 详情
// 5. POST /api/scans/[id]/start — 启动
// 6. POST /api/scans/[id]/suppress — 误报标记
// 7. DELETE /api/scans/[id] — 删除
// 8. 各种认证场景
```

**预计行数**: ~200 行 / ~20 个用例  
**覆盖新文件**: 9 个 API 路由文件

### 阶段 6 — 组件测试（可选，2 天）

```bash
npm install -D @testing-library/react @testing-library/user-event
```

```typescript
// src/__tests__/components/severity-badge.test.tsx
// src/__tests__/components/vulnerability-list.test.tsx
// src/__tests__/pages/dashboard.test.tsx
// src/__tests__/pages/scan-detail.test.tsx
```

---

## 四、执行计划汇总

| 阶段 | 内容 | 文件数 | 新增用例 | 预计行数 | 新增覆盖率 | 工作量 |
|------|------|--------|---------|---------|-----------|--------|
| 0 | 基础设施搭建 | 3 | 0 | ~30 | 0% | 0.5天 |
| 1 | 核心逻辑测试 | 3 | ~38 | ~230 | ~5% | 2-3天 |
| 2 | 扫描器单元测试 | 14 | ~98 | ~700 | ~25% | 3-4天 |
| 3 | AI 编排测试 | 4 | ~35 | ~300 | ~10% | 1-2天 |
| 4 | 编排引擎集成 | 3 | ~25 | ~200 | ~8% | 2天 |
| 5 | API 集成测试 | 9 | ~20 | ~200 | ~12% | 2天 |
| 6 | 组件测试(可选) | ~12 | ~40 | ~300 | ~10% | 2天 |
| **合计** | | **~48** | **~256** | **~1960** | **~70%** | **12-16天** |

### 里程碑效果

```
阶段0-1后:   ~10%  — 核心逻辑有保障
阶段2后:     ~35%  — 所有扫描器有单元测试
阶段3-4后:   ~50%  — AI 能力和编排引擎受控
阶段5后:     ~65%  — API 端点有集成测试
阶段6后(可选): ~75% — 前端组件有覆盖
```

---

## 五、关键设计决策

### 决策 1: mock 子进程 > mock 单个扫描器

```
❌ mock 每个扫描器内部逻辑
   → 侵入性强，扫描器代码变更需要改 mock
   → 每个扫描器的 mock 都要理解其内部实现

✅ mock execAsync（统一的外部命令调用层）
   → exec.ts 是所有扫描器的唯一外部依赖
   → mock 一个点覆盖所有扫描器
   → 扫描器代码可自由重构，mock 不变
```

### 决策 2: 按类别选代表性扫描器

18 个扫描器有大量重复模式，不需要全部独立测试：

| 类别 | 模式 | 需完整测试 | 可简化 |
|------|------|-----------|--------|
| secret | gitleaks, trufflehog | gitleaks | trufflehog 仅测基本流程 |
| sast | semgrep, bandit, bearer, codeql | semgrep | 其余测模板逻辑 |
| dependency | npm-audit, pip-audit, osv-scanner, dep-check, cve-cpp, swift | npm-audit | 其余测模板逻辑 |
| filesystem | trivy, checkov, nuclei, scorecard | trivy | 其余测模板逻辑 |
| ai | ai-scanner, orchestrator, aggregator | 全部 | 核心差异化能力 |

### 决策 3: 优先测试边界条件

扫描器测试按优先级排列：

```
P0: 解析成功路径（正常 JSON 输出 → Vulnerability[]）
P1: 错误处理（空输出、非零退出、超时）
P2: 边界条件（空结果、大量结果、特殊字符）
P3: 映射正确性（severity 映射、source 字段、id 格式）
```

---

## 六、风险与缓解

| 风险 | 影响 | 缓解 |
|------|------|------|
| 扫描器输出格式变化 | 测试假阳性 | 使用真实输出的快照测试 |
| 文件系统 mock 不稳定 | 测试假阴性 | 使用 `memfs` 库 mock fs |
| AI 响应格式漂移 | AI 测试失效 | 固定 mock JSON 响应 |
| Windows 兼容性 | execAsync 路径处理 | CI 使用 Linux/macOS runner |
| 没有测试时间预算 | 阶段 2-5 做不完 | 从阶段 0-1 开始，逐步推进 |

---

## 七、立即可以开始的工作（第 1 天）

```bash
# 1. 装依赖
npm install -D @vitest/coverage-v8

# 2. 写第一个真正有用的测试
cat > src/__tests__/ignore-rules.test.ts << 'EOF'
import { describe, it, expect } from "vitest"
import { filterIgnored, getVulnKey } from "@/lib/ignore-rules"
// ... 开始写测试
EOF

# 3. 跑覆盖率
npx vitest run --coverage

# 4. 看见基线
# 5. 每加一个文件，看覆盖率上升
```
