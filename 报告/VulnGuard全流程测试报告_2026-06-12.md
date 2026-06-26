# VulnGuard 全流程测试报告

**测试日期**: 2026-06-12  
**测试环境**: Windows 11, Node.js (Next.js 14.2.35), Python 3.12, Git Bash  
**测试范围**: TypeScript 编译、单元测试、页面路由、API 端点、扫描流程（Basic/AI 引擎）、误报管理、基线对比、文件上传、报告导出  
**测试方法**: 黑盒 + 白盒结合，逐接口验证 + 全流程端到端测试

---

## 1. 基础检查

| 项目 | 结果 | 耗时 |
|------|------|------|
| TypeScript 编译 (`tsc --noEmit`) | ✅ 通过 | 即时 |
| 单元测试 (vitest) | ✅ **42 文件 / 140 用例全部通过** | 24.5s |
| Dev Server 启动 | ✅ 正常 (port 3001) | 4.2s |
| 首页加载 (`GET /`) | ✅ HTTP 200 | 即时 |

**结论**: 项目代码质量良好，无编译错误，测试覆盖完整。

---

## 2. 页面路由测试

| 路由 | 预期 | 实际 | 结论 |
|------|------|------|------|
| `/` (仪表盘) | 200 | 200 | ✅ |
| `/scan/new` (新建扫描) | 200 | 200 | ✅ |
| `/scan/history` (扫描历史) | 200 | 200 | ✅ |
| `/reports` (报告页) | 200 | 200 | ✅ |
| `/settings` (设置) | 200 | 200 | ✅ |
| `/scan/[id]` (扫描详情) | 200 | 200 | ✅ |
| `/loading` | 404 | 404 | ✅ (loading.tsx 非独立路由) |

所有页面路由正常，暗色主题 UI 渲染正确。

---

## 3. 认证系统测试

| 场景 | 预期 | 实际 | 结论 |
|------|------|------|------|
| 无 `Authorization` 头 | 401 | `{"error":"未授权，请提供有效的 SCAN_AUTH_TOKEN"}` | ✅ |
| 无效 Bearer Token | 401 | `{"error":"未授权，请提供有效的 SCAN_AUTH_TOKEN"}` | ✅ |
| 有效 Bearer Token | 200/JSON | 正常返回数据 | ✅ |
| `?token=` 查询参数 | 200 | 支持 SSE 回退认证 | ✅ |

**结论**: 认证机制正确，支持 `Authorization: Bearer` 和 URL query 参数两种方式（后者为 SSE 兼容）。

---

## 4. API 端点测试

### 4.1 扫描管理

| 端点 | 请求方式 | 结果 | 说明 |
|------|---------|------|------|
| `GET /api/scans` | - | ✅ | 返回历史扫描列表，含风险评分/摘要 |
| `POST /api/scans` | `{target, mode, engine}` | ✅ | 创建扫描会话，返回 `{id, status:"pending"}` |
| `GET /api/scans/[id]` | - | ✅ | 返回完整扫描详情（漏洞/进度/扫描器状态） |
| `DELETE /api/scans/[id]` | - | ✅ | 删除扫描 + 清理上传目录 |
| `POST /api/scans/[id]/start` | - | ✅ | 触发后台扫描执行，返回 `{status:"scanning"}` |

### 4.2 实时进度

| 端点 | 结果 | 说明 |
|------|------|------|
| `GET /api/scan-progress/[id]` | ✅ | 返回 `{percent, currentScanner, elapsed, eta, scannerStatuses[]}` |

### 4.3 误报管理

| 端点 | 结果 | 说明 |
|------|------|------|
| `POST /api/scans/[id]/suppress` | ✅ | 需传 `{scanner, cve}` 或 `{scanner, id}` |
| `GET /api/scans/[id]/suppress` | ✅ | 返回所有忽略规则 |
| `DELETE /api/scans/[id]/suppress?pattern=` | ✅ | 按 pattern 精确删除 |

### 4.4 基线对比

| 端点 | 结果 | 说明 |
|------|------|------|
| `GET /api/scans/[id]/compare` | ✅ | 返回带 `baselineStatus` 的漏洞列表 |

### 4.5 ❌ 缺失 API

| 端点 | 结果 | 影响 |
|------|------|------|
| `GET /api/reports` | **404** | Reports 页面通过 `useScans()` 客户端获取数据，但缺少独立的报告 API |
| `GET /api/scans/[id]/sarif` | **404 (返回 HTML)** | SARIF 格式仅能通过客户端 `sarif-converter.ts` 生成，无 API 导出接口 |
| `GET /api/scans/[id]/report` | **404** | 无可用的报告下载 API |

### 4.6 文件上传

| 端点 | 结果 | 说明 |
|------|------|------|
| `POST /api/upload` (multipart) | ✅ | 返回 `{id, path, fileCount}` |
| `POST /api/upload` (JSON) | ❌ | 返回错误: 需要 multipart 格式 |

**结论**: 上传接口设计正确，仅接受 `multipart/form-data`，拒绝 JSON 提交符合安全最佳实践。

---

## 5. 扫描全流程端到端测试（核心）

### 5.1 Basic 引擎扫描

**目标**: `src/lib/scanner`（30 个 TypeScript 文件）

```
POST /api/scans { target: "src/lib/scanner", engine: "basic" }
  → POST /api/scans/[id]/start
    → runCompositeScan()
```

| 阶段 | 耗时 | 结果 | 详情 |
|------|------|------|------|
| Phase 0: 目标分析 | 6ms | ✅ | 30 文件, typescript, 无 config 文件 |
| Phase 1: 扫描器选择 | - | ❌ | **Semgrep 被丢弃**，仅选 3 个 |
| Phase 2: Gitleaks | ~5s | ✅ | 0 漏洞 |
| Phase 2: Trivy | ~5s | ✅ | 0 漏洞 |
| Phase 2: Nuclei | >60s | ⚠️ | 0 漏洞，长时间阻塞 |
| Phase 3: 误报过滤 | - | ✅ | 无可忽略项 |
| 总耗时 | ~70s | ✅ | 风险 A, 0 漏洞, 120 checks |

**❌ 问题: Basic 引擎 Semgrep 丢失**

`selectScannersByRules()` 代码中 `semgrep` 是 **always selected**（第 66 行），但在可用扫描器列表中被过滤掉了。排查发现：
- Semgrep 在系统 PATH 中确实存在（`/c/Users/.../semgrep`，v1.165.0）
- `resolveBin("semgrep", "semgrep.exe")` 应返回 PATH 中的 semgrep
- 但 AI 引擎扫描中 Semgrep 成功运行，说明 `isAvailable()` 存在偶发性失败

可能原因：Basic 与 AI 引擎走不同代码路径，Basic 引擎调用时 Semgrep 的 PATH 查找出现竞态条件。

### 5.2 AI 引擎扫描

**目标**: `src/lib/scanner`（30 个 TypeScript 文件）

```
POST /api/scans { target: "src/lib/scanner", engine: "ai" }
  → POST /api/scans/[id]/start
    → runCompositeScan()
      → createOrchestratorPlan() → FALLBACK (返回 null)
      → selectScannersByRules() → 4 scanners
      → executeScanners()
      → filterIgnored()
      → aggregateScanResults() → FALLBACK (规则回退)
```

| 扫描器 | 耗时 | 漏洞数 | 状态 |
|--------|------|--------|------|
| Semgrep | ~15s | **163** | ✅ |
| Gitleaks | ~5s | 0 | ✅ |
| Trivy | ~10s | 0 | ✅ |
| Nuclei | >50s | 0 | ⚠️ 阻塞 |
| **总计** | **~80s** | **161** (去重后) | ✅ |

**最终结果**: 风险 **F**, 161 漏洞（50 Critical, 66 High, 45 Medium）

**严重等级分布**:
- Critical: 50 (31%)
- High: 66 (41%)
- Medium: 45 (28%)
- Low: 0 (0%)

**漏洞来源**: 全部来自 Semgrep（Gitleaks/Trivy/Nuclei 对 TypeScript 源码无发现）

### 5.3 ❌ 关键问题: AI 编排器未被正确调用

扫描日志显示：
```
AI orchestrator analyzing target... → Rules selected 4 scanners
```

`createOrchestratorPlan()` 调用 DeepSeek API 但返回了 `null`，导致降级到 `selectScannersByRules()`。根本原因需排查：
- `llm-client.ts` 的 `callLlmJson` 调用是否成功
- DeepSeek API 响应格式是否符合 `OrchestratorPlan` 接口
- API key 是否有效（`.env.local` 中存在 `DEEPSEEK_API_KEY`）

### 5.4 ❌ 关键问题: AI 聚合器未被正确调用

扫描日志无 aggregation 条目，`aiAggregationReport` 内容显示：
```
规则回退聚合：161 个发现（严重: 50, 高危: 66, 中危: 45, 低危: 0）
```

`aggregateScanResults()` 同样降级到 `createFallbackReport()`，AI 交叉关联/假阳性检测未生效。

### 5.5 ❌ 中文字符编码问题

AI 聚合结果中的 `priorityActions` 字段出现 Unicode 乱码：
```
立即���50 ���严重漏洞 → 应为"立即处理 50 个严重漏洞"
优先处理 66 ���高危漏洞 → 应为"优先处理 66 个高危漏洞"
```

扫描日志中的 emoji 图标同样乱码：
```
馃攳 → 应为 🔍
馃搳 → 应为 📊
```

可能与 Windows 环境下 Python/Node.js 的 UTF-8 编码处理不一致有关。

### 5.6 ⚠️ Nuclei 选型问题

Nuclei 对源码目录 `src/lib/scanner` 的扫描耗时 **>60 秒**，0 发现。Nuclei 本质上是网络/Web 漏洞扫描器（基于 YAML 模板匹配），对本地 TypeScript 源码文件进行 filesystem 模式扫描属于使用场景错配。

---

## 6. 误报管理测试

### 6.1 创建忽略规则

```
POST /api/scans/[id]/suppress
Body: { scanner: "semgrep", cve: "C", comment: "false positive test" }
→ {"success": true, "pattern": "semgrep:C", "rules": 1}
```

### 6.2 查询规则

```
GET /api/scans/[id]/suppress
→ {"rules": [{"pattern":"semgrep:C", "source":"ui", "comment":"false positive test"}]}
```

### 6.3 删除规则

```
DELETE /api/scans/[id]/suppress?pattern=semgrep%3AC
→ {"success": true, "rules": 0}
```

**⚠️ 注意**: 删除需传入 URL 编码后的精确 pattern 值（`semgrep:C`），如果传 `semgrep:*`（glob 通配符）则不会匹配，删除静默失败（返回 count 无变化但 response 仍为 `success: true`）。建议对用户提示更清晰。

---

## 7. 扫描器可用性

| 扫描器 | 本地状态 | 注册表检测 | 实际运行 |
|--------|---------|-----------|---------|
| Semgrep v1.165.0 | ✅ PATH 中 | ✅ `resolveBin` | ✅ 163 发现 |
| Gitleaks | ✅ `tools/bin/gitleaks.exe` | ✅ | ✅ 0 发现 |
| Trivy | ✅ `tools/bin/trivy.exe` | ✅ | ✅ 0 发现 |
| Nuclei | ✅ `tools/bin/nuclei.exe` | ✅ | ⚠️ 超慢, 0 发现 |
| Bandit v1.9.4 | ✅ pip 安装 | ✅ | 未选择 (无 Python 目标) |
| Checkov v3.2.533 | ✅ pip 安装 | ✅ | 未选择 (无 IaC 目标) |
| npm-audit | ✅ `npm --version` 有效 | ✅ | 未选择 (无可扫描 config) |
| pip-audit | ❌ 未安装 | ❌ | - |
| Dependency-Check | ❌ 未安装 | ❌ | - |
| CodeQL | ❌ 未安装 | ❌ | - |
| TruffleHog | ❌ 未安装 | ❌ | - |
| Bearer | ❌ (Windows 不支持) | ❌ | - |
| OSV-Scanner | ❌ 未安装 | ❌ | - |
| Scorecard | ❌ 未安装 | ❌ | - |
| CVE-CPP | - | ✅ (始终可用) | 未选择 |
| Swift | - | ✅ (始终可用) | 未选择 |
| AI Code Review | - | ✅ (有 API key) | 未选择 (仅 AI/all 引擎) |

---

## 8. 问题清单

### P0 — 功能阻塞

| # | 问题 | 文件/位置 | 描述 |
|---|------|-----------|------|
| 1 | **Missing API: SARIF/Report 导出** | `src/app/api/scans/[id]/` | 缺少 `/sarif` 和 `/report` 的 API 路由，`/api/reports` 同样不存在。SARIF 仅能在客户端通过 `sarif-converter.ts` 生成 |
| 2 | **Nuclei 对源码扫描不适用** | `src/lib/scanner/nuclei.ts` | Nuclei 对纯源码目录扫描耗时 >60s、0 发现，本质是网络扫描器 |

### P1 — 严重

| # | 问题 | 文件/位置 | 描述 |
|---|------|-----------|------|
| 3 | **Basic 引擎 Semgrep 静默丢失** | `src/lib/scanner/composite.ts` | `selectScannersByRules()` 通过 `availableNames.includes(n)` 过滤时，Semgrep 的 `isAvailable()` 偶发返回 false，导致 Basic 引擎丢掉了核心 SAST 扫描器 |
| 4 | **AI 编排器降级** | `src/lib/scanner/orchestrator.ts` | `createOrchestratorPlan()` 调用 DeepSeek 后返回 null，导致降级到规则回退，AI 智能选型未生效 |
| 5 | **AI 聚合器降级** | `src/lib/scanner/ai-aggregator.ts` | `aggregateScanResults()` 同样降级到 `createFallbackReport()`，交叉关联和假阳性检测未生效 |

### P2 — 一般

| # | 问题 | 文件/位置 | 描述 |
|---|------|-----------|------|
| 6 | **中文编码乱码** | AI 响应处理 | DeepSeek 返回的中文在存储/展示时出现 Unicode 乱码（`\udcae`），扫描日志中的 emoji 也显示为原始码点 |
| 7 | **Nuclei 进程驻留** | 进程管理 | 扫描完成后 `nuclei.exe` 进程未退出，常驻 ~55MB 内存 |

### P3 — 轻微

| # | 问题 | 文件/位置 | 描述 |
|---|------|-----------|------|
| 8 | **Suppress 删除无 pattern 校验** | `src/app/api/scans/[id]/suppress/route.ts` | pattern 不匹配时返回 `success: true` 但规则未被实际删除，应返回 pattern 未找到的提示 |
| 9 | **扫描日志存储膨胀** | `.scans/` 目录 | 每次扫描在 `.scans/` 下生成 JSON 文件，含完整漏洞列表和日志，无自动清理机制 |

---

## 9. 测试清单

### ✅ 通过项

- [x] TypeScript 类型检查
- [x] 单元测试全部通过
- [x] 所有页面路由 200
- [x] API 认证机制
- [x] 扫描会话创建
- [x] 扫描启动/执行
- [x] 扫描完成/风险评分
- [x] 文件上传
- [x] 误报标记/查询/删除
- [x] 基线对比
- [x] 扫描详情页渲染
- [x] 实时进度轮询

### ❌ 未通过/异常

- [ ] Basic 引擎完整扫描 (Semgrep 丢失)
- [x] AI 引擎扫描 (完成但有降级)
- [ ] 报告 API 导出
- [ ] SARIF 导出
- [ ] Nuclei 源码扫描性能
- [ ] 中文编码正确性

### ⚠️ 未测试项

- [ ] 容器镜像扫描 (trivy-image, 需 Docker)
- [ ] 容器化部署 (Docker Compose)
- [ ] CI/CD 集成 (GitHub Actions Webhook)
- [ ] SSE 推送端点完整验证 (EventSource)
- [ ] Webhook 通知 (需 WEBHOOK_URL 配置)
- [ ] SBOM 生成 (依赖 Trivy CycloneDX 输出)
- [ ] 扫描基线 (baseline.ts)
- [ ] 大文件/超大规模仓库扫描
- [ ] 并发多扫描同时执行

---

## 10. 测试结论

**整体评级: ⚠️ 核心流程可跑通，AI 能力未生效**

扫描引擎能够正常启动、执行、完成并生成结果报告，核心流程链路是通的。但以下三个关键设计目标未达预期：

| 设计目标 | 实际表现 | 差距 |
|---------|---------|------|
| AI 编排智能选型 | 降级到规则回退，始终选择固定 4 个扫描器 | ❌ 关键 |
| AI 聚合交叉关联/假阳性检测 | 降级到规则去重，161 个结果 0 假阳性去除 | ❌ 关键 |
| 多引擎多扫描器协同 | 仅 Semgrep 产生有效结果，其他扫描器对 TS 项目 0 发现 | ⚠️ 部分 |

**建议优先修复**: AI 编排器/聚合器的 DeepSeek 调用问题（P1 #4 #5），这是 VulnGuard 相对传统 SAST 的核心差异化能力。
