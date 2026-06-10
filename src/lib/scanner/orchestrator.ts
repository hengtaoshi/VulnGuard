import { SCANNER_MANIFEST } from "./manifest"
import type { ScannerManifestEntry } from "./manifest"

const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || "deepseek-v4-flash"
const DEEPSEEK_API_URL = process.env.DEEPSEEK_BASE_URL
  ? process.env.DEEPSEEK_BASE_URL + "/v1/chat/completions"
  : "https://api.deepseek.com/v1/chat/completions"

export type ScanPriority = "speed" | "depth" | "balanced"

export interface ScanPlan {
  reasoning: string
  selectedScanners: string[]
  parallelGroups: string[][]
  aiReview: boolean
  scanPriority: ScanPriority
}

export interface OrchestratorInput {
  mode: "url" | "source"
  target: string
  availableScannerNames: string[]
  engine: "ai" | "all"
}

// ─── System Prompt ───────────────────────────────────────────────────────────

function buildSystemPrompt(manifest: ScannerManifestEntry[]): string {
  return `你是一位专业的安全扫描编排专家，你的职责是分析扫描目标并制定最优的扫描计划。

重要：reasoning 字段必须使用中文描述。

## 可用扫描引擎清单

以下是所有可用的扫描引擎及其能力、检测类型和耗时。

${JSON.stringify(manifest, null, 2)}

## 决策框架

### Step 1: 目标分析
分析目标 URL/路径的特征，判断以下维度：
- **协议类型**: HTTP vs HTTPS（HTTPS 需要 TLS 证书检查）
- **目标类型**: API 端点（含 /api/、/graphql、/v1/ 等） vs Web 页面 vs 静态站点
- **技术推断**: 从 URL 路径推断可能的底层技术（如 .php、.aspx、/wp-content/ 等）
- **域名特征**: 主域名 vs 子域名（子域名可能指向不同服务）
- **是否可能有API**: 包含 /api、/rest、/graphql 等路径

### Step 2: 扫描类别选择
根据目标分析结果，从以下类别中选择合适的扫描类别：

**a) DNS 信息收集**（仅域名目标时使用）
- subfinder: 快速被动子域名枚举，从30+数据源聚合
- assetfinder: 轻量子域名发现
- shuffledns: DNS 解析验证（配合 subfinder 使用）
- amass: 深度 DNS 枚举（耗时较长，仅对复杂目标使用）

**b) 端口扫描**（需要知道开放服务时使用）
- nmap: 端口扫描+服务版本检测（耗时较长）
  *注意：仅在需要深度探测时使用，快速检查不需要*

**c) Web 指纹识别与探测**（所有 Web 目标均适用）
- httpx: HTTP 探针，检测存活、技术栈、响应头、favicon
- whatweb: 1800+ 插件的技术栈深度识别

**d) WAF 检测**（所有 Web 目标均适用）
- wafw00f: 识别 150+ 种 WAF 产品

**e) 目录与文件扫描**（需要发现隐藏路径时使用）
- ffuf: 高性能目录/参数模糊测试（首选）
- gobuster: 目录枚举+虚拟主机发现
- kiterunner: API 端点发现（目标含 API 时强烈推荐）

**f) 敏感信息泄露检测**（所有 Web 目标均适用）
- gitdumper: 检测 .git 目录暴露
- gau: 从历史存档中收集 URL
- waybackurls: 从 Wayback Machine 收集历史 URL

**g) Web 漏洞被动分析**（所有 Web 目标均适用）
- http-headers: 安全头检测（HSTS/CSP/XFO/CTO等）
- cors-detector: CORS 配置缺陷检测
- form-analyzer: 表单提交安全性分析
- error-analyzer: 错误页信息泄露检测
- favicon-analyzer: Favicon 哈希分析
- third-party-deps: 第三方库漏洞检测

**h) TLS/SSL 证书审查**（仅 HTTPS 目标）
- tls-analyzer: 证书有效期、协议版本、弱加密套件检测

**i) Web 漏洞深度扫描**（需要主动测试时使用）
- nuclei: 模板化漏洞扫描（8000+ 模板）
- wapiti: DAST 综合扫描（SQL/XSS/命令注入等）
- sqlmap: SQL 注入自动化检测（检测到注入点时使用）

**j) AI 深度分析**（全场景）
- ai-scanner: AI 辅助代码/逻辑漏洞分析

### Step 3: 引擎模式规则

**"ai" 引擎模式** — 智能自适应（根据目标动态选择覆盖深度）：
- 根据目标分析结果动态决定覆盖范围，兼顾效率与全面性
- DNS 类：仅选择 subfinder（快速被动），跳过 amass（太慢）
- Web 指纹：httpx 必须选（快速），whatweb 可选
- 被动分析：所有 Node.js 原生检测全部选择（零耗时快）
- TLS：仅 HTTPS 目标时选择
- 目录扫描：首选 ffuf（最快），skip kiterunner 除非发现 API
- 深度扫描激活规则（以下任一条件满足时，wapiti/sqlmap/nuclei 必须选择）：
  * 目标包含表单（form 标签、登录页、注册页）
  * URL 路径包含 /api/、/graphql、/rest、/v1/、/v2/ 等 API 特征
  * 目标包含文件上传功能（upload、file）
  * 目标 URL 看起来是动态 Web 应用（非静态 HTML）
  * 目标包含搜索功能、用户输入参数（?id=、?q=、?page= 等）
  * 经 httpx 检测有技术栈指纹（表明是动态框架而非静态站点）
- 当上述条件**都不满足**（明确为静态站点）时：可跳过深度扫描

**"all" 引擎模式** — 最大覆盖：
- 选择所有可用的相关扫描器
- DNS：subfinder + assetfinder + shuffledns，复杂目标加 amass
- 端口：如果 nmap 可用则选择
- 目录：ffuf + gobuster + kiterunner
- Web 指纹：httpx + whatweb
- OSINT：gau + waybackurls
- 被动分析：全部选择
- TLS：HTTPS 必选
- 深度扫描：nuclei + wapiti + sqlmap（如相关）
- 始终设置 aiReview = true

### Step 4: 并行分组策略

**URL 模式下的分组规则：**
- **Phase 1 — 快速被动检测组（并行执行）**：
  httpx、http-headers、cors-detector、tls-analyzer（HTTPS）、
  favicon-analyzer、error-analyzer、form-analyzer、third-party-deps、
  wafw00f、gau、waybackurls
  *原因：所有都是轻量级请求，互不依赖*
  *最大并发：不限*

- **Phase 2 — 信息收集组（并行执行）**：
  subfinder、assetfinder、whatweb、gitdumper
  *原因：DNS 和轻量 Web 探测可同时进行*
  *最大并发：4*

- **Phase 3 — 主动探测组（并行执行）**：
  ffuf、gobuster、kiterunner、shuffledns（需 subfinder 完成后）、nuclei
  *原因：这些工具会发起大量请求，但互不干扰*
  *注意：shuffledns 建议在 subfinder 之后执行*

- **Phase 4 — 深度扫描组（串行）**：
  wapiti、sqlmap、nmap、amass
  *原因：这些工具耗时久、资源消耗大，逐一执行*
  *注意：sqlmap 仅在检测到注入点时由 AI 决定是否启用*

- **Phase 5 — AI 汇聚分析（最后执行）**：
  ai-scanner + AI 聚合

### Step 5: 扫描优先级调整

- **speed（速度优先）** — 仅当目标为以下情况时选择：
  * 静态站点（纯 HTML/CSS/JS，无表单、无API、无动态参数）
  * 已知的 CDN、文档站点、博客
  * 快速健康检查场景
  * 仅选择 Phase 1 + Phase 2，跳过 Phase 3/4

- **balanced（均衡）** — 标准 Web 应用：
  * 含表单或基本交互功能的网站
  * 需检查常见 Web 漏洞但无需深度 SQL 注入
  * 选择 Phase 1 + Phase 2 + Phase 3（含 nuclei），跳过 Phase 4

- **depth（深度优先）** — 高价值/高风险目标：
  * 含 API 端点（/api/、/graphql、/rest）
  * 含登录/注册/文件上传功能
  * 含用户输入参数（?id=、?q=、?file= 等）
  * 电商、金融、后台管理系统
  * 经 httpx 检测出具体技术栈框架
  * **选择所有 Phase，包含 wapiti/sqlmap/nuclei**

- **重要规则**：当目标为 URL 模式时，如果无法确定目标类型，**默认使用 balanced 或 depth** 而非 speed，以确保注入漏洞不被遗漏
- "all" 引擎强制使用 depth 优先级

## 输出格式
只返回 JSON，不要 markdown 代码块，不要额外说明。reasoning 字段必须用中文描述。

{
  "reasoning": "简要说明选择了哪些工具以及为何选择（中文，2-3句话）",
  "selectedScanners": ["name1", "name2", ...],
  "parallelGroups": [
    ["name1", "name2", "name3"],
    ["name4", "name5"],
    ...
  ],
  "aiReview": true 或 false,
  "scanPriority": "speed" | "depth" | "balanced"
}`
}

// ─── DeepSeek Call ──────────────────────────────────────────────────────────

async function callDeepSeek(systemPrompt: string, userPrompt: string): Promise<string> {
  const apiKey = process.env.DEEPSEEK_API_KEY
  if (!apiKey) {
    throw new Error("DEEPSEEK_API_KEY not configured. Set the DEEPSEEK_API_KEY environment variable.")
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 30000)

  try {
    const res = await fetch(DEEPSEEK_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + apiKey,
      },
      body: JSON.stringify({
        model: DEEPSEEK_MODEL,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        temperature: 0.1,
        max_tokens: 2048,
      }),
      signal: controller.signal,
    })

    const json = await res.json()

    // Check for API-level errors in response body (e.g., invalid model, auth failure)
    if (json.error) {
      throw new Error(`DeepSeek API error: ${json.error.message || JSON.stringify(json.error)}`)
    }

    if (!res.ok) {
      throw new Error(`DeepSeek API error ${res.status}: ${JSON.stringify(json).slice(0, 200)}`)
    }

    const msg = json.choices?.[0]?.message
    if (!msg) {
      throw new Error("DeepSeek returned empty response (no choices)")
    }

    // Reasoning models (deepseek-v4-flash, deepseek-reasoner) put the response
    // in `reasoning_content` while non-reasoning models use `content`.
    return msg.content || msg.reasoning_content || ""
  } finally {
    clearTimeout(timeout)
  }
}

// ─── Response Parsing ────────────────────────────────────────────────────────

function extractJSON(text: string): string {
  const start = text.indexOf("{")
  const end = text.lastIndexOf("}")
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("No JSON object found in orchestrator response: " + text.slice(0, 200))
  }
  return text.slice(start, end + 1)
}

function parseScanPlan(content: string, availableNames: string[]): ScanPlan {
  const cleaned = extractJSON(content)

  let parsed: any
  try {
    parsed = JSON.parse(cleaned)
  } catch {
    throw new Error("Failed to parse orchestrator response as JSON: " + cleaned.slice(0, 200))
  }

  if (!Array.isArray(parsed.selectedScanners) || parsed.selectedScanners.length === 0) {
    throw new Error("Orchestrator returned empty or invalid selectedScanners")
  }

  // Filter to only available scanners
  const filtered = parsed.selectedScanners.filter((n: any) => availableNames.includes(n))
  if (filtered.length === 0) {
    throw new Error("No selected scanners are available on this system")
  }

  // Validate or derive parallelGroups
  let parallelGroups: string[][]
  if (Array.isArray(parsed.parallelGroups) && parsed.parallelGroups.length > 0) {
    const flat = parsed.parallelGroups.flat()
    const allInPlan = filtered.every((n: string) => flat.includes(n))
    if (allInPlan) {
      parallelGroups = parsed.parallelGroups
        .map((g: any[]) => g.filter((n: any) => availableNames.includes(n)))
        .filter((g: any[]) => g.length > 0)
    } else {
      parallelGroups = [filtered]
    }
  } else {
    parallelGroups = [filtered]
  }

  const validPriorities: ScanPriority[] = ["speed", "depth", "balanced"]
  const scanPriority: ScanPriority = validPriorities.includes(parsed.scanPriority)
    ? parsed.scanPriority
    : "balanced"

  return {
    reasoning: typeof parsed.reasoning === "string" ? parsed.reasoning : "",
    selectedScanners: filtered,
    parallelGroups,
    aiReview: parsed.aiReview === true,
    scanPriority,
  }
}

// ─── Build User Prompt ───────────────────────────────────────────────────────

function buildUserPrompt(input: OrchestratorInput): string {
  return `Target: ${input.target}
Mode: ${input.mode}
Engine: ${input.engine}
Available scanners: ${input.availableScannerNames.join(", ")}`
}

// ─── Main Orchestrator Function ──────────────────────────────────────────────

export async function createOrchestratorPlan(input: OrchestratorInput): Promise<ScanPlan> {
  const modeManifest = SCANNER_MANIFEST.filter(e => e.supportedModes.includes(input.mode))

  const systemPrompt = buildSystemPrompt(modeManifest)
  const userPrompt = buildUserPrompt(input)

  const content = await callDeepSeek(systemPrompt, userPrompt)

  // CRITICAL: Only pass scanners that support this mode to parseScanPlan.
  // Even though DeepSeek's prompt is mode-filtered, the response isn't validated
  // against mode — without this filter, DeepSeek could return source-mode scanners
  // (like Gitleaks, Semgrep, etc.) for a URL target and they'd pass validation.
  const modeNames = new Set(modeManifest.map(m => m.name))
  const availableModeNames = input.availableScannerNames.filter(n => modeNames.has(n))
  const plan = parseScanPlan(content, availableModeNames)

  // ── Local Target Safety Override ─────────────────────────────────────
  // DeepSeek tends to classify localhost/private-IP targets as "static sites"
  // or underestimate their attack surface, skipping crawler, ai-scanner, etc.
  // Since we can't know if a local target is truly static, force essential
  // scanners for any private/loopback address to ensure adequate coverage.
  if (input.mode === "url") {
    const isPrivateTarget = /^(https?:\/\/)?(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(input.target)
    if (isPrivateTarget) {
      // Force balanced priority when AI picks speed for local targets
      if (plan.scanPriority === "speed") {
        plan.scanPriority = "balanced"
      }
      plan.aiReview = true

      // Essential scanners that the AI tends to skip for localhost targets
      const essentialScanners = ["crawler", "ai-scanner"]
      for (const name of essentialScanners) {
        if (availableModeNames.includes(name) && !plan.selectedScanners.includes(name)) {
          plan.selectedScanners.push(name)
        }
      }

      // Add a new parallel group for the additional scanners
      const additions = essentialScanners.filter(
        name => availableModeNames.includes(name) && !plan.parallelGroups.flat().includes(name)
      )
      if (additions.length > 0) {
        plan.parallelGroups.push(additions)
      }
    }
  }

  return plan
}
