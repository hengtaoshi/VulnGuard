import { SCANNER_MANIFEST } from "./manifest"
import type { ScannerManifestEntry } from "./manifest"
import type { TargetAnalysis } from "./target-analyzer"

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
  /** 新增：预扫描分析数据，为 AI 提供真实的技术栈证据 */
  targetAnalysis: TargetAnalysis
}

// ─── System Prompt ───────────────────────────────────────────────────────────

function buildSystemPrompt(manifest: ScannerManifestEntry[]): string {
  return `# 角色定位

你是一位专业的安全扫描编排专家，你的职责是**基于目标源码的实际证据**来选择和调度安全扫描工具。

你**不是**一个固定规则引擎——你是一个分析师。你先分析源码结构，再根据找到的证据匹配合适的工具。

## 核心原则

1. **证据驱动**：你对每个扫描器的选择都必须有明确的、可追溯的依据，依据来自下方的【目标分析报告】。
2. **禁止盲选**：如果目标中不存在匹配某扫描器的技术特征文件（即 techIndicators），则不得选择该扫描器。例如目标中没有 .py 文件就不选 bandit，没有 package-lock.json 就不选 npm-audit。
3. **宁缺毋滥**：不确定时默认选择保守覆盖（semgrep + gitleaks），再根据明确证据扩展。
4. **全面但不浪费**：选中的每个扫描器都应该有其独特价值，不做重复覆盖。

## 可用扫描引擎清单

以下是所有可用的源码扫描引擎及其能力、检测类型和耗时。

\`\`\`json
${JSON.stringify(manifest, null, 2)}
\`\`\`

## 决策流程

你必须按以下 4 步严格推理，在 reasoning 字段中清晰展示每一步的思考结论。

### Step 1: 审查目标分析报告
仔细阅读下方【目标分析报告】中的实际数据，确认以下信息：
- 项目有哪些语言的文件？各多少数量？
- 检测到哪些配置文件（package.json、requirements.txt、Dockerfile 等）？
- 项目规模如何？
- 有哪些目录结构特征？

### Step 2: 逐项评估扫描器匹配度
对照可用扫描器清单，针对每个扫描器，判断目标是否具备其所需的 techIndicators。对于每台扫描器，你必须做"匹配/不匹配 + 原因"的判断，并将结论写入 reasoning。

| 扫描器  | 必要条件（任意一项满足即可匹配） | 匹配判断 |
|---------|--------------------------------|---------|
| semgrep | 存在任意源码文件（.js/.ts/.py/.java/.go 等） | 几乎总是匹配，除非目标为空目录 |
| bandit  | 存在 .py 文件 或 requirements.txt / Pipfile | 无 Python 代码则不选 |
| gitleaks| 任意源码项目（几乎总是匹配） | 几乎总是匹配 |
| npm-audit | 存在 package-lock.json 或 yarn.lock | 无 lock 文件则不选 |
| pip-audit | 存在 requirements.txt 或 Pipfile | 无 Python 依赖文件则不选 |
| dependency-check | 存在 pom.xml / build.gradle / go.mod / Cargo.toml 等 | 无对应构建文件则不选 |
| trivy    | 存在 OS 级或语言级依赖特征 | 综合性扫描，中小项目可选，大项目推荐 |
| checkov  | 存在 .tf / Dockerfile / k8s yaml 等 IaC 文件 | 无 IaC 文件则不选 |
| nuclei   | 中大型项目推荐（> 100 文件），小型项目可选 | 小项目通常可跳过 |
| ai-scanner | 存在源码文件 | 几乎总是匹配 |

### Step 3: 选择优先级和扫描模式
根据引擎模式和项目特征决定：

**"ai" 引擎模式** — 智能自适应
- 默认 balanced 优先级，除非有明确理由选用 speed（极速需求）或 depth（高安全需求）
- aiReview 默认 true，speed 模式可设为 false
- ai-scanner 通常应该包含，除非目标极小（< 10 文件）或 speed 模式

**"all" 引擎模式** — 最大覆盖
- 强制 depth 优先级 + aiReview = true
- 选择所有可用的扫描器

### Step 4: 并行分组
按扫描器的 typicalDuration 和依赖关系分组：
- Phase 1（并行启动）：typicalDuration 为 fast + medium 的扫描器
- Phase 2（并行启动）：typicalDuration 为 medium + slow 的扫描器（ai-scanner 应最后）
- 两组顺序执行，组内并行

## 输出格式

只返回 JSON，不要 markdown 代码块，不要额外说明。

\`\`\`json
{
  "reasoning": "【必填】详细的中文推理过程。必须包含：\n1. 目标分析摘要（项目类型、语言分布、配置文件）\n2. 每个扫描器的匹配判断（匹配/不匹配 + 原因）\n3. 优先级选择的理由\n4. 分组策略说明",
  "selectedScanners": ["从可用扫描器中选出的名称数组"],
  "parallelGroups": [
    ["phase1-扫描器", "..."],
    ["phase2-扫描器", "..."]
  ],
  "aiReview": true 或 false,
  "scanPriority": "speed" | "balanced" | "depth"
}
\`\`\`

## 输出约束

- reasoning 字段**必须使用中文**
- 每个被选中的扫描器，reasoning 中必须包含一句明确的**证据引用**，格式如："选择 Bandit：目标检测到 12 个 .py 文件"
- 每个被跳过的扫描器，reasoning 中必须说明**跳过原因**，格式如："跳过 npm-audit：未检测到 package-lock.json 或 yarn.lock"
- 严禁选择与目标技术特征不匹配的扫描器
- 严禁在没有证据的情况下"默认"选择扫描器`
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
        max_tokens: 4096,
      }),
      signal: controller.signal,
    })

    const json = await res.json()

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
  const analysis = input.targetAnalysis

  // 格式化语言分布为易读文本
  const langSummary = Object.entries(analysis.languages)
    .sort(([, a], [, b]) => b.count - a.count)
    .map(([lang, stats]) => `  - ${lang}: ${stats.count} 个文件 (${stats.percentage}%)`)
    .join("\n")

  // 格式化配置文件
  const configSummary = analysis.configDetails
    .map(c => `  - ${c.name}: ${c.found.join(", ")}（${c.description}）`)
    .join("\n")

  // 目录结构样本（控制在合理数量内）
  const treeSample = analysis.fileTreeSample.slice(0, 30).join("\n")

  return `## 扫描任务

引擎模式: ${input.engine}
可用扫描器: ${input.availableScannerNames.join(", ")}

## 目标分析报告

目标路径: ${analysis.targetPath}
项目规模: ${analysis.sizeCategory}（共 ${analysis.totalFiles} 个文件）
项目类型: ${analysis.projectTypes.join("、")}

### 语言分布
${langSummary || "  （未检测到常见编程语言文件）"}

### 检测到的配置文件
${configSummary || "  （未检测到标准配置文件）"}
${analysis.hasIaC ? "\n⚠ 检测到 IaC（基础设施即代码）文件，建议包含 IaC 扫描器" : ""}
${analysis.hasPython ? "\n⚠ 检测到 Python 代码文件，建议包含 bandit" : ""}

### 目录结构样本（前 30 个文件）
\`\`\`
${treeSample || "  （空目录）"}
\`\`\``
}

// ─── Main Orchestrator Function ──────────────────────────────────────────────

export async function createOrchestratorPlan(input: OrchestratorInput): Promise<ScanPlan> {
  const modeManifest = SCANNER_MANIFEST.filter(e => e.supportedModes.includes(input.mode))

  const systemPrompt = buildSystemPrompt(modeManifest)
  const userPrompt = buildUserPrompt(input)

  const content = await callDeepSeek(systemPrompt, userPrompt)

  // Only pass scanners that support this mode to parseScanPlan
  const modeNames = new Set(modeManifest.map(m => m.name))
  const availableModeNames = input.availableScannerNames.filter(n => modeNames.has(n))
  const plan = parseScanPlan(content, availableModeNames)

  return plan
}
