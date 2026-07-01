/**
 * orchestrator.ts — AI 驱动扫描编排器
 *
 * 分析目标项目结构，调用 DeepSeek 生成最优扫描计划。
 * 包含选定扫描器、并行分组、优先级、AI 审查建议。
 *
 * 当 DeepSeek 不可用或调用失败时返回 null，由调用方（composite.ts）
 * 回退到规则驱动的扫描器选择。
 */

import type { TargetAnalysis } from "./target-analyzer"
import { isLlmAvailable, callLlmJson } from "./llm-client"
import { SCANNER_MANIFEST } from "./manifest"
import type { Scanner } from "./types"

export interface OrchestratorPlan {
  reasoning: string
  selectedScanners: string[]
  parallelGroups: string[][]
  aiReview: boolean
  scanPriority: "speed" | "depth" | "balanced"
}

/**
 * 构建系统提示词 — 描述可用扫描器和决策规则
 */
function buildSystemPrompt(availableScanners: Scanner[]): string {
  const scannerList = availableScanners
    .map(s => {
      const manifestEntry = SCANNER_MANIFEST.find(m => m.name === s.name)
      return `- ${s.name} (${s.displayName}) [${s.category}]${
        manifestEntry ? `: ${manifestEntry.description.slice(0, 120)}` : ""
      }`
    })
    .join("\n")

  return `你是 VulnGuard 的安全扫描编排专家。你的任务是根据目标项目分析数据，选择最合适的扫描器组合。

可用扫描器:
${scannerList}

决策规则:
1. **SAST 扫描器**: semgrep（多语言通用）、bandit（仅 Python）、bearer（隐私数据流，仅 Linux/macOS）、codeql（语义分析）
2. **Secret 扫描器**: gitleaks（快速）、trufflehog（深度，更多检测器）
3. **SCA/依赖扫描器**: npm-audit（JS/TS）、pip-audit（Python）、cve-cpp（C/C++ Conan/vcpkg）、swift（Swift）、osv-scanner（Java/Go/Rust/C#/.NET/多生态通用）
4. **文件系统/IaC**: trivy（全面）、checkov（IaC 专项）、nuclei（模板化检测）
5. **供应链**: scorecard（安全实践评分）
6. 对于全量扫描（all 引擎），选择所有可用扫描器
7. 对于 AI 引擎，根据目标语言/框架/配置文件做最优选择

并行分组原则:
- fast 组: secret 扫描器 + semgrep（最快，同时运行）
- medium 组: SAST + 依赖扫描器
- slow 组: codeql、trivy、nuclei（最慢）

scanPriority 选择:
- "speed": 快速扫描，只选最必要的扫描器（1-4 个），全部放一组
- "balanced": 覆盖主要风险，适量并行（默认）
- "depth": 选用所有可能相关的扫描器，分组执行

返回严格的 JSON 格式（不要 markdown 代码块）。`
}

/**
 * 构建用户提示词 — 包含目标分析数据
 */
function buildUserPrompt(analysis: TargetAnalysis, engine: "ai" | "all"): string {
  const langList = Object.entries(analysis.languages)
    .sort(([, a], [, b]) => b.count - a.count)
    .map(([lang, stats]) => `${lang}: ${stats.count} files (${stats.percentage}%)`)
    .join("\n")

  const configList = analysis.configDetails
    .map(c => `- ${c.name}: ${c.found.join(", ")} (${c.description})`)
    .join("\n")

  return `## 目标分析结果

### 项目信息
- 路径: ${analysis.targetPath}
- 总文件数: ${analysis.totalFiles}
- 项目规模: ${analysis.sizeCategory}
- 项目类型: ${analysis.projectTypes.join(", ")}
- 包含 IaC: ${analysis.hasIaC}
- 包含 Python: ${analysis.hasPython}

### 语言分布
${langList || "（未检测到已知语言）"}

### 配置文件
${configList || "（未检测到配置文件）"}

### 扫描引擎模式
engine: "${engine}"

请输出 JSON 格式的扫描计划。`
}

/**
 * 构建并行分组 — 基于选定的扫描器列表
 */
function buildParallelGroups(scannerNames: string[], allScanners: Scanner[]): string[][] {
  const groups: string[][] = []
  const fast: string[] = []
  const medium: string[] = []
  const slow: string[] = []

  const scannerMap = new Map(allScanners.map(s => [s.name, s]))

  for (const name of scannerNames) {
    const s = scannerMap.get(name)
    if (!s) continue
    if (s.category === "secret" || s.name === "semgrep") {
      fast.push(name)
    } else if (s.name === "codeql") {
      slow.push(name)
    } else if (s.category === "dependency" || s.category === "sast" || s.name === "checkov") {
      medium.push(name)
    } else {
      slow.push(name)
    }
  }

  if (fast.length > 0) groups.push(fast)
  if (medium.length > 0) groups.push(medium)
  if (slow.length > 0) groups.push(slow)

  if (groups.length === 0 && scannerNames.length > 0) {
    groups.push(scannerNames)
  }

  return groups
}

/**
 * 创建 AI 编排计划
 *
 * @param analysis 目标分析结果
 * @param engine 扫描引擎模式
 * @param allScanners 所有已注册扫描器
 * @param availableNames 当前可用扫描器名称列表
 * @returns OrchestratorPlan | null（AI 不可用时返回 null）
 */
export async function createOrchestratorPlan(
  analysis: TargetAnalysis,
  engine: "ai" | "all",
  allScanners: Scanner[],
  availableNames: string[],
): Promise<OrchestratorPlan | null> {
  if (!isLlmAvailable()) return null

  const availableScanners = allScanners.filter(s => availableNames.includes(s.name))

  const plan = await callLlmJson<{
    reasoning: string
    selectedScanners: string[]
    aiReview: boolean
    scanPriority: "speed" | "depth" | "balanced"
  }>(
    buildSystemPrompt(availableScanners),
    buildUserPrompt(analysis, engine),
    { temperature: 0.3, maxTokens: 2048, timeoutMs: 30000 },
  )

  if (!plan || !plan.selectedScanners || plan.selectedScanners.length === 0) {
    return null
  }

  // 过滤掉不可用的扫描器
  const selectedScanners = plan.selectedScanners.filter(n => availableNames.includes(n))

  if (selectedScanners.length === 0) return null

  // 构建并行分组
  let parallelGroups: string[][]
  if (plan.scanPriority === "speed") {
    // 速度优先：全部放一组
    parallelGroups = [selectedScanners]
  } else {
    parallelGroups = buildParallelGroups(selectedScanners, allScanners)
  }

  return {
    reasoning: plan.reasoning || "AI 编排器未提供详细理由",
    selectedScanners,
    parallelGroups,
    aiReview: plan.aiReview ?? true,
    scanPriority: plan.scanPriority || "balanced",
  }
}

/**
 * 规则驱动的回退计划生成（当 AI 不可用时使用）
 */
export function createFallbackPlan(
  analysis: TargetAnalysis,
  engine: "ai" | "all",
  allScanners: Scanner[],
  availableNames: string[],
): OrchestratorPlan {
  // 与 composite.ts 中的 selectScannersByRules 逻辑保持一致
  const selected: string[] = []
  const configNames = new Set(analysis.configDetails.map(c => c.name))
  const langs = new Set(Object.keys(analysis.languages))

  // ── 总是选中的扫描器 ──
  selected.push("semgrep", "gitleaks")

  // Python
  if (langs.has("python") || analysis.hasPython || configNames.has("hasRequirementsTxt") || configNames.has("hasPipfile") || configNames.has("hasSetupPy")) {
    selected.push("bandit", "pip-audit")
  }

  // JS/TS
  if (configNames.has("hasPackageLock") || configNames.has("hasPackageJson")) {
    selected.push("npm-audit")
  }

  // IaC
  if (analysis.hasIaC || configNames.has("hasDockerfile") || configNames.has("hasTerraform")) {
    selected.push("checkov")
  }

  // Java
  if (configNames.has("hasMavenPom") || configNames.has("hasGradle")) {
    selected.push("osv-scanner")
  }

  // Go
  if (configNames.has("hasGoMod")) {
    selected.push("osv-scanner")
  }

  // Rust
  if (configNames.has("hasCargoToml")) {
    selected.push("osv-scanner")
  }

  // C/C++
  if (langs.has("c") || langs.has("cpp") || configNames.has("hasConanfile") || configNames.has("hasVcpkg")) {
    selected.push("cve-cpp")
  }

  // Swift
  if (langs.has("swift") || configNames.has("hasSwiftPackage")) {
    selected.push("swift")
  }

  // .NET
  if (langs.has("csharp") || configNames.has("hasCsproj")) {
    selected.push("osv-scanner")
  }

  // CodeQL
  const codeqlLangs = ["javascript", "typescript", "python", "java", "go", "c", "cpp", "csharp", "swift", "ruby"]
  if (langs.size > 0 && codeqlLangs.some(l => langs.has(l))) {
    selected.push("codeql")
  }

  // 综合性
  selected.push("trivy")
  if (analysis.totalFiles > 20) {
    selected.push("nuclei")
  }

  const selectedScanners = selected.filter((n, i, a) => a.indexOf(n) === i).filter(n => availableNames.includes(n))

  if (engine === "all") {
    // 全量模式：在语言匹配基础上补充通用扫描器
    const expanded = [...selectedScanners]
    for (const name of ["trufflehog", "osv-scanner", "nuclei"]) {
      if (availableNames.includes(name) && !expanded.includes(name)) {
        expanded.push(name)
      }
    }
    return {
      reasoning: `全量扫描模式：基于 ${analysis.projectTypes.join("/")} 项目类型的全面覆盖（${langs.size} 种语言）`,
      selectedScanners: expanded,
      parallelGroups: buildParallelGroups(expanded, allScanners),
      aiReview: false,
      scanPriority: "depth",
    }
  }

  return {
    reasoning: `规则回退：基于检测到的 ${analysis.projectTypes.join("/")} 项目类型和 ${langs.size} 种编程语言自动选择`,
    selectedScanners,
    parallelGroups: buildParallelGroups(selectedScanners, allScanners),
    aiReview: false,
    scanPriority: "balanced",
  }
}
