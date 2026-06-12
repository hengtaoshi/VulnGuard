/**
 * ai-scanner.ts — DeepSeek AI 代码审查扫描器
 *
 * 读取源码文件，调用 DeepSeek 大模型进行安全分析。
 * 能发现传统模式匹配 SAST 工具难以识别的逻辑漏洞、
 * 业务逻辑缺陷、权限问题等。
 *
 * 实现 Scanner 接口，注册到 registry.ts。
 */

import { readFileSync, readdirSync, statSync } from "fs"
import { join, extname, relative } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { isLlmAvailable, callLlmJson } from "./llm-client"

// ─── 支持分析的文件类型 ───────────────────────────────────────────────────

const SUPPORTED_EXTS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".java", ".go", ".rs", ".rb", ".php",
  ".cs", ".kt", ".swift", ".scala",
  ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
  ".vue", ".svelte",
])

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", ".next", ".nuxt",
  "dist", "build", "target", "out", "coverage",
  "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv",
  ".trivy-cache", ".scans", ".dc-report", ".terraform",
  ".cache", ".vscode", ".idea", "tools/bin", "data/uploads",
  "vendor", ".vendor",
])

// ─── 扫描策略 ─────────────────────────────────────────────────────────────

interface ScanStrategy {
  maxFiles: number          // 最多扫描的文件数
  maxLinesPerFile: number   // 每个文件最多分析的行数
  batchSize: number         // 每批发送给 AI 的文件数
  maxTotalLines: number     // 所有文件总行数上限
}

function getStrategy(totalFiles: number): ScanStrategy {
  if (totalFiles <= 10) return { maxFiles: 10, maxLinesPerFile: 200, batchSize: 5, maxTotalLines: 2000 }
  if (totalFiles <= 50) return { maxFiles: 20, maxLinesPerFile: 150, batchSize: 5, maxTotalLines: 3000 }
  if (totalFiles <= 200) return { maxFiles: 30, maxLinesPerFile: 120, batchSize: 4, maxTotalLines: 3600 }
  return { maxFiles: 40, maxLinesPerFile: 100, batchSize: 3, maxTotalLines: 4000 }
}

// ─── 文件收集 ─────────────────────────────────────────────────────────────

interface SourceFile {
  path: string
  relativePath: string
  language: string
  lines: number
  content: string
}

function collectSourceFiles(targetPath: string, strategy: ScanStrategy): SourceFile[] {
  const files: SourceFile[] = []

  function walk(dir: string, depth: number = 0) {
    if (depth > 8 || files.length >= strategy.maxFiles) return
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const entry of entries) {
      if (files.length >= strategy.maxFiles) return
      const full = join(dir, entry)
      try {
        const stat = statSync(full)
        if (stat.isDirectory()) {
          if (!SKIP_DIRS.has(entry) && !entry.startsWith(".")) {
            walk(full, depth + 1)
          }
        } else {
          const ext = extname(entry).toLowerCase()
          if (!SUPPORTED_EXTS.has(ext)) continue
          if (stat.size > 1024 * 1024) continue // 跳过 >1MB 的文件

          const content = readFileSync(full, "utf-8").slice(0, strategy.maxLinesPerFile * 80)
          const lines = content.split("\n").length

          files.push({
            path: full,
            relativePath: relative(targetPath, full).replace(/\\/g, "/"),
            language: extToLanguage(ext),
            lines,
            content,
          })
        }
      } catch { /* skip unreadable */ }
    }
  }

  walk(targetPath)

  // 按文件大小排序，优先分析小文件（更可能一次分析完）
  files.sort((a, b) => a.content.length - b.content.length)

  // 限制总行数
  let totalLines = 0
  const result: SourceFile[] = []
  for (const f of files) {
    if (totalLines + f.lines > strategy.maxTotalLines) break
    result.push(f)
    totalLines += f.lines
  }

  return result
}

function extToLanguage(ext: string): string {
  const map: Record<string, string> = {
    ".js": "JavaScript", ".jsx": "JavaScript (React)",
    ".ts": "TypeScript", ".tsx": "TypeScript (React)",
    ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".py": "Python", ".java": "Java", ".go": "Go",
    ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".kt": "Kotlin", ".swift": "Swift",
    ".scala": "Scala",
    ".c": "C", ".h": "C Header", ".cpp": "C++",
    ".hpp": "C++ Header", ".cc": "C++", ".cxx": "C++",
    ".vue": "Vue", ".svelte": "Svelte",
  }
  return map[ext] || "Unknown"
}

// ─── AI 分析 ──────────────────────────────────────────────────────────────

interface AiVulnResult {
  vulnerabilities: Array<{
    name: string
    severity: "Critical" | "High" | "Medium" | "Low"
    location: string
    cve: string
    description: string
    recommendation: string
    code?: string
  }>
}

function buildSystemPrompt(): string {
  return `你是一位资深安全代码审计专家。分析提供的源代码，找出安全漏洞。

重点关注:
1. **注入漏洞**: SQL注入、命令注入、XSS、模板注入、路径遍历
2. **认证与授权**: 硬编码凭据、缺失权限校验、不安全的会话管理
3. **敏感数据泄露**: 日志中打印密码/密钥、不安全的传输、内存中的数据残留
4. **配置安全**: 危险的功能开启、默认凭据、不安全的CORS配置
5. **加密问题**: 使用弱加密算法、自定义加密、密钥硬编码
6. **逻辑漏洞**: 竞态条件、越权访问、业务逻辑绕过
7. **依赖安全**: 使用了已知有漏洞的API或过时库

输出规则:
- 对每段代码，先判断是否有安全风险
- 仅有真实安全隐患才报告，不要误报
- 严重等级:
  - Critical: 可直接被利用导致数据泄露或系统控制
  - High: 有明确的利用路径
  - Medium: 在特定条件下可利用
  - Low: 安全编码最佳实践问题

输出严格的 JSON 格式（不要 markdown 代码块）。`
}

function buildUserPrompt(files: SourceFile[]): string {
  const fileSections = files.map(f =>
    `### ${f.relativePath} (${f.language}, ${f.lines}行)
\`\`\`
${f.content}
\`\`\``
  ).join("\n\n")

  return `请分析以下源码文件，找出所有安全漏洞。

${fileSections}`
}

async function analyzeWithAi(files: SourceFile[]): Promise<Vulnerability[]> {
  const result = await callLlmJson<AiVulnResult>(
    buildSystemPrompt(),
    buildUserPrompt(files),
    { temperature: 0.1, maxTokens: 4096, timeoutMs: 90000 },
  )

  if (!result?.vulnerabilities) return []

  return result.vulnerabilities.map((v, i) => ({
    id: `AI-${i + 1}`,
    name: v.name,
    severity: v.severity,
    location: v.location,
    cve: v.cve || "AI-Finding",
    description: v.description,
    recommendation: v.recommendation,
    code: v.code,
    source: "ai-scanner",
  }))
}

// ─── 主扫描函数 ──────────────────────────────────────────────────────────

export async function runAiScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "ai-scanner"
  const errors: string[] = []

  if (!isLlmAvailable()) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["DeepSeek API key not configured. Set DEEPSEEK_API_KEY environment variable."],
      scannerName,
    }
  }

  try {
    // 1. 先做快速目标分析（文件数/大小），确定扫描策略
    let totalCandidateFiles = 0
    const countFiles = (dir: string, depth = 0) => {
      if (depth > 5) return
      try {
        for (const entry of readdirSync(dir)) {
          if (skipCheck(entry)) continue
          const full = join(dir, entry)
          const s = statSync(full)
          if (s.isDirectory()) countFiles(full, depth + 1)
          else if (SUPPORTED_EXTS.has(extname(entry).toLowerCase())) totalCandidateFiles++
        }
      } catch { /* skip */ }
    }
    countFiles(targetPath)

    const strategy = getStrategy(totalCandidateFiles)

    // 2. 收集源码文件
    const files = collectSourceFiles(targetPath, strategy)

    if (files.length === 0) {
      return {
        vulnerabilities: [],
        totalChecks: 0,
        errors: ["AI scanner: No supported source files found in target"],
        scannerName,
      }
    }

    // 3. 分批发送给 AI 分析
    const allVulnerabilities: Vulnerability[] = []
    for (let i = 0; i < files.length; i += strategy.batchSize) {
      const batch = files.slice(i, i + strategy.batchSize)
      const vulns = await analyzeWithAi(batch)
      allVulnerabilities.push(...vulns)
    }

    // 4. 去重（AI 可能在不同文件中报告相似的漏洞）
    const seen = new Map<string, Vulnerability>()
    for (const v of allVulnerabilities) {
      const key = `${v.name}:${v.location || "unknown"}`.toLowerCase()
      if (!seen.has(key)) {
        seen.set(key, v)
      }
    }

    const vulnerabilities = Array.from(seen.values())
    const totalChecks = Math.max(vulnerabilities.length, files.length)

    return { vulnerabilities, totalChecks, errors, scannerName }
  } catch (err) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`AI scanner failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}

function skipCheck(name: string): boolean {
  return SKIP_DIRS.has(name) || name.startsWith(".")
}
