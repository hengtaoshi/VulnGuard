/**
 * codeql-scanner.ts — CodeQL 语义代码分析引擎集成
 *
 * CodeQL 是 GitHub 出品的语义分析引擎，能发现传统模式匹配 SAST 工具
 * 覆盖不到的逻辑漏洞。使用标准 CodeQL 查询包进行安全分析。
 *
 * 工作原理:
 *   1. codeql database create  ← 从源码创建 CodeQL 数据库
 *   2. codeql database analyze ← 运行安全查询，输出 SARIF
 *   3. 解析 SARIF → Vulnerability[]
 *
 * 依赖: CodeQL CLI (codeql-win64.zip → tools/bin/codeql/)
 * 下载: https://github.com/github/codeql-cli-binaries/releases
 */

import { execAsync } from "./exec"
import { join } from "path"
import { existsSync, mkdirSync, rmSync } from "fs"
import { randomUUID } from "crypto"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const CODEQL_DIR = join(process.cwd(), "tools", "bin", "codeql", "codeql")

// 不同场景的查询包 — 用 codeql pack download 安装
const LANGUAGE_QUERIES: Record<string, string[]> = {
  javascript: ["codeql/javascript-queries"],
  typescript: ["codeql/javascript-queries"],
  python: ["codeql/python-queries"],
  java: ["codeql/java-queries"],
  go: ["codeql/go-queries"],
  csharp: ["codeql/csharp-queries"],
  c: ["codeql/cpp-queries"],
  cpp: ["codeql/cpp-queries"],
  swift: ["codeql/swift-queries"],
  ruby: ["codeql/ruby-queries"],
}

const CODEQL_BIN = join(CODEQL_DIR, "codeql.exe")

// ─── 工具检测 ───────────────────────────────────────────────────────────────

function isCodeqlInstalled(): boolean {
  return existsSync(CODEQL_BIN)
}

/**
 * 尝试获取 codeql 版本字符串
 */
async function getCodeqlVersion(): Promise<string | null> {
  try {
    const { stdout } = await execAsync(`"${CODEQL_BIN}" --version`, { timeout: 10000 })
    const match = stdout.match(/CodeQL command-line toolchain release ([\d.]+)/)
    return match?.[1] || "unknown"
  } catch {
    return null
  }
}

/**
 * 确保 CodeQL 查询包已安装
 */
async function ensurePacks(queries: string[]): Promise<boolean> {
  try {
    const { stdout } = await execAsync(
      `"${CODEQL_BIN}" pack list --format=json`,
      { timeout: 15000 },
    )
    const installed: { name: string }[] = JSON.parse(stdout)
    const installedNames = new Set(installed.map(p => p.name))
    const missing = queries.filter(q => !installedNames.has(q))

    if (missing.length === 0) return true

    // 下载缺失的包
    for (const pack of missing) {
      try {
        await execAsync(
          `"${CODEQL_BIN}" pack download ${pack}`,
          { timeout: 120000 },
        )
      } catch {
        console.warn(`[codeql] Failed to download pack: ${pack}`)
        return false
      }
    }
    return true
  } catch {
    // codeql pack list 不可用，尝试直接 resolve queries
    return true
  }
}

// ─── 语言检测 ───────────────────────────────────────────────────────────────

/**
 * 根据文件扩展名判断合适的 CodeQL 语言
 */
function detectLanguages(targetPath: string): string[] {
  const { readdirSync, statSync } = require("fs") as typeof import("fs")
  const { extname } = require("path") as typeof import("path")

  const extensions: Record<string, string> = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".cs": "csharp",
    ".swift": "swift",
    ".c": "cpp",
    ".h": "cpp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".kt": "java",
  }

  const found = new Set<string>()
  const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "target", ".next", ".venv", "venv", "__pycache__"])

  function walk(dir: string, depth: number = 0) {
    if (depth > 5) return
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }
    for (const entry of entries) {
      const full = join(dir, entry)
      try {
        const stat = statSync(full)
        if (stat.isDirectory()) {
          if (!SKIP_DIRS.has(entry) && !entry.startsWith(".")) {
            walk(full, depth + 1)
          }
        } else {
          const lang = extensions[extname(entry).toLowerCase()]
          if (lang) found.add(lang)
        }
      } catch { /* skip unreadable */ }
    }
  }

  walk(targetPath)
  return Array.from(found)
}

/**
 * 将 CodeQL 严重等级映射到 VulnGuard 格式
 */
function mapSeverity(sev: string): "Critical" | "High" | "Medium" | "Low" {
  switch (sev.toLowerCase()) {
    case "error": return "Critical"
    case "warning": return "Medium"
    case "note": return "Low"
    default: return "Medium"
  }
}

/**
 * 解析 CodeQL 的 SARIF 输出
 */
function parseSarifResults(sarifJson: string, scannerName: string): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = []

  try {
    const sarif = JSON.parse(sarifJson)

    for (const run of sarif.runs || []) {
      const rules = new Map<string, { name: string; description: string; recommendation: string }>()
      for (const rule of run.tool?.driver?.rules || []) {
        rules.set(rule.id, {
          name: rule.name || rule.id,
          description: rule.fullDescription?.text || rule.shortDescription?.text || "",
          recommendation: rule.help?.text || "",
        })
      }

      for (const result of run.results || []) {
        const rule = rules.get(result.ruleId)
        const loc = result.locations?.[0]?.physicalLocation
        let location = loc?.artifactLocation?.uri?.replace(/^file:\/\//, "") || ""
        if (loc?.region?.startLine) {
          location += `:${loc.region.startLine}`
          if (loc.region.startColumn) {
            location += `:${loc.region.startColumn}`
          }
        }

        vulnerabilities.push({
          id: `CQL-${vulnerabilities.length + 1}`,
          name: rule?.name || result.ruleId || "CodeQL finding",
          severity: mapSeverity(result.level),
          location,
          cve: result.ruleId || "CodeQL",
          description: rule?.description || result.message?.text || "",
          recommendation: rule?.recommendation || "",
          source: scannerName,
        })
      }
    }
  } catch {
    /* SARIF parse failed, return empty */
  }

  return vulnerabilities
}

// ─── 主扫描函数 ─────────────────────────────────────────────────────────────

export async function runCodeqlScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "codeql"
  const errors: string[] = []

  if (!isCodeqlInstalled()) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["CodeQL CLI not found. Download from https://github.com/github/codeql-cli-binaries/releases"],
      scannerName,
    }
  }

  const version = await getCodeqlVersion()
  if (!version) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["CodeQL CLI not responding"],
      scannerName,
    }
  }

  // 检测项目语言
  const languages = detectLanguages(targetPath)
  if (languages.length === 0) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["CodeQL: No supported languages detected in target"],
      scannerName,
    }
  }

  const allVulnerabilities: Vulnerability[] = []
  const scanId = randomUUID().slice(0, 8)
  const dbDir = join(process.cwd(), ".scans", `.codeql-db-${scanId}`)
  const resultDir = join(process.cwd(), ".scans", `.codeql-res-${scanId}`)

  try {
    // 确保临时目录存在
    if (!existsSync(join(process.cwd(), ".scans"))) {
      mkdirSync(join(process.cwd(), ".scans"), { recursive: true })
    }
    mkdirSync(resultDir, { recursive: true })

    // 去重处理的语言（JS/TS 共用 javascript 查询）
    const processedLangs = new Set<string>()
    for (const lang of languages) {
      const qlLang = LANGUAGE_QUERIES[lang] ? lang : null
      if (!qlLang || processedLangs.has(qlLang)) continue
      processedLangs.add(qlLang)

      const queries = LANGUAGE_QUERIES[qlLang]
      if (!queries || queries.length === 0) continue

      // 创建数据库
      try {
        await execAsync(
          `"${CODEQL_BIN}" database create "${dbDir}-${qlLang}" --language=${qlLang} --source-root="${targetPath}" --overwrite`,
          { timeout: 300000 }, // 5 分钟超时
        )
      } catch (err) {
        errors.push(`CodeQL ${qlLang}: database creation failed: ${(err as Error).message}`)
        continue
      }

      // 运行查询
      const outputFile = join(resultDir, `${qlLang}.sarif`)
      try {
        await execAsync(
          `"${CODEQL_BIN}" database analyze "${dbDir}-${qlLang}" --format=sarif-latest --output="${outputFile}" --download ${queries.join(" ")}`,
          { timeout: 600000 }, // 10 分钟超时
        )
      } catch (err) {
        // analyze 可能返回非 0 但仍有部分结果
        errors.push(`CodeQL ${qlLang}: analysis warning: ${(err as Error).message}`)
      }

      // 读取结果
      if (existsSync(outputFile)) {
        const { readFileSync } = require("fs") as typeof import("fs")
        const sarifContent = readFileSync(outputFile, "utf-8")
        const vulns = parseSarifResults(sarifContent, scannerName)
        allVulnerabilities.push(...vulns)

        // 清理
        try { rmSync(outputFile, { force: true }) } catch { /* noop */ }
      }

      // 清理数据库
      try { rmSync(`${dbDir}-${qlLang}`, { recursive: true, force: true }) } catch { /* noop */ }
    }

    // 清理结果目录
    try { rmSync(resultDir, { recursive: true, force: true }) } catch { /* noop */ }

    const totalChecks = Math.max(allVulnerabilities.length, 10)
    return {
      vulnerabilities: allVulnerabilities,
      totalChecks,
      errors: errors.length > 0 ? errors : [],
      scannerName,
    }
  } catch (err) {
    // 清理
    try { rmSync(dbDir, { recursive: true, force: true }) } catch { /* noop */ }
    try { rmSync(resultDir, { recursive: true, force: true }) } catch { /* noop */ }

    return {
      vulnerabilities: allVulnerabilities,
      totalChecks: allVulnerabilities.length,
      errors: [...errors, `CodeQL scan failed: ${(err as Error).message}`],
      scannerName,
    }
  }
}
