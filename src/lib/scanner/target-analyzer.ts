/**
 * target-analyzer.ts — 预扫描分析器
 *
 * 在 AI 调度器决策前，先用 Node.js 工具对目标目录做一次快速扫描，
 * 收集文件类型、技术栈、配置文件等真实数据，为 AI 提供决策依据。
 *
 * 这样 AI 就不再是靠路径字符串"猜"技术栈，而是基于实际证据做选择。
 */

import { readdirSync, statSync } from "fs"
import { join, relative, extname, basename } from "path"
import { existsSync } from "fs"

// ─── 配置文件检测清单 ──────────────────────────────────────────────────────

interface ConfigFileCheck {
  name: string
  patterns: string[]       // 要检测的文件名（其中之一存在即算命中）或 glob 扩展名（如 "*.tf"）
  description: string
}

const CONFIG_CHECKS: ConfigFileCheck[] = [
  { name: "hasPackageJson", patterns: ["package.json"], description: "npm/JavaScript 项目" },
  { name: "hasPackageLock", patterns: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"], description: "npm/yarn/pnpm lock 文件" },
  { name: "hasRequirementsTxt", patterns: ["requirements.txt"], description: "Python 依赖" },
  { name: "hasPipfile", patterns: ["Pipfile", "Pipfile.lock"], description: "Pipenv Python 项目" },
  { name: "hasPyprojectToml", patterns: ["pyproject.toml"], description: "Poetry/PEP 621 Python 项目" },
  { name: "hasSetupPy", patterns: ["setup.py"], description: "Python 传统项目" },
  { name: "hasDockerfile", patterns: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"], description: "Docker 容器化" },
  { name: "hasTerraform", patterns: ["*.tf", "*.tfvars"], description: "Terraform IaC" },
  { name: "hasMavenPom", patterns: ["pom.xml"], description: "Java Maven 项目" },
  { name: "hasGradle", patterns: ["build.gradle", "build.gradle.kts"], description: "Java Gradle 项目" },
  { name: "hasGoMod", patterns: ["go.mod"], description: "Go 项目" },
  { name: "hasCargoToml", patterns: ["Cargo.toml"], description: "Rust 项目" },
  { name: "hasComposerJson", patterns: ["composer.json"], description: "PHP Composer 项目" },
  { name: "hasGemfile", patterns: ["Gemfile"], description: "Ruby Bundler 项目" },
  { name: "hasCsproj", patterns: ["*.csproj"], description: ".NET C# 项目" },
  { name: "hasSwiftPackage", patterns: ["Package.swift"], description: "Swift Package Manager" },
  { name: "hasEnvFile", patterns: [".env", ".env.example", ".env.local"], description: "环境变量文件" },
]

// ─── 文件扩展名 → 语言映射 ─────────────────────────────────────────────────

const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".java": "java",
  ".go": "go",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".kt": "kotlin",
  ".swift": "swift",
  ".scala": "scala",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".hpp": "cpp",
  ".cc": "cpp",
  ".cxx": "cpp",
  ".vue": "vue",
  ".svelte": "svelte",
  ".tf": "terraform",
  ".tfvars": "terraform",
  ".sh": "shell",
  ".bash": "shell",
  ".ps1": "powershell",
  ".sql": "sql",
  ".proto": "protobuf",
  ".css": "css",
  ".scss": "scss",
  ".less": "less",
  ".html": "html",
  ".md": "markdown",
}

// ─── 要跳过的目录 ──────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".svn", ".hg", ".next", ".nuxt",
  "dist", "build", "target", "out", "coverage",
  "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv",
  ".trivy-cache", ".scans", ".terraform",
  ".cache", ".vscode", ".idea", "tools/bin", "data/uploads",
])

// ─── 输出类型 ──────────────────────────────────────────────────────────────

export interface LanguageStats {
  count: number
  percentage: number  // 0-100
  sampleFiles: string[]  // 最多5个示例文件
}

export interface TargetAnalysis {
  targetPath: string
  /** 总文件数 */
  totalFiles: number
  /** 总目录数 */
  totalDirs: number
  /** 项目规模分类 */
  sizeCategory: "tiny" | "small" | "medium" | "large" | "huge"
  /** 按语言分组的文件统计（值 = 真实数量） */
  languages: Record<string, LanguageStats>
  /** 检测到的配置文件清单（true/false） */
  configFiles: Record<string, boolean>
  /** 配置文件详细信息 */
  configDetails: { name: string; found: string[]; description: string }[]
  /** 是否包含 IaC 文件 */
  hasIaC: boolean
  /** 推断的项目类型 */
  projectTypes: string[]
  /** 目录结构样本（最多 50 个文件路径） */
  fileTreeSample: string[]
  /** 是否存在 Python 文件 */
  hasPython: boolean
  /** 是否存在源码文件 */
  hasSourceCode: boolean
  /** 分析用时（毫秒） */
  analysisTimeMs: number
}

// ─── 辅助函数 ──────────────────────────────────────────────────────────────

function shouldSkipDir(name: string): boolean {
  return SKIP_DIRS.has(name) || name.startsWith(".")
}

function hasExtension(name: string, extGlob: string): boolean {
  // "*.tf" → .tf
  const targetExt = extGlob.replace("*.", ".")
  return extname(name).toLowerCase() === targetExt
}

// ─── 主分析函数 ────────────────────────────────────────────────────────────

export function analyzeTarget(targetPath: string): TargetAnalysis {
  const startTime = Date.now()

  if (!existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`)
  }

  // —— 统计数据结构 ——
  const languageCounters: Record<string, number> = {}      // lang → 真实文件数
  const languageSamples: Record<string, string[]> = {}      // lang → 示例文件路径（最多5个）
  const foundConfigs: Record<string, string[]> = {}         // configName → 找到的文件路径
  const fileTree: string[] = []                             // 目录树样本（最多50个）

  let totalFiles = 0
  let totalDirs = 0

  // 初始化配置检测
  const configFiles: Record<string, boolean> = {}
  for (const check of CONFIG_CHECKS) {
    configFiles[check.name] = false
    foundConfigs[check.name] = []
  }

  // —— 递归遍历 ——
  function walk(dir: string, depth: number = 0) {
    if (depth > 10) return // 防止超大目录卡死

    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry)
      let stat: ReturnType<typeof statSync>
      try {
        stat = statSync(fullPath)
      } catch {
        continue
      }

      if (stat.isDirectory()) {
        if (shouldSkipDir(entry)) continue
        totalDirs++
        walk(fullPath, depth + 1)
      } else {
        const ext = extname(entry).toLowerCase()

        // 目录树样本（所有文件）
        if (fileTree.length < 50) {
          fileTree.push(relative(targetPath, fullPath).replace(/\\/g, "/"))
        }

        // —— 语言统计（只统计可识别的源码文件） ——
        const lang = EXTENSION_LANGUAGE_MAP[ext]
        if (lang) {
          totalFiles++
          // 递增计数器（真实数量）
          languageCounters[lang] = (languageCounters[lang] || 0) + 1

          // 保存样本（最多5个）
          if (!languageSamples[lang]) languageSamples[lang] = []
          if (languageSamples[lang].length < 5) {
            languageSamples[lang].push(relative(targetPath, fullPath).replace(/\\/g, "/"))
          }
        }

        // —— 配置文件检测 ——
        for (const check of CONFIG_CHECKS) {
          for (const pattern of check.patterns) {
            const matched = pattern.startsWith("*.")
              ? hasExtension(entry, pattern)
              : entry === pattern

            if (matched) {
              configFiles[check.name] = true
              if (foundConfigs[check.name].length < 3) {
                foundConfigs[check.name].push(
                  relative(targetPath, fullPath).replace(/\\/g, "/")
                )
              }
              break // 一个 pattern 匹配就够了
            }
          }
        }
      }
    }
  }

  walk(targetPath)

  // —— 计算语言统计 ——
  const languages: Record<string, LanguageStats> = {}
  const langNames = Object.keys(languageCounters)

  for (const lang of langNames) {
    languages[lang] = {
      count: languageCounters[lang],
      percentage: totalFiles > 0
        ? Math.round((languageCounters[lang] / totalFiles) * 100)
        : 0,
      sampleFiles: languageSamples[lang]?.slice(0, 5) ?? [],
    }
  }

  // —— 推断项目类型 ——
  const projectTypes: string[] = []

  if (langNames.includes("typescript") || langNames.includes("javascript")) {
    projectTypes.push(configFiles.hasPackageJson ? "javascript/typescript" : "javascript/typescript")
  }
  if (langNames.includes("python") || configFiles.hasRequirementsTxt || configFiles.hasPipfile) {
    projectTypes.push("python")
  }
  if (langNames.includes("java") || configFiles.hasMavenPom || configFiles.hasGradle) {
    projectTypes.push("java")
  }
  if (langNames.includes("go") || configFiles.hasGoMod) {
    projectTypes.push("go")
  }
  if (langNames.includes("rust") || configFiles.hasCargoToml) {
    projectTypes.push("rust")
  }
  if (langNames.includes("csharp") || configFiles.hasCsproj) {
    projectTypes.push("csharp")
  }
  if (langNames.includes("php") || configFiles.hasComposerJson) {
    projectTypes.push("php")
  }
  if (langNames.includes("ruby") || configFiles.hasGemfile) {
    projectTypes.push("ruby")
  }
  if (langNames.includes("swift") || configFiles.hasSwiftPackage) {
    projectTypes.push("swift")
  }
  if (configFiles.hasDockerfile) {
    projectTypes.push("docker")
  }
  if (configFiles.hasTerraform) {
    projectTypes.push("terraform")
  }

  if (projectTypes.length === 0) {
    projectTypes.push(totalFiles > 0 ? "unknown/generic" : "empty")
  }

  const hasIaC = configFiles.hasTerraform || configFiles.hasDockerfile
  const hasPython = langNames.includes("python")
    || configFiles.hasRequirementsTxt
    || configFiles.hasPipfile
  const hasSourceCode = langNames.length > 0

  // 项目规模
  let sizeCategory: TargetAnalysis["sizeCategory"]
  if (totalFiles <= 10) sizeCategory = "tiny"
  else if (totalFiles <= 100) sizeCategory = "small"
  else if (totalFiles <= 500) sizeCategory = "medium"
  else if (totalFiles <= 2000) sizeCategory = "large"
  else sizeCategory = "huge"

  // 配置文件详细信息
  const configDetails = CONFIG_CHECKS
    .filter(c => configFiles[c.name])
    .map(c => ({
      name: c.name,
      found: foundConfigs[c.name],
      description: c.description,
    }))

  return {
    targetPath,
    totalFiles,
    totalDirs,
    sizeCategory,
    languages,
    configFiles,
    configDetails,
    hasIaC,
    projectTypes,
    fileTreeSample: fileTree,
    hasPython,
    hasSourceCode,
    analysisTimeMs: Date.now() - startTime,
  }
}
