/**
 * ignore-rules.ts — VulnGuard 误报忽略规则管理
 *
 * 支持两种方式标记误报:
 * 1. `.vulnguard-ignore` 文件（类似 .gitignore 语法，可提交到仓库）
 * 2. Web UI 标记（保存到 .scans/ignore-rules.json）
 *
 * 忽略规则格式: scanner:pattern（如 trivy:CVE-2024-12345 或 semgrep:*）
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs"
import { join } from "path"
import type { Vulnerability } from "@/lib/api/types"

const IGNORE_RULES_FILE = join(process.cwd(), ".vulnguard-ignore")
const IGNORE_DB_FILE = join(process.cwd(), ".scans", "ignore-rules.json")

export interface IgnoreRule {
  /** 匹配模式: 格式 "scanner:pattern" */
  pattern: string
  /** 创建时间 */
  createdAt: string
  /** 可选备注 */
  comment?: string
  /** 来源: "file" (.vulnguard-ignore) 或 "ui" (Web UI) */
  source: "file" | "ui"
}

interface IgnoreDb {
  rules: IgnoreRule[]
  updatedAt: string
}

// ─── 规则文件解析 ───────────────────────────────────────────────────────────

/**
 * 解析 .vulnguard-ignore 文件
 * 格式: scanner:pattern  或  scanner:*
 */
function parseIgnoreFile(filePath: string): IgnoreRule[] {
  if (!existsSync(filePath)) return []

  const content = readFileSync(filePath, "utf-8")
  const rules: IgnoreRule[] = []

  for (const line of content.split("\n")) {
    const trimmed = line.trim()
    // 跳过注释和空行
    if (!trimmed || trimmed.startsWith("#")) continue

    // 验证格式: scanner:pattern
    if (!trimmed.includes(":")) continue

    rules.push({
      pattern: trimmed,
      createdAt: new Date().toISOString(),
      source: "file",
    })
  }

  return rules
}

// ─── 规则库管理 ─────────────────────────────────────────────────────────────

function loadIgnoreDb(): IgnoreDb {
  if (!existsSync(IGNORE_DB_FILE)) {
    return { rules: [], updatedAt: new Date().toISOString() }
  }
  try {
    return JSON.parse(readFileSync(IGNORE_DB_FILE, "utf-8"))
  } catch {
    return { rules: [], updatedAt: new Date().toISOString() }
  }
}

function saveIgnoreDb(db: IgnoreDb) {
  const dir = join(process.cwd(), ".scans")
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(IGNORE_DB_FILE, JSON.stringify(db, null, 2), "utf-8")
}

/**
 * 获取所有忽略规则
 */
export function getAllIgnoreRules(): IgnoreRule[] {
  // 从文件 + DB 合并去重
  const fileRules = parseIgnoreFile(IGNORE_RULES_FILE)
  const dbRules = loadIgnoreDb().rules

  // DB 规则优先（覆盖文件规则的相同 pattern）
  const dbPatterns = new Set(dbRules.map(r => r.pattern))
  return [...dbRules, ...fileRules.filter(r => !dbPatterns.has(r.pattern))]
}

/**
 * 添加 UI 标记的忽略规则
 */
export function addIgnoreRule(pattern: string, comment?: string): IgnoreRule[] {
  const db = loadIgnoreDb()
  // 去重
  db.rules = db.rules.filter(r => r.pattern !== pattern)
  db.rules.push({
    pattern,
    createdAt: new Date().toISOString(),
    comment,
    source: "ui",
  })
  db.updatedAt = new Date().toISOString()
  saveIgnoreDb(db)
  return getAllIgnoreRules()
}

/**
 * 移除忽略规则
 */
export function removeIgnoreRule(pattern: string): IgnoreRule[] {
  const db = loadIgnoreDb()
  db.rules = db.rules.filter(r => r.pattern !== pattern)
  db.updatedAt = new Date().toISOString()
  saveIgnoreDb(db)
  return getAllIgnoreRules()
}

// ─── 匹配引擎 ───────────────────────────────────────────────────────────────

/**
 * 简单的 glob 匹配 — 支持 * 和 **
 */
function globMatch(pattern: string, value: string): boolean {
  // 将模式转为正则
  const regexStr = pattern
    .replace(/\*\*/g, "___DOUBLE_WILDCARD___")
    .replace(/\*/g, "[^/]*")
    .replace(/___DOUBLE_WILDCARD___/g, ".*")
    .replace(/\?/g, ".")
  try {
    return new RegExp(`^${regexStr}$`).test(value)
  } catch {
    return false
  }
}

/**
 * 检查某个漏洞是否匹配忽略规则
 */
function matchesRule(vuln: Vulnerability, rule: IgnoreRule): boolean {
  const [scannerPattern, ...rest] = rule.pattern.split(":")
  const valuePattern = rest.join(":") // pattern 部分可能包含冒号（如 CVE 编号）

  if (!scannerPattern || valuePattern === undefined) return false

  // 匹配扫描器
  const scannerName = vuln.source || ""
  if (!globMatch(scannerPattern, scannerName) && scannerPattern !== "*") return false

  // 匹配值
  // 检查 CVE
  if (vuln.cve && globMatch(valuePattern, vuln.cve)) return true
  // 检查 ID (SG-1, TRIVY-1, B101, CKV_xxx 等)
  if (globMatch(valuePattern, vuln.id)) return true
  // 检查名称
  if (globMatch(valuePattern, vuln.name)) return true
  // 检查位置路径
  if (globMatch(valuePattern, vuln.location)) return true
  // 通配符: 忽略该扫描器所有
  if (valuePattern === "*") return true

  return false
}

/**
 * 过滤掉被忽略的漏洞
 * @param vulnerabilities 原始漏洞列表
 * @returns 过滤后的漏洞列表 + 被忽略的计数
 */
export function filterIgnored(vulnerabilities: Vulnerability[]): {
  filtered: Vulnerability[]
  ignoredCount: number
} {
  const rules = getAllIgnoreRules()
  if (rules.length === 0) {
    return { filtered: vulnerabilities, ignoredCount: 0 }
  }

  const filtered: Vulnerability[] = []
  let ignoredCount = 0

  for (const vuln of vulnerabilities) {
    const isIgnored = rules.some(rule => matchesRule(vuln, rule))
    if (isIgnored) {
      ignoredCount++
    } else {
      filtered.push(vuln)
    }
  }

  return { filtered, ignoredCount }
}

/**
 * 为某个漏洞生成唯一标识键（用于 UI 标记）
 */
export function getVulnKey(vuln: Vulnerability): string {
  return `${vuln.source || "*"}:${vuln.cve || vuln.id}`
}
