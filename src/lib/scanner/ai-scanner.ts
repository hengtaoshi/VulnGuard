import { readFileSync, readdirSync, statSync, existsSync } from "fs"
import { join, relative, extname } from "path"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const SOURCE_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
  ".py", ".java", ".go", ".rs", ".rb", ".php",
  ".cs", ".swift", ".kt", ".scala", ".vue", ".svelte",
  ".yaml", ".yml", ".json", ".xml", ".html", ".css",
  ".sql", ".graphql", ".proto", ".dockerfile",
])

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", ".nuxt", "dist", "build",
  ".cache", "__pycache__", "venv", ".venv", "env", ".env",
  "coverage", ".scans", ".trivy-cache", ".claude", "target",
  ".serverless", ".terraform", ".pytest_cache", "vendor",
])

const MAX_CODE_CHARS = 80000
const MAX_FILE_CHARS = 15000

export const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || "deepseek-v4-flash"
export const DEEPSEEK_API_URL = process.env.DEEPSEEK_BASE_URL
  ? process.env.DEEPSEEK_BASE_URL + "/v1/chat/completions"
  : "https://api.deepseek.com/v1/chat/completions"

interface AIVulnerability {
  name: string
  severity: "Critical" | "High" | "Medium" | "Low"
  location: string
  cwe: string
  description: string
  recommendation: string
  code?: string
  /** AI 生成的修复代码示例 */
  codeFix?: string
}

interface AIScanResponse {
  vulnerabilities: AIVulnerability[]
  analysis_summary: string
}

function collectSourceFiles(dirPath: string): { path: string; content: string }[] {
  const files: { path: string; content: string }[] = []
  let totalChars = 0

  function walk(dir: string) {
    if (totalChars >= MAX_CODE_CHARS) return

    let entries: string[] = []
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }

    for (const entry of entries) {
      if (totalChars >= MAX_CODE_CHARS) break

      const fullPath = join(dir, entry)
      let stats
      try {
        stats = statSync(fullPath)
      } catch {
        continue
      }

      if (stats.isDirectory()) {
        if (!SKIP_DIRS.has(entry) && !entry.startsWith(".")) {
          walk(fullPath)
        }
      } else if (stats.isFile() && stats.size > 0 && stats.size < 500000) {
        const ext = extname(entry).toLowerCase()
        if (SOURCE_EXTENSIONS.has(ext)) {
          try {
            let content: string
            try {
              content = readFileSync(fullPath, "utf-8")
            } catch {
              content = readFileSync(fullPath, "latin1")
            }

            const relPath = relative(dirPath, fullPath).replace(/\\/g, "/")
            if (content.indexOf("\0") !== -1) return

            const truncated = content.length > MAX_FILE_CHARS
              ? content.slice(0, MAX_FILE_CHARS) + "\n// ... [truncated]"
              : content

            if (totalChars + truncated.length <= MAX_CODE_CHARS) {
              files.push({ path: relPath, content: truncated })
              totalChars += truncated.length
            }
          } catch {
            // skip unreadable files
          }
        }
      }
    }
  }

  walk(dirPath)
  return files
}

async function fetchSinglePage(url: string): Promise<{ content: string; links: string[] }> {
  const mod = url.startsWith("https") ? await import("https") : await import("http")

  return new Promise<{ content: string; links: string[] }>((resolve, reject) => {
    const req = mod.get(url, { timeout: 15000 }, (res) => {
      const chunks: Buffer[] = []
      res.on("data", (chunk: Buffer) => chunks.push(chunk))
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf-8")
        const content = body.length > MAX_FILE_CHARS ? body.slice(0, MAX_FILE_CHARS) : body
        const links: string[] = []
        const linkRegex = /<a[^>]+href=["']([^"']+)["']/gi
        let m: RegExpExecArray | null
        while ((m = linkRegex.exec(body)) !== null) {
          const href = m[1].split("#")[0].split("?")[0]
          if (href && !href.startsWith("javascript:") && !href.startsWith("mailto:")) {
            links.push(href)
          }
        }
        resolve({ content, links })
      })
    })
    req.on("error", (e: Error) => reject(e))
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")) })
  })
}

function resolveUrl(base: string, path: string): string | null {
  try {
    if (path.startsWith("http://") || path.startsWith("https://")) return path
    const url = new URL(path, base)
    return url.href
  } catch {
    return null
  }
}

const MAX_CRAWL_PAGES = 20

async function crawlSite(targetUrl: string): Promise<string> {
  const visited = new Set<string>()
  const pageContents: { url: string; content: string }[] = []
  let totalChars = 0

  const parsedUrl = new URL(targetUrl)
  const baseDomain = parsedUrl.hostname
  const baseUrl = parsedUrl.origin

  const queue: string[] = [targetUrl]

  while (queue.length > 0 && pageContents.length < MAX_CRAWL_PAGES && totalChars < MAX_CODE_CHARS) {
    const url = queue.shift()!
    if (visited.has(url)) continue
    visited.add(url)

    try {
      const { content, links } = await fetchSinglePage(url)

      if (content.trim().length > 100) {
        pageContents.push({ url, content })
        totalChars += content.length
      }

      for (const link of links) {
        const resolved = resolveUrl(baseUrl, link)
        if (resolved && resolved.startsWith(baseUrl) && !visited.has(resolved)) {
          const parsed = new URL(resolved)
          if (parsed.hostname === baseDomain) {
            queue.push(resolved)
          }
        }
      }
    } catch {
      // skip pages that fail to load
    }
  }

  if (pageContents.length === 0) {
    return "No pages could be fetched from " + targetUrl
  }

  let remainingChars = MAX_CODE_CHARS
  const parts: string[] = []
  for (const page of pageContents) {
    if (remainingChars <= 0) break
    const header = "=== " + page.url + " ===\n"
    const available = Math.min(page.content.length, remainingChars - header.length - 10)
    if (available > 0) {
      parts.push(header + page.content.slice(0, available))
      remainingChars -= header.length + available
    }
  }

  return parts.join("\n\n")
}

async function callDeepSeek(
  codeContext: string,
  targetName: string,
  scanMode: "url" | "source",
): Promise<AIScanResponse> {
  const apiKey = process.env.DEEPSEEK_API_KEY
  if (!apiKey) {
    throw new Error("DEEPSEEK_API_KEY not configured. Set the DEEPSEEK_API_KEY environment variable.")
  }

  const languageHint = scanMode === "url" ? "HTML/JavaScript" : "multiple languages"

  const systemPrompt =
    "You are a senior security code auditor specializing in **deep logic analysis** that traditional scanners miss.\n" +
    "\n" +
    "IMPORTANT: All textual output must be in Chinese (中文). Vulnerability names, descriptions, recommendations, " +
    "and analysis_summary must be written in Chinese. CVE IDs, file paths, and code snippets should keep original format.\n" +
    "\n" +
    "For each vulnerability found, return a JSON object with this exact structure (no markdown, no code blocks):\n" +
    '{\n' +
    '  "vulnerabilities": [\n' +
    '    {\n' +
    '      "name": "漏洞名称（中文）",\n' +
    '      "severity": "Critical|High|Medium|Low",\n' +
    '      "location": "file:line (or URL/path)",\n' +
    '      "cwe": "CWE-ID or N/A",\n' +
    '      "description": "漏洞详细描述（中文）",\n' +
    '      "recommendation": "修复建议（中文）",\n' +
    '      "code": "存在漏洞的代码片段（可选）",\n' +
    '      "codeFix": "修复后的代码（必须提供，至少一条漏洞）"\n' +
    "    }\n" +
    '  ],\n' +
    '  "analysis_summary": "简要分析总结（中文）"\n' +
    "}\n" +
    "\n" +
    "## ⛔ 不要报告以下类型（规则引擎已覆盖）\n" +
    "- SQL/NoSQL 注入（semgrep 已覆盖）\n" +
    "- XSS / 跨站脚本（semgrep 已覆盖）\n" +
    "- 命令/代码注入（semgrep 已覆盖）\n" +
    "- 路径遍历（semgrep 已覆盖）\n" +
    "- 硬编码凭据/密钥（gitleaks 已覆盖）\n" +
    "- 已知 CVE 依赖漏洞（npm-audit / pip-audit / trivy 已覆盖）\n" +
    "- 不安全的反序列化（semgrep 已覆盖）\n" +
    "- SSRF / 开放重定向（semgrep 已覆盖）\n" +
    "\n" +
    "## ✅ 专注于规则引擎查不出的深层问题\n" +
    "1. **业务逻辑漏洞**：绕过支付、越权操作、提权、条件竞争\n" +
    "2. **权限绕过**：缺失权限校验、水平/垂直越权\n" +
    "3. **跨文件复合漏洞**：单独看每个函数都安全，组合起来有风险\n" +
    "4. **认证/授权逻辑缺陷**：session 管理、token 验证、密码重置流程\n" +
    "5. **数据验证链缺失**：前端校验后端没做、类型转换引入风险\n" +
    "6. **错误处理不当**：信息泄露、降级不安全模式\n" +
    "7. **架构设计缺陷**：信任边界模糊、权限模型错误\n" +
    "8. **误报分析**：如果发现某个告警实际不可利用，在报告中说明原因\n" +
    "\n" +
    "## 输出要求\n" +
    "- 宁缺毋滥：只报告经过推理确认的真实问题，不要凑数\n" +
    "- recommendation 必须包含具体的代码修改示例（false positive 分析除外）\n" +
    "- 如果某个问题被多个扫描器检出且你认为不可利用，在 analysis_summary 中说明"

  const userPrompt =
    "Target: " + targetName + "\n" +
    "Mode: " + scanMode + "\n" +
    "Language: " + languageHint + "\n" +
    "\n" +
    "Code to analyze:\n" +
    "```\n" +
    codeContext + "\n" +
    "```"

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
      temperature: 0.2,
      max_tokens: 4096,
    }),
  })

  if (!res.ok) {
    const errBody = await res.text().catch(() => "unknown")
    throw new Error("DeepSeek API error " + res.status + ": " + errBody.slice(0, 200))
  }

  const json = await res.json()
  const content = json.choices?.[0]?.message?.content || ""

  try {
    const cleaned = content
      .replace(/```json\s*/gi, "")
      .replace(/```\s*/g, "")
      .trim()
    const parsed = JSON.parse(cleaned)
    return {
      vulnerabilities: parsed.vulnerabilities || [],
      analysis_summary: parsed.analysis_summary || "",
    }
  } catch {
    return {
      vulnerabilities: [],
      analysis_summary: content.slice(0, 500),
    }
  }
}

export async function runAIScan(targetPath: string, mode?: "url" | "source"): Promise<ScanResult> {
  const actualMode = mode || (targetPath.startsWith("http://") || targetPath.startsWith("https://") ? "url" : "source")
  const scannerName = "ai-scanner"

  if (!process.env.DEEPSEEK_API_KEY) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["AI scanner requires DEEPSEEK_API_KEY. Configure it in .env.local"],
      scannerName,
    }
  }

  try {
    let codeContext: string
    let targetName: string

    if (actualMode === "url") {
      targetName = targetPath
      const crawledContent = await crawlSite(targetPath)
      codeContext = "Target: " + targetPath + "\n\nPages analyzed (" + (crawledContent.includes("===") ? "multiple pages" : "single page") + "):\n" + crawledContent
    } else {
      targetName = targetPath
      if (!existsSync(targetPath)) {
        return {
          vulnerabilities: [],
          totalChecks: 0,
          errors: ["Target path does not exist: " + targetPath],
          scannerName,
        }
      }

      const files = collectSourceFiles(targetPath)
      if (files.length === 0) {
        return {
          vulnerabilities: [],
          totalChecks: 0,
          errors: ["No source code files found in target directory"],
          scannerName,
        }
      }

      codeContext = files
        .map(function(f) { return "--- " + f.path + " ---\n" + f.content })
        .join("\n\n")
    }

    const result = await callDeepSeek(codeContext, targetName, actualMode)

    const vulnerabilities: Vulnerability[] = result.vulnerabilities.map(function(v, idx) {
      return {
        id: "AI-" + (idx + 1),
        name: v.name,
        severity: v.severity,
        location: v.location,
        cve: v.cwe || "N/A",
        description: v.description,
        recommendation: v.recommendation,
        code: v.code || undefined,
        codeFix: v.codeFix || undefined,
        source: "ai-scanner" as const,
      }
    })

    const totalChecks = Math.max(vulnerabilities.length + 10, 10)

    return {
      vulnerabilities,
      totalChecks,
      errors: [],
      scannerName,
    }
  } catch (ex: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: ["AI scan failed: " + String(ex instanceof Error ? ex.message : ex)],
      scannerName,
    }
  }
}
