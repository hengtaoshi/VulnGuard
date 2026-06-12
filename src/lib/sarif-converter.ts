/**
 * sarif-converter.ts — 将 VulnGuard 内部漏洞格式转换为 SARIF 2.1.0 标准 JSON
 *
 * SARIF (Static Analysis Results Interchange Format) 是 OASIS 标准，
 * GitHub、VSCode、SonarQube 等工具原生支持渲染 SARIF 报告。
 *
 * 规范: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * Schema: https://json.schemastore.org/sarif-2.1.0.json
 */

import type { Vulnerability, ScanDetail } from "@/lib/api/types"

// ─── 严重等级 → SARIF level ───────────────────────────────────────────────

function severityToLevel(severity: string): "error" | "warning" | "note" {
  switch (severity) {
    case "Critical":
    case "High":
      return "error"
    case "Medium":
      return "warning"
    case "Low":
      return "note"
    default:
      return "warning"
  }
}

// ─── 从 location 解析文件名和行号 ──────────────────────────────────────────
// location 可能是 "path/to/file:123" 或 "path/to/file:123:45" 或纯路径

interface ParsedLocation {
  uri: string
  startLine: number
  startColumn: number
}

function parseLocation(location: string, targetPath: string): ParsedLocation {
  const uriBase = targetPath.replace(/\\/g, "/").replace(/\/?$/, "/")

  // Try to extract line:column from the end of the path
  const match = location.match(/^(.+?)(?::(\d+))?(?::(\d+))?$/)
  if (!match) {
    return { uri: `file:///${uriBase}${location}`, startLine: -1, startColumn: -1 }
  }

  const [, filePath, lineStr, colStr] = match
  const startLine = lineStr ? parseInt(lineStr, 10) : -1
  const startColumn = colStr ? parseInt(colStr, 10) : -1

  return {
    uri: `file:///${uriBase}${filePath}`,
    startLine,
    startColumn,
  }
}

// ─── 去重统计 ───────────────────────────────────────────────────────────────

interface RuleStats {
  id: string
  name: string
  severity: string
  description: string
  recommendation: string
  count: number
}

function collectRules(vulnerabilities: Vulnerability[]): RuleStats[] {
  const ruleMap = new Map<string, RuleStats>()

  for (const v of vulnerabilities) {
    const key = v.name
    if (ruleMap.has(key)) {
      ruleMap.get(key)!.count++
    } else {
      ruleMap.set(key, {
        id: `VG-${ruleMap.size + 1}`,
        name: v.name,
        severity: v.severity,
        description: v.description,
        recommendation: v.recommendation,
        count: 1,
      })
    }
  }

  return Array.from(ruleMap.values())
}

// ─── 主转换函数 ─────────────────────────────────────────────────────────────

export interface SarifOutput {
  $schema: string
  version: string
  runs: SarifRun[]
}

interface SarifRun {
  tool: {
    driver: {
      name: string
      version?: string
      informationUri: string
      rules: SarifRule[]
    }
  }
  results: SarifResult[]
  properties?: Record<string, unknown>
  automationDetails?: {
    id: string
  }
  invocations?: SarifInvocation[]
}

interface SarifRule {
  id: string
  name: string
  shortDescription: {
    text: string
  }
  fullDescription?: {
    text: string
  }
  help?: {
    text: string
    markdown?: string
  }
  properties: {
    severity: string
    precision?: string
    tags?: string[]
  }
  defaultConfiguration?: {
    level: "error" | "warning" | "note"
  }
}

interface SarifResult {
  ruleId: string
  ruleIndex: number
  level: "error" | "warning" | "note"
  message: {
    text: string
  }
  locations: SarifLocation[]
  properties?: {
    severity: string
    cve?: string
    source?: string
  }
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string
    }
    region?: {
      startLine: number
      startColumn?: number
    }
  }
}

interface SarifInvocation {
  startTimeUtc: string
  endTimeUtc?: string
  executionSuccessful: boolean
}

/**
 * 将扫描详情转换为 SARIF 2.1.0 JSON 字符串
 */
export function convertToSarif(scan: ScanDetail): string {
  const vulnerabilities = scan.vulnerabilities || []
  const rules = collectRules(vulnerabilities)
  const targetPath = scan.target || ""

  // Build rule lookup
  const ruleLookup = new Map<string, RuleStats>()
  for (const r of rules) {
    ruleLookup.set(r.name, r)
  }

  // Build SARIF results
  const results: SarifResult[] = vulnerabilities.map((v, i) => {
    const rule = ruleLookup.get(v.name)
    const parsed = parseLocation(v.location, targetPath)

    return {
      ruleId: rule?.id || `VG-UNK-${i}`,
      ruleIndex: rule ? rules.indexOf(rule) : 0,
      level: severityToLevel(v.severity),
      message: {
        text: v.description || v.name,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: parsed.uri,
            },
            ...(parsed.startLine > 0
              ? {
                  region: {
                    startLine: parsed.startLine,
                    ...(parsed.startColumn > 0 ? { startColumn: parsed.startColumn } : {}),
                  },
                }
              : {}),
          },
        },
      ],
      properties: {
        severity: v.severity,
        ...(v.cve ? { cve: v.cve } : {}),
        ...(v.source ? { source: v.source } : {}),
      },
    }
  })

  // Build SARIF rules
  const sarifRules: SarifRule[] = rules.map(r => ({
    id: r.id,
    name: r.name,
    shortDescription: {
      text: r.description.slice(0, 200),
    },
    fullDescription: r.description
      ? { text: r.description }
      : undefined,
    help: r.recommendation
      ? {
          text: r.recommendation,
          markdown: r.recommendation,
        }
      : undefined,
    properties: {
      severity: r.severity,
      tags: ["vulnguard"],
    },
    defaultConfiguration: {
      level: severityToLevel(r.severity),
    },
  }))

  // Build SARIF output
  const sarif: SarifOutput = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "VulnGuard",
            informationUri: "https://vulnguard.local",
            rules: sarifRules,
          },
        },
        results,
        automationDetails: {
          id: scan.id,
        },
        properties: {
          target: targetPath,
          totalChecks: scan.totalChecks,
          riskScore: scan.riskScore,
          summary: scan.summary,
        },
        invocations: [
          {
            startTimeUtc: scan.createdAt || new Date().toISOString(),
            executionSuccessful: scan.status === "completed",
          },
        ],
      },
    ],
  }

  return JSON.stringify(sarif, null, 2)
}

/**
 * 生成 SARIF 下载文件名
 */
export function getSarifFilename(scanId: string): string {
  return `vulnguard-${scanId.slice(0, 12)}.sarif.json`
}
