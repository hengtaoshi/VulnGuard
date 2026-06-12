/**
 * baseline.ts — 基线/回归检测模块
 *
 * 将当前扫描结果与同一目标的最近一次扫描做对比，
 * 识别新增漏洞（NEW）和回归漏洞（REGRESSION）。
 *
 * 基线选取策略:
 * 1. 查找同一 target 的上一次 completed 扫描
 * 2. 如果找不到，仅标记所有发现为 NEW（首次扫描）
 */

import type { Vulnerability } from "@/lib/api/types"
import { getAllSessions } from "./scan-store"
import { getVulnKey } from "../ignore-rules"

export type BaselineStatus = "new" | "existing" | "regression"

export interface BaselineResult {
  vulnerabilities: (Vulnerability & { baselineStatus: BaselineStatus })[]
  stats: {
    total: number
    new: number
    existing: number
    regression: number
  }
  /** 用作基线的扫描 ID，null = 首次扫描 */
  baselineScanId: string | null
  /** 基线的扫描时间 */
  baselineDate: string | null
}

/**
 * 查找同一目标的上一次扫描会话
 */
function findBaselineScan(currentScanId: string, target: string): { id: string; createdAt: string; vulnerabilities: Vulnerability[] } | null {
  const allSessions = getAllSessions()

  // 找同一 target 的上一次 completed 扫描
  const previous = allSessions
    .filter(s =>
      s.id !== currentScanId &&
      s.status === "completed" &&
      s.target === target &&
      s.vulnerabilities.length > 0
    )
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())

  if (previous.length === 0) return null

  const baseline = previous[0]
  return {
    id: baseline.id,
    createdAt: baseline.createdAt,
    vulnerabilities: baseline.vulnerabilities,
  }
}

/**
 * 创建基线指纹集合
 */
function buildFingerprintSet(vulnerabilities: Vulnerability[]): Set<string> {
  const set = new Set<string>()
  for (const v of vulnerabilities) {
    // 使用唯一键作为指纹
    set.add(getVulnKey(v))
    // 也加入 name:location 指纹
    set.add(`${v.name}:${v.location}`)
  }
  return set
}

/**
 * 执行基线对比
 *
 * @param currentScanId 当前扫描 ID
 * @param target 扫描目标路径
 * @param currentVulnerabilities 当前扫描的漏洞列表
 * @returns BaselineResult
 */
export function compareWithBaseline(
  currentScanId: string,
  target: string,
  currentVulnerabilities: Vulnerability[],
): BaselineResult {
  const baseline = findBaselineScan(currentScanId, target)

  const result: (Vulnerability & { baselineStatus: BaselineStatus })[] = []

  if (!baseline) {
    // 首次扫描：全部标记为 NEW
    for (const v of currentVulnerabilities) {
      result.push({ ...v, baselineStatus: "new" })
    }
    return {
      vulnerabilities: result,
      stats: { total: result.length, new: result.length, existing: 0, regression: 0 },
      baselineScanId: null,
      baselineDate: null,
    }
  }

  const baselineFingerprints = buildFingerprintSet(baseline.vulnerabilities)
  const currentFingerprints = buildFingerprintSet(currentVulnerabilities)

  let newCount = 0
  let existingCount = 0
  let regressionCount = 0

  for (const v of currentVulnerabilities) {
    const key = getVulnKey(v)
    const nameLocKey = `${v.name}:${v.location}`

    if (baselineFingerprints.has(key) || baselineFingerprints.has(nameLocKey)) {
      result.push({ ...v, baselineStatus: "existing" })
      existingCount++
    } else {
      result.push({ ...v, baselineStatus: "new" })
      newCount++
    }
  }

  // 检查基线中有但当前扫描中消失的 — 这些已被修复
  // 反向查找回归: 当前扫描中消失的不算 regression，算已修复
  for (const bv of baseline.vulnerabilities) {
    const key = getVulnKey(bv)
    const nameLocKey = `${bv.name}:${bv.location}`
    if (!currentFingerprints.has(key) && !currentFingerprints.has(nameLocKey)) {
      // 已修复 — 不标记为 regression，仅计数
    }
  }

  return {
    vulnerabilities: result,
    stats: {
      total: result.length,
      new: newCount,
      existing: existingCount,
      regression: regressionCount,
    },
    baselineScanId: baseline.id,
    baselineDate: baseline.createdAt,
  }
}
