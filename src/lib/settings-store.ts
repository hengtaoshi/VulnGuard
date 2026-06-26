/**
 * settings-store.ts — VulnGuard 设置持久化存储
 *
 * 设置保存在 .scans/settings.json，与应用数据同级。
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs"
import { join } from "path"

const DATA_DIR_ENV = process.env.VULNGUARD_DATA_DIR || process.env.DATA_DIR
const SETTINGS_DIR = DATA_DIR_ENV
  ? join(DATA_DIR_ENV)
  : join(process.cwd(), ".scans")
const SETTINGS_FILE = join(SETTINGS_DIR, "settings.json")

export interface AppSettings {
  /** 单次扫描最大时长（分钟），默认 30 */
  maxDuration: number
  /** 扫描完成后自动生成报告 */
  autoReport: boolean
  /** 默认扫描引擎：ai | all */
  defaultEngine: "ai" | "all"
  /** AI 聚合分析开关 */
  aiAggregation: boolean
  /** 最大并行扫描器数 */
  concurrentScanners: number
  /** 自动清理扫描数据天数（0 = 永不） */
  retentionDays: number
  /** DeepSeek API Key */
  deepseekApiKey: string
  /** DeepSeek API Base URL */
  deepseekBaseUrl: string
  /** DeepSeek 模型 */
  deepseekModel: string
  /** 代理开关 */
  proxyEnabled: boolean
  /** HTTP 代理地址 */
  httpProxy: string
  /** HTTPS 代理地址 */
  httpsProxy: string
  /** Webhook 通知开关 */
  webhookEnabled: boolean
  /** Webhook URL */
  webhookUrl: string
  /** 禁用的扫描器名称列表 */
  disabledScanners: string[]
}

export const DEFAULT_SETTINGS: AppSettings = {
  maxDuration: 30,
  autoReport: true,
  defaultEngine: "ai",
  aiAggregation: true,
  concurrentScanners: 4,
  retentionDays: 0,
  deepseekApiKey: "",
  deepseekBaseUrl: "",
  deepseekModel: "deepseek-v4-flash",
  proxyEnabled: false,
  httpProxy: "",
  httpsProxy: "",
  webhookEnabled: false,
  webhookUrl: "",
  disabledScanners: [],
}

function ensureDir() {
  if (!existsSync(SETTINGS_DIR)) {
    mkdirSync(SETTINGS_DIR, { recursive: true })
  }
}

export function getSettings(): AppSettings {
  try {
    ensureDir()
    if (!existsSync(SETTINGS_FILE)) {
      writeFileSync(SETTINGS_FILE, JSON.stringify(DEFAULT_SETTINGS, null, 2), "utf-8")
      return { ...DEFAULT_SETTINGS }
    }
    const raw = readFileSync(SETTINGS_FILE, "utf-8")
    const parsed = JSON.parse(raw)
    return { ...DEFAULT_SETTINGS, ...parsed }
  } catch {
    return { ...DEFAULT_SETTINGS }
  }
}

/**
 * 掩码 API Key，只显示前4位和后4位
 * "sk-abc123xyz789" → "sk-a****789"
 */
export function maskApiKey(key: string): string {
  if (!key || key.length < 10) return key
  return key.slice(0, 4) + "****" + key.slice(-4)
}

/**
 * 判断值是否为已被掩码的 key（4明文 + 4星号 + 4明文）
 */
export function isMaskedKey(key: string): boolean {
  return /^.{4}\*{4}.{4}$/.test(key)
}

export function updateSettings(partial: Partial<AppSettings>): AppSettings {
  ensureDir()
  const current = getSettings()
  const updated = { ...current, ...partial }
  writeFileSync(SETTINGS_FILE, JSON.stringify(updated, null, 2), "utf-8")
  return updated
}
