/**
 * llm-client.ts — DeepSeek LLM API 共享客户端
 *
 * 封装 DeepSeek Chat Completions API 调用，供 orchestrator、ai-aggregator、
 * 供 orchestrator、ai-aggregator 等模块统一使用。
 */

import { getSettings } from "../settings-store"

function getModel(): string {
  return process.env.DEEPSEEK_MODEL || getSettings().deepseekModel || "deepseek-v4-flash"
}
function getApiUrl(): string {
  return `${process.env.DEEPSEEK_BASE_URL || getSettings().deepseekBaseUrl || "https://api.deepseek.com"}/v1/chat/completions`
}

export interface LlmMessage {
  role: "system" | "user" | "assistant"
  content: string
}

export interface LlmOptions {
  temperature?: number
  maxTokens?: number
  timeoutMs?: number
}

/**
 * 检查 DeepSeek API 是否可用
 */
export function isLlmAvailable(): boolean {
  return !!(process.env.DEEPSEEK_API_KEY || getSettings().deepseekApiKey)
}

/**
 * 调用 DeepSeek API 并返回解析后的文本内容
 * 返回 null 表示 API 不可用或调用失败
 */
export async function callLlm(
  systemPrompt: string,
  userPrompt: string,
  options: LlmOptions = {},
): Promise<string | null> {
  const apiKey = process.env.DEEPSEEK_API_KEY || getSettings().deepseekApiKey
  if (!apiKey) return null

  const {
    temperature = 0.2,
    maxTokens = 4096,
    timeoutMs = 60000,
  } = options

  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)

    const res = await fetch(getApiUrl(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: getModel(),
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        temperature,
        max_tokens: maxTokens,
      }),
      signal: controller.signal,
    })

    clearTimeout(timer)

    if (!res.ok) {
      const errBody = await res.text().catch(() => "")
      console.warn(`[llm-client] DeepSeek API error ${res.status}: ${errBody.slice(0, 200)}`)
      return null
    }

    const json = await res.json()
    const content: string = json?.choices?.[0]?.message?.content || ""
    return content || null
  } catch (err) {
    console.warn(`[llm-client] DeepSeek call failed: ${err instanceof Error ? err.message : String(err)}`)
    return null
  }
}

/**
 * 调用 DeepSeek API 并解析返回的 JSON 对象
 * 自动处理 markdown 代码块包裹
 */
export async function callLlmJson<T>(
  systemPrompt: string,
  userPrompt: string,
  options: LlmOptions = {},
): Promise<T | null> {
  const content = await callLlm(systemPrompt, userPrompt, options)
  if (!content) return null

  try {
    // 去掉 markdown 代码块包裹（```json ... ```）
    const cleaned = content
      .replace(/```(?:json)?\s*/gi, "")
      .replace(/```\s*$/g, "")
      .trim()
    return JSON.parse(cleaned) as T
  } catch {
    console.warn(`[llm-client] Failed to parse LLM JSON response: ${content.slice(0, 200)}`)
    return null
  }
}
