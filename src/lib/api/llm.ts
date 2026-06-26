export interface LLMAnalysisRequest {
  target: string
  riskScore: string
  summary: {
    critical: number
    high: number
    medium: number
    low: number
    passed: number
  }
  vulnerabilities: {
    name: string
    severity: string
    location: string
    description: string
  }[]
}

export interface LLMAnalysisResponse {
  riskAssessment: string
  priorityFixes: string[]
  architectureRisks: string[]
  complianceNotes: string[]
  overallAdvice: string
}

import { getSettings } from "../settings-store"

export function getDeepseekModel(): string {
  return process.env.DEEPSEEK_MODEL || getSettings().deepseekModel || "deepseek-v4-flash"
}
export function getDeepseekApiUrl(): string {
  return `${process.env.DEEPSEEK_BASE_URL || getSettings().deepseekBaseUrl || "https://api.deepseek.com"}/v1/chat/completions`
}
