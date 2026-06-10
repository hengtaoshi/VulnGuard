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

export const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || "deepseek-v4-flash"
export const DEEPSEEK_API_URL = `${process.env.DEEPSEEK_BASE_URL || "https://api.deepseek.com"}/v1/chat/completions`
