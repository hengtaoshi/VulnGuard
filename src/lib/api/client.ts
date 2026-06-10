import type { ScanSummary, ScanDetail, DashboardStats } from "./types"

const BASE_URL = "/api"

async function fetcher<T>(url: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${url}`)
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

export function getScans() {
  return fetcher<ScanSummary[]>("/scans")
}

export function getScanDetail(id: string) {
  return fetcher<ScanDetail>(`/scans/${id}`)
}

export function getStats() {
  return fetcher<DashboardStats>("/stats")
}

export async function createScan(data: { target?: string; url?: string; mode?: string }) {
  const res = await fetch(`${BASE_URL}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

export async function getLLMAnalysis(data: {
  target: string
  riskScore: string
  summary: { critical: number; high: number; medium: number; low: number; passed: number }
  vulnerabilities: { name: string; severity: string; location: string; description: string }[]
}) {
  const res = await fetch(`${BASE_URL}/llm/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error(`LLM API error: ${res.status}`)
  return res.json() as Promise<{
    riskAssessment: string
    priorityFixes: string[]
    architectureRisks: string[]
    complianceNotes: string[]
    overallAdvice: string
  }>
}

export async function deleteScan(id: string) {
  const res = await fetch(`${BASE_URL}/scans/${id}`, { method: "DELETE" })
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}

export async function clearScans() {
  const res = await fetch(`${BASE_URL}/scans`, { method: "DELETE" })
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  return res.json()
}
