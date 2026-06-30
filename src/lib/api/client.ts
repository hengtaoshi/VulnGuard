import type { ScanSummary, ScanDetail, DashboardStats } from "./types"

const BASE_URL = "/api"

/**
 * Auth is handled via HttpOnly `scan_auth_token` cookie set by middleware.ts.
 * The browser automatically sends the cookie with same-origin API requests.
 * No manual Authorization header needed on the client side.
 */

async function fetcher<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${url}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  })
  if (!res.ok) {
    const body = await res.text().catch(() => "")
    let detail = ""
    try { detail = JSON.parse(body).error || body } catch { detail = body }
    throw new Error(detail || `API error: ${res.status}`)
  }
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
  return fetcher<{ id: string; status: string; target: string; type: string; engine: string }>("/scans", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function getLLMAnalysis(data: {
  target: string
  riskScore: string
  summary: { critical: number; high: number; medium: number; low: number; passed: number }
  vulnerabilities: { name: string; severity: string; location: string; description: string }[]
}) {
  return fetcher<{
    riskAssessment: string
    priorityFixes: string[]
    architectureRisks: string[]
    complianceNotes: string[]
    overallAdvice: string
  }>("/llm/analyze", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteScan(id: string) {
  return fetcher<{ success: boolean }>(`/scans/${id}`, { method: "DELETE" })
}

export async function clearScans() {
  return fetcher<{ success: boolean }>("/scans", { method: "DELETE" })
}
