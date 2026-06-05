import { describe, it, expect } from "vitest"
import { mockVulnerabilities, mockScans } from "@/lib/api/mock-data"

describe("mock data integrity", () => {
  it("all vulnerabilities have required fields", () => {
    for (const v of mockVulnerabilities) {
      expect(v.id).toBeTruthy()
      expect(v.name).toBeTruthy()
      expect(v.severity).toMatch(/^(Critical|High|Medium|Low)$/)
      expect(v.location).toBeTruthy()
      expect(v.description).toBeTruthy()
      expect(v.recommendation).toBeTruthy()
    }
  })

  it("vulnerability CVE format is valid", () => {
    for (const v of mockVulnerabilities) {
      if (v.cve !== "—") {
        expect(v.cve).toMatch(/^CVE-\d{4}-\d{4,}$/)
      }
    }
  })

  it("scan summaries have valid status and type", () => {
    for (const s of mockScans) {
      expect(["completed", "scanning", "pending", "failed"]).toContain(s.status)
      expect(["url", "source"]).toContain(s.type)
    }
  })
})
