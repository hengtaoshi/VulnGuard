import { execSync } from "child_process"
import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

function isAvailable(): boolean {
  try {
    execSync("nmap --version", { stdio: "pipe", timeout: 5000 })
    return true
  } catch {
    return false
  }
}

function severityFromPort(port: number, service: string): "Critical" | "High" | "Medium" | "Low" {
  const sensitive = [22, 23, 21, 3306, 5432, 27017, 6379, 9200, 3389, 1433, 1521, 8080]
  if (sensitive.includes(port)) return "High"
  if (port < 1024) return "Medium"
  return "Low"
}

export async function runNmapScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "nmap"
  if (!isAvailable()) {
    return { vulnerabilities: [], totalChecks: 0, errors: ["Nmap not found. Install nmap to enable port scanning."], scannerName }
  }

  // Extract hostname from URL
  let host = targetPath.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]
  if (!host) host = targetPath

  // Quick scan: top 1000 ports with service detection
  try {
    const output = execSync(
      `nmap -sS -sV --top-ports 1000 --open -T4 -oG - "${host}"`,
      { timeout: 60000, maxBuffer: 10 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] },
    )

    const lines = output.toString().trim().split("\n")
    const vulnerabilities: Vulnerability[] = []
    let totalScanned = 0

    for (const line of lines) {
      // Grepable format: Host: ... Ports: 80/open/tcp//http///
      if (line.includes("/open/")) {
        totalScanned++
        const parts = line.split("\t")
        for (const part of parts) {
          const portMatch = part.match(/(\d+)\/open\/(\w+)\/{2}([^/]*)\/{2}/)
          if (portMatch) {
            const port = parseInt(portMatch[1])
            const protocol = portMatch[2]
            const service = portMatch[3] || "unknown"

            vulnerabilities.push({
              id: `NMAP-${vulnerabilities.length + 1}`,
              name: `Open Port: ${port}/${protocol}`,
              severity: severityFromPort(port, service),
              location: `${host}:${port}`,
              cve: "PORT-SCAN",
              description: `Port ${port}/${protocol} is open — ${service}${service ? ` (${service})` : ""}. Exposed services increase attack surface.`,
              recommendation: `Review if port ${port} needs to be publicly accessible. If not, restrict access via firewall rules. For ${service}, ensure it is patched and properly configured.`,
              source: scannerName,
            })
          }
        }
      }
    }

    // Check for unreachable
    if (vulnerabilities.length === 0 && lines.length > 0) {
      const hasError = lines.some(l => l.includes("Error") || l.includes("failed") || l.includes("0 hosts"))
      if (hasError) {
        return { vulnerabilities: [], totalChecks: 0, errors: ["Nmap could not reach the target"], scannerName }
      }
    }

    return { vulnerabilities, totalChecks: Math.max(totalScanned, 1), errors: [], scannerName }
  } catch (err: unknown) {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Nmap scan failed: ${err instanceof Error ? err.message : String(err)}`],
      scannerName,
    }
  }
}
