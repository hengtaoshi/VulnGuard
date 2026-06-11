import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

export async function runGitDumperScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "gitdumper"

  // Normalize URL: ensure it ends with /
  const baseUrl = targetPath.replace(/\/+$/, "") + "/"

  const vulnerabilities: Vulnerability[] = []

  async function checkPath(path: string): Promise<{ status: number; body: string } | null> {
    try {
      const res = await fetch(baseUrl + path, { signal: AbortSignal.timeout(8000), redirect: "manual" })
      const body = await res.text()
      return { status: res.status, body }
    } catch {
      return null
    }
  }

  // Check .git/config first — the primary indicator of .git exposure
  const configResult = await checkPath(".git/config")
  if (configResult && configResult.status === 200 && configResult.body.includes("[core]")) {
    // .git is fully exposed — HIGH severity finding
    vulnerabilities.push({
      id: "GIT-1",
      name: "Git Repository Exposed (.git/config accessible)",
      severity: "High",
      location: baseUrl + ".git/config",
      cve: "INFO-DISC",
      description:
        "The .git/config file is publicly accessible. This allows attackers to download the entire git repository including source code, commit history, credentials, and sensitive configuration.",
      recommendation:
        "Remove the .git directory from the web root, or block access to it in the web server configuration. Never deploy .git to production.",
      source: scannerName,
    })

    // Also probe .git/HEAD and .git/refs/heads/master for additional confirmation
    const headResult = await checkPath(".git/HEAD")
    if (headResult && headResult.status === 200 && headResult.body.includes("ref:")) {
      vulnerabilities.push({
        id: "GIT-2",
        name: "Git HEAD Reference Accessible",
        severity: "High",
        location: baseUrl + ".git/HEAD",
        cve: "INFO-DISC",
        description:
          "The .git/HEAD file is accessible, confirming full git repository disclosure. Attackers can reconstruct the entire source code and commit history.",
        recommendation: "Block access to the entire .git directory. Use .htaccess, nginx config, or equivalent to deny access.",
        source: scannerName,
      })
    }

    const masterResult = await checkPath(".git/refs/heads/master")
    if (masterResult && masterResult.status === 200) {
      vulnerabilities.push({
        id: "GIT-3",
        name: "Git Branch Reference Exposed",
        severity: "Medium",
        location: baseUrl + ".git/refs/heads/master",
        cve: "INFO-DISC",
        description:
          "The .git/refs/heads/master file is accessible, revealing the commit hash of the master branch. This aids attackers in reconstructing the repository.",
        recommendation: "Block access to the entire .git directory recursively.",
        source: scannerName,
      })
    }

    return { vulnerabilities, totalChecks: 3, errors: [], scannerName }
  }

  // Check if .git/HEAD gives 200 but config didn't (partial exposure)
  if (configResult && configResult.status === 200 && !configResult.body.includes("[core]")) {
    const headResult = await checkPath(".git/HEAD")
    if (headResult && headResult.status === 200 && headResult.body.includes("ref:")) {
      vulnerabilities.push({
        id: "GIT-1",
        name: "Git HEAD Reference Exposed (Partial)",
        severity: "High",
        location: baseUrl + ".git/HEAD",
        cve: "INFO-DISC",
        description:
          "The .git/HEAD file is publicly accessible, revealing the active branch reference. Partial git disclosure may allow information gathering.",
        recommendation: "Block access to the .git directory. Check for additional .git file exposure.",
        source: scannerName,
      })

      return { vulnerabilities, totalChecks: 3, errors: [], scannerName }
    }
  }

  // No git exposure found
  return { vulnerabilities: [], totalChecks: 3, errors: [], scannerName }
}
