import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"

const CWD = process.cwd()

// ─── Utility ─────────────────────────────────────────────────────────────

async function fetchUrl(url: string, init?: RequestInit, retries = 2): Promise<{ ok: boolean; status: number; headers: Record<string, string>; body: string }> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000), redirect: "manual", ...init })
      const headers: Record<string, string> = {}
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v })
      const body = await res.text()
      return { ok: res.ok, status: res.status, headers, body }
    } catch (err) {
      if (attempt < retries) {
        await new Promise(r => setTimeout(r, 500 * (attempt + 1)))
        continue
      }
      return { ok: false, status: 0, headers: {}, body: (err as Error).message }
    }
  }
  return { ok: false, status: 0, headers: {}, body: "Failed after retries" }
}

// ─── HTTP Security Headers Check ─────────────────────────────────────────

export async function runHttpHeadersScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "http-headers"
  const { headers, status } = await fetchUrl(targetPath)
  if (status === 0) return { vulnerabilities: [], totalChecks: 0, errors: ["Failed to connect"], scannerName }

  const vulns: Vulnerability[] = []
  const id = (n: number) => `HTTP-HDR-${n}`

  // Security header checks
  const checks: { header: string; name: string; sev: "High" | "Medium" | "Low"; desc: string; rec: string }[] = [
    { header: "strict-transport-security", name: "Missing HSTS Header", sev: "Medium", desc: "HTTP Strict-Transport-Security header is missing. This allows downgrade attacks and cookie hijacking over HTTP.", rec: "Add Strict-Transport-Security header with a max-age of at least 31536000 and includeSubDomains." },
    { header: "content-security-policy", name: "Missing CSP Header", sev: "Medium", desc: "Content-Security-Policy header is missing. Browsers may load untrusted resources, increasing XSS risk.", rec: "Implement CSP header to restrict resource loading sources." },
    { header: "x-frame-options", name: "Missing X-Frame-Options", sev: "Medium", desc: "X-Frame-Options header is missing. The site could be embedded in iframes (clickjacking risk).", rec: "Add X-Frame-Options: DENY or SAMEORIGIN." },
    { header: "x-content-type-options", name: "Missing X-Content-Type-Options", sev: "Low", desc: "X-Content-Type-Options: nosniff is missing. Browsers may MIME-sniff responses.", rec: "Add X-Content-Type-Options: nosniff." },
    { header: "referrer-policy", name: "Missing Referrer-Policy", sev: "Low", desc: "Referrer-Policy header is missing. Referrer information may leak in cross-origin requests.", rec: "Add Referrer-Policy header (recommend: strict-origin-when-cross-origin)." },
  ]

  for (const c of checks) {
    if (!headers[c.header]) {
      vulns.push({
        id: id(vulns.length + 1), name: c.name, severity: c.sev, location: targetPath,
        cve: "MISCONFIG", description: c.desc, recommendation: c.rec, source: scannerName,
      })
    }
  }

  // Server header info disclosure
  if (headers["server"]) {
    vulns.push({
      id: id(vulns.length + 1), name: "Server Version Disclosure", severity: "Low", location: targetPath,
      cve: "INFO-DISC", description: `Server header exposes version: "${headers["server"]}". Attackers can target known vulnerabilities for this version.`, recommendation: "Remove or obfuscate the Server header, or set it to a generic value.",
      source: scannerName,
    })
  }

  // X-Powered-By info disclosure
  if (headers["x-powered-by"]) {
    vulns.push({
      id: id(vulns.length + 1), name: "X-Powered-By Information Disclosure", severity: "Low", location: targetPath,
      cve: "INFO-DISC", description: `X-Powered-By header reveals: "${headers["x-powered-by"]}". This exposes the server technology to attackers.`, recommendation: "Remove the X-Powered-By header in server configuration.",
      source: scannerName,
    })
  }

  // Set-Cookie analysis
  const setCookie = headers["set-cookie"] || ""
  if (setCookie) {
    if (!setCookie.toLowerCase().includes("httponly")) {
      vulns.push({
        id: id(vulns.length + 1), name: "Cookie Missing HttpOnly Flag", severity: "Medium", location: targetPath,
        cve: "MISCONFIG", description: "Cookies set without HttpOnly flag — accessible to JavaScript, increasing XSS impact.", recommendation: "Add HttpOnly flag to all session cookies.",
        source: scannerName,
      })
    }
    if (!setCookie.toLowerCase().includes("secure")) {
      vulns.push({
        id: id(vulns.length + 1), name: "Cookie Missing Secure Flag", severity: "Medium", location: targetPath,
        cve: "MISCONFIG", description: "Cookies set without Secure flag — may be transmitted over HTTP connections.", recommendation: "Add Secure flag to all session cookies.",
        source: scannerName,
      })
    }
    if (!setCookie.toLowerCase().includes("samesite")) {
      vulns.push({
        id: id(vulns.length + 1), name: "Cookie Missing SameSite Attribute", severity: "Low", location: targetPath,
        cve: "MISCONFIG", description: "Cookies set without SameSite attribute — may be sent in cross-site requests (CSRF risk).", recommendation: "Add SameSite=Lax or SameSite=Strict to session cookies.",
        source: scannerName,
      })
    }
  }

  return { vulnerabilities: vulns, totalChecks: checks.length + 4, errors: [], scannerName }
}

// ─── CORS Misconfiguration Detection ─────────────────────────────────────

export async function runCorsScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "cors-detector"
  const baseUrl = targetPath.replace(/\/+$/, "")

  const vulns: Vulnerability[] = []
  const id = (n: number) => `CORS-${n}`

  // Test with a malicious origin
  try {
    const res = await fetch(baseUrl, {
      headers: { Origin: "https://evil.com" },
      signal: AbortSignal.timeout(10000),
      redirect: "manual",
    })

    const acao = res.headers.get("access-control-allow-origin")
    const acac = res.headers.get("access-control-allow-credentials")
    const acam = res.headers.get("access-control-allow-methods")

    if (acao === "*") {
      vulns.push({
        id: id(vulns.length + 1), name: "CORS Wildcard Origin", severity: "High", location: baseUrl,
        cve: "CORS-MISCONFIG", description: "Access-Control-Allow-Origin: * allows any website to make cross-origin requests. If sensitive data is returned, this can lead to data theft.", recommendation: "Restrict Access-Control-Allow-Origin to specific trusted origins instead of using wildcard.",
        source: scannerName,
      })
    } else if (acao === "https://evil.com") {
      vulns.push({
        id: id(vulns.length + 1), name: "CORS Origin Reflection", severity: "High", location: baseUrl,
        cve: "CORS-MISCONFIG", description: "Access-Control-Allow-Origin reflects any Origin header value — allows arbitrary cross-origin access.", recommendation: "Use a whitelist of allowed origins instead of reflecting the Origin header.",
        source: scannerName,
      })
    }

    if (acac === "true" && (acao === "*" || acao === "https://evil.com")) {
      vulns.push({
        id: id(vulns.length + 1), name: "CORS With Credentials Enabled", severity: "Critical", location: baseUrl,
        cve: "CORS-MISCONFIG", description: "Access-Control-Allow-Credentials: true combined with permissive Origin allows attackers to make authenticated cross-origin requests.", recommendation: "Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins.",
        source: scannerName,
      })
    }

    if (acam === "*" || acam === "GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD") {
      vulns.push({
        id: id(vulns.length + 1), name: "CORS Unrestricted Methods", severity: "Low", location: baseUrl,
        cve: "CORS-MISCONFIG", description: "Access-Control-Allow-Methods is overly permissive.", recommendation: "Restrict allowed methods to only those required by the application.",
        source: scannerName,
      })
    }
  } catch {
    // Connection error — skip CORS check
  }

  return { vulnerabilities: vulns, totalChecks: 4, errors: [], scannerName }
}

// ─── Form Security Analyzer ──────────────────────────────────────────────

export async function runFormScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "form-analyzer"
  const { body, status } = await fetchUrl(targetPath)
  if (status === 0) return { vulnerabilities: [], totalChecks: 0, errors: ["Failed to connect"], scannerName }

  const vulns: Vulnerability[] = []
  const id = (n: number) => `FORM-${n}`

  // Extract form elements
  const formRegex = /<form[\s\S]*?<\/form>/gi
  const forms = body.match(formRegex) || []

  for (let fi = 0; fi < forms.length; fi++) {
    const f = forms[fi]

    // Check form action
    const actionMatch = f.match(/action\s*=\s*["']([^"']*)["']/i)
    const action = actionMatch?.[1] || ""

    // Check if form submits to HTTP (plaintext)
    if (action.startsWith("http://")) {
      vulns.push({
        id: id(vulns.length + 1), name: "Form Submits Over HTTP", severity: "High", location: `${targetPath} (form #${fi + 1})`,
        cve: "INSECURE-FORM", description: "Form action points to an HTTP URL — data will be transmitted in plaintext.", recommendation: "Change form action to HTTPS URL to ensure encrypted transmission.",
        source: scannerName,
      })
    }

    // Check for password fields
    if (f.includes('type="password"') || f.includes("type='password'")) {
      // Check autocomplete
      if (!f.includes("autocomplete=")) {
        vulns.push({
          id: id(vulns.length + 1), name: "Password Field Without Autocomplete Protection", severity: "Low", location: `${targetPath} (form #${fi + 1})`,
          cve: "MISCONFIG", description: "Password field does not have autocomplete=off — browser may remember and auto-fill the password.", recommendation: "Add autocomplete=off to password fields, or use autocomplete=new-password for password managers.",
          source: scannerName,
        })
      }

      // Check form action protocol
      if (!targetPath.startsWith("https") && !action.startsWith("https")) {
        vulns.push({
          id: id(vulns.length + 1), name: "Password Form on HTTP Page", severity: "Critical", location: `${targetPath} (form #${fi + 1})`,
          cve: "INSECURE-FORM", description: "Password form is served over HTTP — credentials can be intercepted via MITM.", recommendation: "Serve login/register pages exclusively over HTTPS.",
          source: scannerName,
        })
      }
    }

    // Check for external form action
    if (action && !action.startsWith("#") && !action.startsWith("/") && !action.startsWith(targetPath.replace(/\/[^/]*$/, ""))) {
      const hostname = new URL(targetPath).hostname
      if (!action.includes(hostname) && action.startsWith("http")) {
        vulns.push({
          id: id(vulns.length + 1), name: "Form Submits to External Domain", severity: "Medium", location: `${targetPath} (form #${fi + 1})`,
          cve: "EXTERNAL-FORM", description: `Form action points to "${action}" — data may be sent to an external/third-party server.`, recommendation: "Verify this external endpoint is authorized and uses HTTPS. Consider proxying through your own server.",
          source: scannerName,
        })
      }
    }
  }

  return { vulnerabilities: vulns, totalChecks: Math.max(forms.length, 1), errors: [], scannerName }
}

// ─── Error Page Analyzer ─────────────────────────────────────────────────

export async function runErrorPageScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "error-analyzer"
  const baseUrl = targetPath.replace(/\/+$/, "")
  const vulns: Vulnerability[] = []
  const id = (n: number) => `ERR-${n}`

  // Test 1: Non-existent path for path disclosure
  const randomPath = `/nonexistent-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const { body: errBody, headers: errHeaders, status: errStatus } = await fetchUrl(`${baseUrl}${randomPath}`)

  if (errStatus !== 404 && errStatus !== 0) {
    // Custom error page — check for path disclosure
    const pathPatterns = [
      /[a-zA-Z]:[\\/][^\s"'<>]+/i,  // Windows absolute paths
      /\/var\/www\/[^\s"'<>]*/i,    // Linux web paths
      /\/home\/[^\s"'<>]*/i,        // Home dir paths
      /\/root\/[^\s"'<>]*/i,        // Root paths
      /\/app\/[^\s"'<>]*/i,         // App paths
      /\/usr\/[^\s"'<>]*/i,         // Usr paths
    ]
    for (const pattern of pathPatterns) {
      if (pattern.test(errBody)) {
        const match = errBody.match(pattern)
        vulns.push({
          id: id(vulns.length + 1), name: "Absolute Path Disclosure", severity: "High", location: `${baseUrl}${randomPath}`,
          cve: "INFO-DISC", description: `Error page reveals absolute file path: "${match?.[0]}". Attackers can use this to understand server structure.`, recommendation: "Use relative paths in error messages and disable detailed error display in production.",
          source: scannerName,
        })
        break
      }
    }

    // Check for stack trace
    const stackPatterns = [/at\s+\S+\s+\(/i, /stack trace/i, /error\s+line\s+\d+/i, /in\s+(\/[\w./]+)/i]
    for (const pattern of stackPatterns) {
      if (pattern.test(errBody)) {
        vulns.push({
          id: id(vulns.length + 1), name: "Stack Trace Disclosure", severity: "High", location: `${baseUrl}${randomPath}`,
          cve: "INFO-DISC", description: "Error page exposes a stack trace with sensitive code structure information.", recommendation: "Disable debug mode in production. Configure custom error pages that don't expose internals.",
          source: scannerName,
        })
        break
      }
    }

    // Check for framework version disclosure
    const versionPatterns = [
      { pattern: /(?:laravel|symfony|django|rails|spring|express)\s*[\d.]+\d/i, name: "Framework" },
      { pattern: /(?:apache|nginx|iis|tomcat)\/\d[\d.]*/i, name: "Web Server" },
      { pattern: /(?:php|python|ruby|java|node|asp\.net)\s*[\d.]+\d/i, name: "Runtime" },
    ]
    for (const { pattern, name } of versionPatterns) {
      if (pattern.test(errBody)) {
        const match = errBody.match(pattern)
        vulns.push({
          id: id(vulns.length + 1), name: `${name} Version Disclosure via Error Page`, severity: "Low", location: `${baseUrl}${randomPath}`,
          cve: "INFO-DISC", description: `Error page reveals: "${match?.[0]}". Attackers can target known vulnerabilities for this version.`, recommendation: "Use generic error pages and remove version information from error output.",
          source: scannerName,
        })
        break
      }
    }
  }

  // Test 2: Check for directory listing on common paths
  const dirPaths = ["/", "/assets/", "/static/", "/backup/", "/admin/"]
  for (const dir of dirPaths) {
    try {
      const res = await fetch(`${baseUrl}${dir}`, { signal: AbortSignal.timeout(5000), redirect: "manual" })
      const body = await res.text()
      if (body.includes("Index of /") || body.includes("<title>Index of") || body.includes("[parent directory]") || body.toLowerCase().includes("directory listing")) {
        vulns.push({
          id: id(vulns.length + 1), name: "Directory Listing Enabled", severity: "High", location: `${baseUrl}${dir}`,
          cve: "MISCONFIG", description: `Directory listing is enabled on ${dir} — attackers can browse files and discover sensitive information.`, recommendation: "Disable directory listing in web server configuration.",
          source: scannerName,
        })
        break
      }
    } catch { /* skip */ }
  }

  return { vulnerabilities: vulns, totalChecks: 3, errors: [], scannerName }
}

// ─── Favicon Analyzer ────────────────────────────────────────────────────

export async function runFaviconScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "favicon-analyzer"
  const baseUrl = targetPath.replace(/\/+$/, "")
  const vulns: Vulnerability[] = []
  const id = (n: number) => `FAV-${n}`

  try {
    const res = await fetch(`${baseUrl}/favicon.ico`, { signal: AbortSignal.timeout(5000), redirect: "manual" })
    if (res.status === 200) {
      const buffer = await res.arrayBuffer()
      const bytes = new Uint8Array(buffer)

      // Calculate MD5 hash using Web Crypto API
      const hashBuffer = await crypto.subtle.digest("MD5", bytes)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("")

      vulns.push({
        id: id(vulns.length + 1), name: "Favicon Detected", severity: "Low", location: `${baseUrl}/favicon.ico`,
        cve: "FAVICON", description: `Favicon found with MD5 hash: ${hashHex}. This can be used for technology fingerprinting and asset correlation across domains.`, recommendation: "Use a unique favicon that doesn't match known frameworks or default icons. Consider removing favicon or replacing with a generic one.",
        source: scannerName,
      })
      return { vulnerabilities: vulns, totalChecks: 2, errors: [], scannerName }
    }
    // No favicon.ico found — not an error, just nothing to analyze
    return { vulnerabilities: [], totalChecks: 1, errors: [], scannerName }
  } catch {
    return { vulnerabilities: [], totalChecks: 1, errors: [], scannerName }
  }
}

// ─── Third-Party Dependency Check ────────────────────────────────────────

interface KnownVulnLib {
  name: string
  pattern: RegExp
  versionExtract: RegExp
  vulns: { maxVer: string; cve: string; desc: string }[]
}

const KNOWN_VULN_LIBS: KnownVulnLib[] = [
  {
    name: "jQuery",
    pattern: /jquery[.-]?(\d+\.\d+\.\d+)/i,
    versionExtract: /jquery[.-]?(\d+\.\d+\.\d+)/i,
    vulns: [
      { maxVer: "1.12.4", cve: "CVE-2020-11023", desc: "jQuery < 1.12.5 vulnerable to XSS via HTML parsing in .html()" },
      { maxVer: "3.4.99", cve: "CVE-2020-11022", desc: "jQuery < 3.5.0 vulnerable to XSS when processing HTML" },
    ],
  },
  {
    name: "AngularJS",
    pattern: /angular[.-]?(\d+\.\d+\.\d+)/i,
    versionExtract: /angular[.-]?(\d+\.\d+\.\d+)/i,
    vulns: [
      { maxVer: "1.7.9", cve: "CVE-2022-25844", desc: "AngularJS < 1.8.0 vulnerable to prototype pollution" },
    ],
  },
  {
    name: "React",
    pattern: /react[.-]?(\d+\.\d+\.\d+)/i,
    versionExtract: /react[.-]?(\d+\.\d+\.\d+)/i,
    vulns: [
      { maxVer: "16.8.5", cve: "CVE-2019-1010099", desc: "React < 16.8.6 has XSS vulnerability in DEV mode" },
    ],
  },
]

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number)
  const pb = b.split(".").map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0, nb = pb[i] || 0
    if (na !== nb) return na - nb
  }
  return 0
}

export async function runThirdPartyScan(targetPath: string): Promise<ScanResult> {
  const scannerName = "third-party-deps"
  const { body, status } = await fetchUrl(targetPath)
  if (status === 0) return { vulnerabilities: [], totalChecks: 0, errors: ["Failed to connect"], scannerName }

  const vulns: Vulnerability[] = []
  const id = (n: number) => `DEP-${n}`
  let checksDone = 0

  // Check script sources for known libraries
  const scriptRegex = /<script[\s\S]*?src=["']([^"']*)["'][\s\S]*?>/gi
  let scriptMatch: RegExpExecArray | null
  while ((scriptMatch = scriptRegex.exec(body)) !== null) {
    const src = scriptMatch[1]
    checksDone++

    // Check SRI integrity
    const fullTag = scriptMatch[0]
    if (!fullTag.includes("integrity=")) {
      // Check if external CDN
      if (src.includes("cdn.") || src.includes("cloudflare") || src.includes("unpkg") || src.includes("jsdelivr")) {
        vulns.push({
          id: id(vulns.length + 1), name: "External Script Missing SRI", severity: "Medium", location: src,
          cve: "SRI-MISSING", description: `Script loaded from CDN without Subresource Integrity attribute — compromised CDN could inject malicious code.`, recommendation: "Add integrity attribute with the correct hash to all externally loaded scripts.",
          source: scannerName,
        })
      }
    }

    // Check known vulnerable library versions
    for (const lib of KNOWN_VULN_LIBS) {
      const libMatch = lib.pattern.exec(src)
      if (libMatch) {
        const ver = libMatch[1]
        for (const vuln of lib.vulns) {
          if (compareVersions(ver, vuln.maxVer) <= 0) {
            vulns.push({
              id: id(vulns.length + 1), name: `Vulnerable ${lib.name} ${ver}`, severity: "High", location: src,
              cve: vuln.cve, description: vuln.desc, recommendation: `Upgrade ${lib.name} to version > ${vuln.maxVer}.`,
              source: scannerName,
            })
          }
        }
      }
    }
  }

  // Also check the full body for inline version strings
  for (const lib of KNOWN_VULN_LIBS) {
    const match = lib.versionExtract.exec(body)
    if (match) {
      const ver = match[1]
      for (const vuln of lib.vulns) {
        if (compareVersions(ver, vuln.maxVer) <= 0) {
          // Avoid duplicating if already found via script src
          const dupKey = `${vuln.cve}:${ver}`
          const exists = vulns.some(v => v.cve === dupKey)
          if (!exists) {
            vulns.push({
              id: id(vulns.length + 1), name: `Vulnerable ${lib.name} ${ver}`, severity: "High", location: targetPath,
              cve: dupKey, description: vuln.desc, recommendation: `Upgrade ${lib.name} to version > ${vuln.maxVer}.`,
              source: scannerName,
            })
          }
        }
      }
    }
  }

  return { vulnerabilities: vulns, totalChecks: Math.max(checksDone, 1), errors: [], scannerName }
}
