import type { Vulnerability } from "@/lib/api/types"
import type { ScanResult } from "./types"
import { readdirSync, existsSync } from "fs"
import { join } from "path"

// ─── Types ─────────────────────────────────────────────────────────────────

export interface CrawledPage {
  url: string
  title: string
  depth: number
  statusCode: number
  contentType: string
  /** Forms found on this page */
  forms: { action: string; method: string; fields: { name: string; type: string }[] }[]
  hasPasswordField: boolean
  hasFileUpload: boolean
  /** Links found on this page (same-domain, non-static) */
  links: string[]
  /** Technologies detected from page content */
  techDetected: string[]
}

export interface CrawlResult {
  pages: CrawledPage[]
  /** All unique discovered URLs (including main page) */
  sitemap: { url: string; title: string; depth: number }[]
  totalPages: number
  totalForms: number
  totalPasswordFields: number
  totalFileUploads: number
  durationMs: number
}

// ─── Fetch with timeout and redirect handling ─────────────────────────────

interface FetchResponse {
  status: number
  headers: Record<string, string>
  contentType: string
  html: string
}

async function smartFetch(url: string): Promise<FetchResponse | null> {
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)

    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 (compatible; VulnGuard/1.0; +https://vulnguard.dev)" },
    })
    clearTimeout(timeout)

    const html = await res.text()
    const headers: Record<string, string> = {}
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v })

    const contentType = headers["content-type"] || ""
    return { status: res.status, headers, contentType, html }
  } catch {
    return null
  }
}

// ─── HTML Parsing Utilities ───────────────────────────────────────────────

function extractLinks(html: string, baseUrl: string): string[] {
  const links = new Set<string>()
  const base = baseUrl.replace(/\/$/, "")

  try {
    // <a href="...">
    const aRegex = /<a\s[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi
    let m: RegExpExecArray | null
    while ((m = aRegex.exec(html)) !== null) {
      const raw = m[1] || m[2] || m[3]
      if (raw && !raw.startsWith("#") && !raw.startsWith("javascript:")) {
        try {
          const absolute = new URL(raw, base).href
          links.add(absolute)
        } catch { /* skip malformed */ }
      }
    }

    // <form action="...">
    const formRegex = /<form\s[^>]*action\s*=\s*(?:"([^"]*)"|'([^']*)')/gi
    while ((m = formRegex.exec(html)) !== null) {
      const raw = m[1] || m[2]
      if (raw && !raw.startsWith("#")) {
        try {
          const absolute = new URL(raw, base).href
          links.add(absolute)
        } catch { /* skip */ }
      }
    }

    // <iframe src="..."> / <frame src="...">
    const frameRegex = /<(?:iframe|frame)\s[^>]*src\s*=\s*(?:"([^"]*)"|'([^']*)')/gi
    while ((m = frameRegex.exec(html)) !== null) {
      const raw = m[1] || m[2]
      if (raw) {
        try {
          const absolute = new URL(raw, base).href
          links.add(absolute)
        } catch { /* skip */ }
      }
    }
  } catch {
    // If URL parsing fails, return empty
  }

  return Array.from(links)
}

// ─── SPA Route Discovery ────────────────────────────────────────────────────

/** Extract route references from <script> tag data (RSC payload, JS configs, etc.) */
function extractLinksFromScriptData(html: string, baseUrl: string): string[] {
  const links = new Set<string>()
  const base = baseUrl.replace(/\/$/, "")

  // Look for "href":"/path" patterns in JSON/React props within scripts
  const jsonHrefRegex = /"href"\s*:\s*"(\\"|[^"\\])*"/g
  let m: RegExpExecArray | null
  while ((m = jsonHrefRegex.exec(html)) !== null) {
    const raw = m[0].replace(/^"href"\s*:\s*"/, "").replace(/"$/, "")
    if (raw && !raw.startsWith("#") && !raw.startsWith("javascript:") && !raw.startsWith("http")) {
      try {
        const absolute = new URL(raw, base).href
        if (absolute.startsWith(base)) links.add(absolute)
      } catch { /* skip */ }
    }
  }

  // Extract Next.js RSC module references: src/app/X/page.tsx → /X
  const rscModuleRegex = /src\/app\/([^"']+)\/page\.tsx/g
  while ((m = rscModuleRegex.exec(html)) !== null) {
    const routePath = "/" + m[1]
    try {
      const absolute = new URL(routePath, base).href
      if (absolute.startsWith(base)) links.add(absolute)
    } catch { /* skip */ }
  }

  // Path-like string literals in JS code: "/scan/new", '/reports', etc.
  const routeLiteralRegex = /["']\/(?!_next|static|api)[a-zA-Z][a-zA-Z0-9_\/-]*["']/g
  while ((m = routeLiteralRegex.exec(html)) !== null) {
    const raw = m[0].replace(/["']/g, "")
    if (raw !== "/" && !raw.includes("//") && !raw.includes(".") && raw.split("/").length <= 4) {
      try {
        const absolute = new URL(raw, base).href
        if (absolute.startsWith(base)) links.add(absolute)
      } catch { /* skip */ }
    }
  }

  return Array.from(links)
}

/** Discover Next.js page routes from the filesystem (works for localhost dev) */
function discoverNextJSRoutes(): string[] {
  const appDir = join(process.cwd(), "src", "app")
  if (!existsSync(appDir)) return []

  const routes: string[] = []

  function walk(dir: string) {
    try {
      const entries = readdirSync(dir, { withFileTypes: true })
      for (const entry of entries) {
        const fullPath = join(dir, entry.name)
        if (entry.isDirectory() && !entry.name.startsWith("_") && !entry.name.startsWith(".")) {
          walk(fullPath)
        } else if (entry.isFile() && (entry.name === "page.tsx" || entry.name === "page.ts")) {
          const relativePath = fullPath
            .replace(appDir, "")
            .replace(/\\/g, "/")
            .replace(/\/page\.(tsx|ts)$/, "")
          const route = relativePath || "/"
          // Skip dynamic route segments like [id] — can't guess param values
          if (!route.includes("[")) {
            routes.push(route)
          }
        }
      }
    } catch { /* skip unreadable dirs */ }
  }

  walk(appDir)
  return Array.from(new Set(routes)).sort()
}

function extractForms(html: string, pageUrl: string): CrawledPage["forms"] {
  const forms: CrawledPage["forms"] = []

  try {
    const formRegex = /<form[\s\S]*?<\/form>/gi
    let fm: RegExpExecArray | null
    while ((fm = formRegex.exec(html)) !== null) {
      const formHtml = fm[0]

      const actionMatch = /action\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(formHtml)
      const methodMatch = /method\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(formHtml)

      let action = actionMatch?.[1] || actionMatch?.[2] || pageUrl
      // Resolve relative action URLs
      if (!action.startsWith("http")) {
        try { action = new URL(action, pageUrl).href } catch { /* keep as-is */ }
      }
      const method = (methodMatch?.[1] || methodMatch?.[2] || "GET").toUpperCase()

      // Extract input fields
      const fields: { name: string; type: string }[] = []
      const inputRegex = /<input\s[^>]*\/?>/gi
      let im: RegExpExecArray | null
      while ((im = inputRegex.exec(formHtml)) !== null) {
        const inputTag = im[0]
        const nameMatch = /name\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(inputTag)
        const typeMatch = /type\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(inputTag)
        if (nameMatch) {
          fields.push({
            name: nameMatch[1] || nameMatch[2] || nameMatch[3] || "",
            type: (typeMatch?.[1] || typeMatch?.[2] || typeMatch?.[3] || "text").toLowerCase(),
          })
        }
      }

      forms.push({ action, method, fields })
    }
  } catch {
    // If parsing fails, return empty forms list
  }

  return forms
}

function extractTitle(html: string): string {
  const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)
  return m?.[1]?.trim() || ""
}

function detectTech(html: string, headers: Record<string, string>, status: number): string[] {
  const tech: string[] = []

  // From headers
  const server = headers["server"] || ""
  if (server.includes("nginx")) tech.push("Nginx")
  if (server.includes("Apache")) tech.push("Apache")
  if (server.includes("IIS")) tech.push("IIS")
  if (server.includes("cloudflare")) tech.push("Cloudflare")
  if (server.includes("Caddy")) tech.push("Caddy")
  if (headers["x-powered-by"]) tech.push(headers["x-powered-by"].split("/")[0])

  // From HTML content
  if (/wp-content|wp-includes|wordpress/i.test(html)) tech.push("WordPress")
  if (/Drupal|drupal/i.test(html)) tech.push("Drupal")
  if (/Joomla|joomla/i.test(html)) tech.push("Joomla")
  if (/Shopify|shopify/i.test(html)) tech.push("Shopify")
  if (/react\.js|react\.min\.js/i.test(html)) tech.push("React")
  if (/vue\.js|vue\.min\.js|Vue\.js/i.test(html)) tech.push("Vue.js")
  if (/angular\.js|angular\.min\.js|ng-app/i.test(html)) tech.push("Angular")
  if (/jquery/i.test(html)) tech.push("jQuery")
  if (/bootstrap/i.test(html)) tech.push("Bootstrap")
  if (/next\.js|nextjs/i.test(html)) tech.push("Next.js")
  if (/nuxt/i.test(html)) tech.push("Nuxt.js")
  if (/api\/|graphql|swagger/i.test(html)) tech.push("API endpoint")
  if (/\?page=|\?id=|\?q=|\?s=|\?cat=/i.test(html)) tech.push("Dynamic parameters")

  return Array.from(new Set(tech))
}

function isStaticFile(url: string): boolean {
  return /\.(pdf|zip|tar|gz|png|jpg|jpeg|gif|svg|ico|css|js|woff|woff2|ttf|eot|mp4|mp3|avi|doc|docx|xls|xlsx|ppt|pptx)$/i.test(url)
}

// ─── Page Analysis ─────────────────────────────────────────────────────────

function analyzePageSecurity(
  html: string,
  headers: Record<string, string>,
  pageUrl: string,
  status: number,
): Vulnerability[] {
  const vulns: Vulnerability[] = []
  const scannerName = "crawler"
  const id = (n: number) => `CRAWL-${n}`

  // 1. Check for missing security headers (like http-headers)
  const headerChecks: { header: string; name: string; sev: "Medium" | "Low"; desc: string; rec: string }[] = [
    {
      header: "strict-transport-security",
      name: "Missing HSTS Header",
      sev: "Medium",
      desc: "HTTP Strict-Transport-Security header is missing, allowing downgrade attacks.",
      rec: "Add Strict-Transport-Security header with max-age >= 31536000.",
    },
    {
      header: "content-security-policy",
      name: "Missing CSP Header",
      sev: "Medium",
      desc: "Content-Security-Policy header is missing, increasing XSS risk from untrusted resources.",
      rec: "Implement CSP header to restrict resource loading sources.",
    },
    {
      header: "x-frame-options",
      name: "Missing X-Frame-Options",
      sev: "Medium",
      desc: "X-Frame-Options header is missing — site could be embedded in iframes (clickjacking risk).",
      rec: "Add X-Frame-Options: DENY or SAMEORIGIN.",
    },
    {
      header: "x-content-type-options",
      name: "Missing X-Content-Type-Options",
      sev: "Low",
      desc: "X-Content-Type-Options: nosniff is missing — browsers may MIME-sniff responses.",
      rec: "Add X-Content-Type-Options: nosniff.",
    },
  ]

  for (const c of headerChecks) {
    if (!headers[c.header]) {
      vulns.push({
        id: id(vulns.length + 1),
        name: `${c.name} on ${pageUrl}`,
        severity: c.sev,
        location: pageUrl,
        cve: "MISCONFIG",
        description: c.desc,
        recommendation: c.rec,
        source: scannerName,
      })
    }
  }

  // 2. Check form security (like form-analyzer, but per-page)
  const forms = extractForms(html, pageUrl)
  for (const form of forms) {
    const pageHostname = new URL(pageUrl).hostname
    const actionHostname = form.action.startsWith("http") ? new URL(form.action).hostname : pageHostname

    // Form over HTTP
    if (form.action.startsWith("http://")) {
      vulns.push({
        id: id(vulns.length + 1),
        name: "Form Submits Over HTTP",
        severity: "High",
        location: pageUrl,
        cve: "INSECURE-FORM",
        description: `Form on ${pageUrl} submits to ${form.action} — data transmitted in plaintext.`,
        recommendation: "Change form action to HTTPS to ensure encrypted transmission.",
        source: scannerName,
      })
    }

    // Password field present
    const hasPassword = form.fields.some(f => f.type === "password")
    if (hasPassword && !pageUrl.startsWith("https")) {
      vulns.push({
        id: id(vulns.length + 1),
        name: "Password Form on HTTP Page",
        severity: "Critical",
        location: pageUrl,
        cve: "INSECURE-FORM",
        description: "Password form served over HTTP — credentials can be intercepted via MITM.",
        recommendation: "Serve login/register pages exclusively over HTTPS.",
        source: scannerName,
      })
    }

    // External form action
    if (actionHostname !== pageHostname && form.action.startsWith("http")) {
      vulns.push({
        id: id(vulns.length + 1),
        name: "Form Submits to External Domain",
        severity: "Medium",
        location: pageUrl,
        cve: "EXTERNAL-FORM",
        description: `Form submits to external domain "${form.action}". Data may be sent to third-party server.`,
        recommendation: "Verify external endpoint is authorized and uses HTTPS.",
        source: scannerName,
      })
    }
  }

  // 3. Error page info disclosure
  if (!html.toLowerCase().includes("404") && status >= 400) {
    // Check for path disclosure in error pages
    const pathPatterns = [
      /[a-zA-Z]:[\\/][^\s"'<>]+/i,
      /\/var\/www\/[^\s"'<>]*/i,
      /\/home\/[^\s"'<>]*/i,
      /\/root\/[^\s"'<>]*/i,
      /\/app\/[^\s"'<>]*/i,
    ]
    for (const pattern of pathPatterns) {
      if (pattern.test(html)) {
        const match = html.match(pattern)
        vulns.push({
          id: id(vulns.length + 1),
          name: "Absolute Path Disclosure",
          severity: "High",
          location: pageUrl,
          cve: "INFO-DISC",
          description: `Error page on ${pageUrl} reveals absolute file path: "${match?.[0]}".`,
          recommendation: "Use custom error pages and disable detailed error display in production.",
          source: scannerName,
        })
        break
      }
    }
  }

  // 4. Server version disclosure
  if (headers["server"] && headers["server"].match(/\d+\.\d+/)) {
    vulns.push({
      id: id(vulns.length + 1),
      name: `Server Version Disclosure on ${pageUrl}`,
      severity: "Low",
      location: pageUrl,
      cve: "INFO-DISC",
      description: `Server header exposes version: "${headers["server"]}". Attackers can target known vulnerabilities.`,
      recommendation: "Remove or obfuscate the Server header.",
      source: scannerName,
    })
  }

  return vulns
}

// ─── Main Crawler ─────────────────────────────────────────────────────────

export interface CrawlerCallbacks {
  onPageCrawled?: (pageNum: number, totalEstimated: number, url: string, title: string) => void
}

export async function runCrawlerScan(
  targetUrl: string,
  callbacks?: CrawlerCallbacks,
): Promise<ScanResult & { crawlResult?: CrawlResult }> {
  const scannerName = "crawler"
  const startTime = Date.now()

  // Normalize target URL
  let normalizedUrl = targetUrl.replace(/\/+$/, "")
  if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
    normalizedUrl = "https://" + normalizedUrl
  }

  let baseHostname: string
  try {
    baseHostname = new URL(normalizedUrl).hostname
  } catch {
    return {
      vulnerabilities: [],
      totalChecks: 0,
      errors: [`Invalid URL: ${targetUrl}`],
      scannerName,
    }
  }

  const visited = new Set<string>()
  const pages: CrawledPage[] = []
  const allVulns: Vulnerability[] = []

  const MAX_PAGES = 50
  const MAX_DEPTH = 2

  async function crawlPage(url: string, depth: number): Promise<void> {
    // Stop conditions
    if (depth > MAX_DEPTH) return
    if (visited.size >= MAX_PAGES) return
    if (visited.has(url)) return
    if (isStaticFile(url)) return

    visited.add(url)

    const result = await smartFetch(url)
    if (!result) return

    // Only parse HTML pages
    if (!result.html || (!result.contentType.includes("text/html") && !result.contentType.includes("application/xhtml"))) {
      // Add as a non-HTML page reference (no further analysis or link extraction)
      pages.push({
        url,
        title: "",
        depth,
        statusCode: result.status,
        contentType: result.contentType || "unknown",
        forms: [],
        hasPasswordField: false,
        hasFileUpload: false,
        links: [],
        techDetected: [],
      })
      return
    }

    const title = extractTitle(result.html)
    const forms = extractForms(result.html, url)
    const techDetected = detectTech(result.html, result.headers, result.status)
    const links = extractLinks(result.html, url)
      .filter(l => {
        try {
          const h = new URL(l).hostname
          return h === baseHostname && !visited.has(l) && !isStaticFile(l)
        } catch {
          return false
        }
      })

    const hasPasswordField = forms.some(f => f.fields.some(ff => ff.type === "password"))
    const hasFileUpload = forms.some(f => f.fields.some(ff => ff.type === "file"))

    pages.push({
      url,
      title,
      depth,
      statusCode: result.status,
      contentType: result.contentType || "text/html",
      forms,
      hasPasswordField,
      hasFileUpload,
      links,
      techDetected,
    })

    // Run security analysis on this page
    const pageVulns = analyzePageSecurity(result.html, result.headers, url, result.status)
    allVulns.push(...pageVulns)

    // Report progress
    callbacks?.onPageCrawled?.(pages.length, MAX_PAGES, url, title)

    // Recursively crawl unvisited links
    if (depth < MAX_DEPTH) {
      const unvisited = links.filter(l => !visited.has(l))
      // Limit concurrent crawling to avoid resource exhaustion
      const BATCH_SIZE = 8
      for (let i = 0; i < unvisited.length; i += BATCH_SIZE) {
        const batch = unvisited.slice(i, i + BATCH_SIZE)
        await Promise.all(batch.map(l => crawlPage(l, depth + 1)))
      }
    }
  }

  // Start crawling from the target URL
  await crawlPage(normalizedUrl, 0)

  // ── SPA Route Discovery ──────────────────────────────────────────
  // If only the main page was found (no HTML links), the target is likely
  // a JavaScript SPA. Try alternative discovery methods to find routes.
  if (pages.length <= 1) {
    // Method 1: Re-fetch the page and scan ALL content (incl. scripts) for route patterns
    const mainSource = await smartFetch(normalizedUrl)
    if (mainSource) {
      const scriptRoutes = extractLinksFromScriptData(mainSource.html, normalizedUrl)
      for (const routeUrl of scriptRoutes) {
        if (!visited.has(routeUrl)) {
          await crawlPage(routeUrl, 1)
        }
      }
    }

    // Method 2: For localhost Next.js apps, discover routes from the project filesystem
    if (pages.length <= 1 && (baseHostname === "localhost" || baseHostname === "127.0.0.1")) {
      const baseUrl = normalizedUrl.replace(/\/+$/, "")
      const fsRoutes = discoverNextJSRoutes()
      for (const route of fsRoutes) {
        const fullUrl = `${baseUrl}${route === "/" ? "" : route}`
        if (!visited.has(fullUrl)) {
          await crawlPage(fullUrl, 1)
        }
      }
    }
  }

  // ── Build Summary Findings ─────────────────────────────────────────
  const totalForms = pages.reduce((s, p) => s + p.forms.length, 0)
  const totalPasswordFields = pages.reduce((s, p) => s + (p.hasPasswordField ? 1 : 0), 0)
  const totalFileUploads = pages.reduce((s, p) => s + (p.hasFileUpload ? 1 : 0), 0)

  // Add a summary finding about discovered pages
  if (pages.length > 1) {
    allVulns.push({
      id: "CRAWL-SUMMARY",
      name: `Website Crawl Summary: ${pages.length} Pages Discovered`,
      severity: "Low",
      location: normalizedUrl,
      cve: "CRAWL",
      description:
        `Crawler discovered ${pages.length} pages (depth ${MAX_DEPTH}). ` +
        `${totalForms} forms, ${totalPasswordFields} login pages, ${totalFileUploads} file upload pages found. ` +
        `Discovered ${allVulns.length - 1} security issues across all pages.`,
      recommendation:
        "Review all discovered pages for security issues. Pay special attention to login forms and file upload functionality.",
      source: scannerName,
    })
  }

  const durationMs = Date.now() - startTime

  const crawlResult: CrawlResult = {
    pages,
    sitemap: pages.map(p => ({ url: p.url, title: p.title, depth: p.depth })),
    totalPages: pages.length,
    totalForms,
    totalPasswordFields,
    totalFileUploads,
    durationMs,
  }

  return {
    vulnerabilities: allVulns,
    totalChecks: Math.max(pages.length, 1),
    errors: [],
    scannerName,
    crawlResult,
  }
}
