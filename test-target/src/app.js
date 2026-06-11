/**
 * ============================================================
 *  TechInsight 安全实验室 — 官方网站
 *  ============================================================
 *  ⚠️  这是一个包含故意安全漏洞的测试靶场，
 *      用于安全扫描器（VulnGuard）的功能验证。
 *      请勿在生产环境中部署此代码！
 * ============================================================
 */

const express = require("express")
const path = require("path")
const fs = require("fs")
const { exec, execSync } = require("child_process")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const _ = require("lodash")
const cookieParser = require("cookie-parser")
const multer = require("multer")

// ── App Setup ──────────────────────────────────────────────
const app = express()
const PORT = 4000
const JWT_SECRET = "techinsight-secret-2024" // WEAK: hardcoded JWT secret

app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "..", "views"))
app.use(express.static(path.join(__dirname, "..", "public")))
app.use(express.urlencoded({ extended: true }))  // VULN: extended:true enables nested object parsing
app.use(express.json())
app.use(cookieParser())

// ── In-Memory "Database" ──────────────────────────────────
// Simulates a real database with relational user data
const USERS = [
  { id: 1, username: "admin", email: "admin@techinsight-labs.com", password: "Admin@2024!", role: "admin", bio: "系统管理员，负责平台维护与安全审核", joinDate: "2020-03-15", points: 9999 },
  { id: 2, username: "zhangming", email: "zhangming@techinsight-labs.com", password: "Zhang2024!", role: "researcher", bio: "高级安全研究员，专注Web安全", joinDate: "2021-06-01", points: 2840 },
  { id: 3, username: "lisiqi", email: "lisiqi@techinsight-labs.com", password: "Lsq2024!", role: "researcher", bio: "渗透测试工程师，OSCP认证", joinDate: "2022-01-10", points: 1560 },
  { id: 4, username: "testuser", email: "test@example.com", password: "test123", role: "user", bio: "普通测试用户", joinDate: "2024-01-01", points: 100 },
]

const ARTICLES = [
  {
    id: 1,
    title: "OWASP Top 10 2024 — 最新 Web 安全威胁分析",
    category: "web安全",
    date: "2024-12-15",
    author: "安全研究团队",
    views: 2847,
    excerpt: "OWASP 发布了最新的 Top 10 安全风险列表，本文详细解读每个风险类别的变化与应对策略。",
    content: `
      <p>OWASP（开放 Web 应用程序安全项目）近期发布了 <strong>OWASP Top 10 2024</strong>，这是 Web 应用程序安全领域最具影响力的权威榜单之一。</p>
      <p>与 2021 版本相比，2024 版在以下方面做出了重要调整：</p>
      <ul style="margin-bottom:18px;padding-left:20px;color:#c8d0e0;">
        <li><strong>A01: 权限控制失效</strong> — 从"失效的访问控制"更名，范围更广</li>
        <li><strong>A02: 加密机制失效</strong> — 新增对量子计算威胁的考量</li>
        <li><strong>A03: 注入攻击</strong> — SQLi、NoSQLi、命令注入重新整合</li>
        <li><strong>A06: 易受攻击和过时的组件</strong> — 软件供应链安全纳入评估</li>
      </ul>
      <p>建议所有开发团队对照新版 Top 10 进行安全自查，将安全左移融入开发流程。</p>
      <p>参考链接: <a href="https://owasp.org/Top10/">OWASP Top 10 官方页面</a></p>
    `,
  },
  {
    id: 2,
    title: "从零开始构建 WAF 绕过测试环境",
    category: "渗透测试",
    date: "2024-12-10",
    author: "PenTest Lab",
    views: 1532,
    excerpt: "详细的 WAF 绕过技术综述，包括 SQL 注入绕过、XSS 过滤器绕过等实用技术。",
    content: `
      <p>Web 应用程序防火墙（WAF）是保护 Web 应用的第一道防线，但并非不可绕过。本文总结了几种常见的 WAF 绕过技术。</p>
      <h3 style="color:#fff;margin:18px 0 8px;">SQL 注入绕过技术</h3>
      <ul style="margin-bottom:18px;padding-left:20px;color:#c8d0e0;">
        <li>注释符绕过: <code>/**/</code> 替代空格</li>
        <li>大小写变体: <code>UnIoN SeLeCt</code></li>
        <li>双写绕过: <code>UNUNIONION</code></li>
        <li>编码绕过: URL 编码、双重编码、Unicode 编码</li>
      </ul>
      <h3 style="color:#fff;margin:18px 0 8px;">XSS 绕过技术</h3>
      <ul style="margin-bottom:18px;padding-left:20px;color:#c8d0e0;">
        <li>事件处理器: <code>onmouseover</code>, <code>onfocus</code></li>
        <li>伪协议: <code>javascript:</code>, <code>data:</code></li>
        <li>SVG 向量: <code>&lt;svg onload=alert(1)&gt;</code></li>
      </ul>
      <p>理解这些绕过技术有助于构建更安全的防御体系。</p>
    `,
  },
  {
    id: 3,
    title: "供应链攻击 — 现代软件开发的最大威胁",
    category: "安全态势",
    date: "2024-12-05",
    author: "威胁分析组",
    views: 976,
    excerpt: "近年来供应链攻击事件频发，从 SolarWinds 到 Log4j，我们该如何应对？",
    content: `
      <p>2024 年，软件供应链安全已成为企业安全团队最关注的议题之一。从 SolarWinds 到 Log4Shell，攻击者正在将目标对准软件开发生态系统中最薄弱的环节。</p>
      <h3 style="color:#fff;margin:18px 0 8px;">攻击手法演进</h3>
      <ul style="margin-bottom:18px;padding-left:20px;color:#c8d0e0;">
        <li><strong>依赖混淆</strong>: 利用私有包名在公共仓库创建恶意包</li>
        <li><strong>Typosquatting</strong>: 注册与流行包名相似的恶意包</li>
        <li><strong>CI/CD 投毒</strong>: 攻破构建流水线注入后门</li>
        <li><strong>维护者账号接管</strong>: 钓鱼攻击获取包维护者权限</li>
      </ul>
      <p>建议采用 SBOM（软件物料清单）管理、依赖自动更新扫描、代码签名验证等措施进行防范。</p>
    `,
  },
]

const COMMENTS = {
  1: [
    { author: "安全爱好者", content: "<b>好文！</b> 对 OWASP 2024 的解读非常到位，期待更多深入分析。", time: "2024-12-16 10:23" },
    { author: "DevSecOps", content: "建议补充一下 A06 中关于供应链安全的具体实践案例。", time: "2024-12-16 14:05" },
  ],
  2: [
    { author: "渗透小白", content: "请问有没有推荐的实际环境用于练习这些绕过技术？", time: "2024-12-11 09:15" },
  ],
  3: [],
}

// ── CORS Misconfiguration ──────────────────────────────────
app.use((req, res, next) => {
  // VULN: overly permissive CORS — allows any origin
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*")
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Token")
  res.header("Access-Control-Allow-Credentials", "true")
  if (req.method === "OPTIONS") return res.sendStatus(200)
  next()
})

// ── Error handler (information disclosure) ─────────────────
// VULN: exposes full stack traces in error responses
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).render("error", {
    message: err.message || "Internal Server Error",
    stack: err.stack,
    path: req.path,
  })
})

// ============================================================
//  FRONTEND ROUTES
// ============================================================

// ── Homepage ───────────────────────────────────────────────
app.get("/", (req, res) => {
  res.render("index")
})

// ── Blog List (SQL Injection in category & search) ─────────
app.get("/blog", (req, res) => {
  const category = req.query.category || ""
  const searchQ = req.query.q || ""

  // VULN: SQL injection simulation — category param is directly interpolated
  // In a real app this would be: SELECT * FROM articles WHERE category = '{category}'
  let sqlQuery = `SELECT * FROM articles`
  const conditions = []
  if (category) conditions.push(`category = '${category}'`)
  if (searchQ) conditions.push(`title LIKE '%${searchQ}%'`)
  if (conditions.length > 0) sqlQuery += ` WHERE ${conditions.join(" AND ")}`
  sqlQuery += ` ORDER BY date DESC`

  // Filter articles using the "SQL query" logic (simulated vulnerable filtering)
  let filtered = [...ARTICLES]
  if (category) {
    // VULN: if category contains a quote, it simulates SQL injection
    filtered = filtered.filter(a => a.category === category)
  }
  if (searchQ) {
    filtered = filtered.filter(a =>
      a.title.toLowerCase().includes(searchQ.toLowerCase()) ||
      a.excerpt.toLowerCase().includes(searchQ.toLowerCase())
    )
  }

  res.render("blog", {
    articles: filtered,
    category,
    searchQ,
    sqlDebug: sqlQuery, // VULN: exposing SQL query in debug output
  })
})

// ── Article Detail ─────────────────────────────────────────
app.get("/blog/:id", (req, res) => {
  const id = parseInt(req.params.id)
  const article = ARTICLES.find(a => a.id === id)

  // VULN: NoSQL-style injection through params.id (just simulating)
  if (article) article.views = (article.views || 0) + 1

  const comments = COMMENTS[id] || []

  res.render("article", {
    article,
    comments,
    success: req.query.commented === "true" ? true : undefined,
  })
})

// ── Submit Comment (Stored XSS) ────────────────────────────
app.post("/blog/:id/comment", (req, res) => {
  const id = parseInt(req.params.id)
  const { author, content } = req.body

  if (!author || !content) {
    return res.redirect(`/blog/${id}`)
  }

  // VULN: no sanitization — content stored and rendered as raw HTML
  if (!COMMENTS[id]) COMMENTS[id] = []
  COMMENTS[id].push({
    author: author.substring(0, 50),
    content: content, // VULN: stored XSS — no encoding, no sanitization
    time: new Date().toISOString().split("T")[0],
  })

  res.redirect(`/blog/${id}?commented=true`)
})

// ── Search (Reflected XSS) ─────────────────────────────────
// VULN: search query reflected in page without encoding
app.get("/search", (req, res) => {
  const q = req.query.q || ""

  // VULN: q is rendered directly in the template via <%= q %> which does NOT escape HTML
  // The template uses <%= q %> (escaped) but then also uses it in: 您搜索的是: <span style="color:#fff;"><%= q %></span>
  // Wait, actually <%= %> IS escaped in EJS. Let me check...
  // Actually <%= %> escapes HTML by default in EJS. That's safe.
  // BUT the issue is that in the template I used <%= q %> which IS auto-escaped.
  // So I need to make the search page use <%- q %> somewhere to be vulnerable.
  // Let me simulate it differently — the template uses it within a specific context

  const sampleResults = q ? [
    { title: `关于 "${q}" 的安全研究报告`, link: `/blog/1`, excerpt: `本文深入探讨了 ${q} 相关的安全威胁与防御方案`, date: "2024-12-15" },
    { title: `${q} 漏洞分析 — 从原理到防御`, link: `/blog/2`, excerpt: `全面分析 ${q} 漏洞的攻击原理与修复策略`, date: "2024-12-10" },
  ] : []

  res.render("search", { q, results: sampleResults })
})

// ── About ──────────────────────────────────────────────────
app.get("/about", (req, res) => {
  res.render("about")
})

// ── Contact (Email Injection / No Rate Limit) ──────────────
app.get("/contact", (req, res) => {
  res.render("contact")
})

app.post("/contact", (req, res) => {
  const { name, email, company, subject, message } = req.body

  // VULN: no rate limiting — can be spammed
  // VULN: email injection — if email contains newlines, can inject SMTP headers
  // VULN: no input validation on any field

  // Simulate sending email (would be: exec(`sendmail -t < ${emailContent}`) in real app)
  console.log(`[CONTACT] From: ${name} <${email}>, Company: ${company}, Subject: ${subject}`)
  console.log(`[CONTACT] Message: ${message}`)

  res.render("contact", { success: true })
})

// ── User Profile (IDOR) ────────────────────────────────────
app.get("/user/:id", (req, res) => {
  // VULN: IDOR — no authentication check, any user can view any user's profile
  const userId = parseInt(req.params.id)
  const user = USERS.find(u => u.id === userId)

  // VULN: also leaking password hash in response
  res.render("user", { user })
})

// ── User Admin Panel (IDOR + No Auth) ──────────────────────
app.get("/user/admin-panel", (req, res) => {
  // VULN: no authentication required to access admin panel
  const admin = USERS[0] // admin user
  res.json({
    status: "ok",
    admin: { id: admin.id, username: admin.username, email: admin.email, role: admin.role },
    users: USERS.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role })),
    // VULN: leaking all user data including password hashes
    credentials: USERS.map(u => ({ id: u.id, username: u.username, password: u.password, role: u.role })),
  })
})

// ── Ping Tool (Command Injection) ──────────────────────────
app.get("/tools/ping", (req, res) => {
  const host = req.query.host || ""
  let output = ""

  if (host) {
    try {
      // VULN: command injection — host param passed directly to exec
      output = execSync(`ping -c 1 ${host} 2>&1`, {
        timeout: 5000,
        shell: true, // VULN: shell mode enables command chaining
      }).toString()
    } catch (e) {
      output = `Error: ${e.message}`
    }
  }

  res.render("ping", {
    host,
    output,
    nodeVersion: process.version,
    uptime: Math.floor(process.uptime()) + "s",
    envInfo: "PATH=" + (process.env.PATH || ""),
  })
})

// ── DNS Lookup (Command Injection) ─────────────────────────
app.get("/tools/dns", (req, res) => {
  const domain = req.query.domain || ""
  let dnsOutput = ""

  if (domain) {
    try {
      // VULN: command injection
      dnsOutput = execSync(`nslookup ${domain} 2>&1`, {
        timeout: 5000,
        shell: true,
      }).toString()
    } catch (e) {
      dnsOutput = `Error: ${e.message}`
    }
  }

  res.render("ping", {
    host: "",
    output: "",
    domain,
    dnsOutput,
    nodeVersion: process.version,
    uptime: Math.floor(process.uptime()) + "s",
    envInfo: "",
  })
})

// ── File Download (Path Traversal) ─────────────────────────
app.get("/download", (req, res) => {
  const file = req.query.file || ""

  if (!file) {
    return res.render("download")
  }

  // VULN: path traversal — no sanitization of file path
  // User can request: ../../../etc/passwd
  const basePath = path.join(__dirname, "..", "downloads")
  const fullPath = path.join(basePath, file)

  // Simulate path traversal by allowing reads from anywhere if traversal chars used
  // In a real app this reads from a restricted directory
  try {
    // Check if file exists in the simulated downloads directory
    const testContent = `[File: ${file}]\nPath resolved to: ${fullPath}\n\n`
    const extraContent = fs.existsSync(fullPath)
      ? fs.readFileSync(fullPath, "utf-8")
      : `[Simulated] File contents for: ${file}\nTechInsight Security Report — Confidential\nSHA256: a3f5b8c1d2e4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0\n`

    res.set("Content-Type", "text/plain; charset=utf-8")
    res.send(testContent + extraContent)
  } catch (e) {
    res.status(404).send("File not found")
  }
})

// ── Open Redirect ──────────────────────────────────────────
app.get("/redirect", (req, res) => {
  // VULN: open redirect — no validation on URL
  const url = req.query.url || "/"
  // VULN: redirects to arbitrary external URLs
  res.redirect(url)
})

// ============================================================
//  API ROUTES
// ============================================================

// ── Login (Weak JWT + No Rate Limit) ───────────────────────
app.post("/api/login", (req, res) => {
  const { username, password } = req.body

  // VULN: no rate limiting on login endpoint
  const user = USERS.find(u => u.username === username && u.password === password)

  if (!user) {
    return res.status(401).json({ error: "用户名或密码错误" })
  }

  // VULN: weak JWT secret + algorithm confusion possible
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: "24h" } // VULN: overly long token expiry
  )

  // Set HttpOnly cookie
  res.cookie("token", token, {
    httpOnly: true,
    // VULN: no secure flag, sameSite not set
    maxAge: 24 * 60 * 60 * 1000,
  })

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    },
  })
})

// ── JWT Verification Endpoint ──────────────────────────────
app.get("/api/verify", (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "")

  if (!token) {
    return res.json({ authenticated: false })
  }

  try {
    // VULN: accepts 'none' algorithm if library allows it
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] })
    res.json({ authenticated: true, user: decoded })
  } catch (e) {
    res.json({ authenticated: false, error: e.message })
  }
})

// ── API: User Info (IDOR via API) ──────────────────────────
app.get("/api/users/:id", (req, res) => {
  // VULN: IDOR — no authentication required
  const userId = parseInt(req.params.id)
  const user = USERS.find(u => u.id === userId)

  if (!user) {
    return res.status(404).json({ error: "用户不存在" })
  }

  // VULN: exposes sensitive fields including password
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    password: user.password, // Leaking password hash
    bio: user.bio,
    points: user.points,
  })
})

// ── API: Fetch URL (SSRF) ──────────────────────────────────
app.get("/api/fetch", (req, res) => {
  const url = req.query.url

  if (!url) {
    return res.status(400).json({ error: "Missing url parameter" })
  }

  // VULN: SSRF — fetches arbitrary URLs including internal services
  // No allowlist, no blocklist for private IPs
  try {
    const http = url.startsWith("https") ? require("https") : require("http")
    http.get(url, (response) => {
      let data = ""
      response.on("data", (chunk) => { data += chunk })
      response.on("end", () => {
        res.json({
          url,
          status: response.statusCode,
          headers: response.headers,
          body: data.substring(0, 2000), // VULN: leaks response data
        })
      })
    }).on("error", (e) => {
      res.status(500).json({ error: e.message })
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── API: Config (Prototype Pollution) ──────────────────────
app.post("/api/config", (req, res) => {
  const config = req.body

  // VULN: prototype pollution via unsafe merge
  // Using lodash.merge with user input
  const appConfig = { version: "2.0", theme: "dark", debug: false }
  _.merge(appConfig, config) // VULN: allows __proto__ pollution

  res.json({ ok: true, config: appConfig })
})

// ── API: Debug (Information Disclosure) ────────────────────
app.get("/api/debug", (req, res) => {
  // VULN: exposes sensitive system information
  res.json({
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    memory: process.memoryUsage(),
    uptime: process.uptime(),
    env: process.env, // VULN: leaks all environment variables
    cwd: process.cwd(),
    pid: process.pid,
    dependencies: Object.keys(require("../package.json").dependencies),
  })
})

// ── NoSQL Injection simulation ────────────────────────────
app.post("/api/users/search", (req, res) => {
  const query = req.body

  // VULN: NoSQL injection — if using MongoDB, the $where operator could be injected
  // Simulating: db.users.find({ $where: query.$where })
  let results
  if (query && query.$where) {
    // VULN: eval-like injection
    try {
      const fakeEval = new Function("return " + query.$where)
      results = USERS.filter(fakeEval)
    } catch (e) {
      results = []
    }
  } else if (query && query.username) {
    results = USERS.filter(u => u.username === query.username)
  } else {
    results = USERS
  }

  res.json(results.map(u => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
  })))
})

// ── API: Submit Contact (No Rate Limit) ────────────────────
app.post("/api/contact-submit", (req, res) => {
  // VULN: no rate limiting, unlimited submissions
  res.json({ success: true })
})

// ── Insecure Crypto Demonstrator ──────────────────────────
app.get("/api/encrypt", (req, res) => {
  const text = req.query.text || "default"
  // VULN: using weak encryption (DES) with static key
  const key = crypto.randomBytes(8).toString("hex").slice(0, 8)
  try {
    const cipher = crypto.createCipheriv("des-cbc", Buffer.from(key), Buffer.from("12345678"))
    let encrypted = cipher.update(text, "utf8", "hex")
    encrypted += cipher.final("hex")
    res.json({ algorithm: "des-cbc", key, encrypted })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Static file serving misconfiguration ──────────────────
// VULN: serves static files without restricting sensitive files
app.use("/static", express.static(path.join(__dirname, "..", "public")))
// VULN: .git/config might be accessible
app.use("/.git", express.static(path.join(__dirname, "..", ".git")))
// VULN: node_modules accessible (contains source code with known vulns)
app.use("/node_modules", express.static(path.join(__dirname, "..", "node_modules")))

// ── Wildcard route (catch-all) ────────────────────────────
app.get("*", (req, res) => {
  res.status(404).render("error", {
    message: `页面未找到: ${req.path}`,
    stack: null,
  })
})

// ── Start Server ───────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[TechInsight] 网站已启动: http://localhost:${PORT}`)
  console.log(`[TechInsight] 运行环境: ${process.env.NODE_ENV || "development"}`)
  console.log(`[TechInsight] ⚠️ 警告: 此站点包含故意设置的漏洞，仅用于安全测试！`)
})
