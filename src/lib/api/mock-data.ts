import { type Vulnerability } from "./types"

export const mockVulnerabilities: Vulnerability[] = [
  {
    id: "VULN-001",
    name: "SQL Injection in User Login",
    severity: "Critical",
    location: "src/api/auth/login.ts:42",
    cve: "CVE-2024-21626",
    description:
      "User input from the 'username' field is directly concatenated into SQL query strings without parameterization, allowing an attacker to execute arbitrary SQL commands.",
    recommendation:
      "Use parameterized queries (prepared statements) instead of string concatenation. For PostgreSQL with Node.js, use the $1 placeholder syntax.",
    code: `// ❌ Vulnerable
const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;

// ✅ Fixed
const query = 'SELECT * FROM users WHERE username = $1 AND password = $2';
const result = await pool.query(query, [username, password]);`,
  },
  {
    id: "VULN-002",
    name: "Cross-Site Scripting (XSS)",
    severity: "Critical",
    location: "src/components/Comment.tsx:28",
    cve: "CVE-2024-21887",
    description:
      "User comment content is rendered using dangerouslySetInnerHTML without sanitization, allowing stored XSS attacks.",
    recommendation:
      "Use DOMPurify to sanitize HTML content before rendering, or use a safe rendering library that escapes HTML by default.",
    code: `// ❌ Vulnerable
<div dangerouslySetInnerHTML={{ __html: comment.content }} />

// ✅ Fixed
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.content) }} />`,
  },
  {
    id: "VULN-003",
    name: "Hardcoded API Key",
    severity: "High",
    location: "src/config/constants.ts:15",
    cve: "—",
    description:
      "A Stripe secret API key is hardcoded directly in the source code, exposing sensitive credentials to anyone with access to the codebase.",
    recommendation:
      "Move secrets to environment variables. Use .env files locally and a secrets manager in production.",
    code: `// ❌ Vulnerable
const STRIPE_SECRET = 'sk_live_xxxxxxxxxxxxxxxxxxxxx';

// ✅ Fixed
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;`,
  },
  {
    id: "VULN-004",
    name: "Missing CSRF Protection",
    severity: "High",
    location: "src/api/payments/checkout.ts:1-50",
    cve: "—",
    description:
      "The payment checkout endpoint lacks CSRF token validation, allowing attackers to forge requests on behalf of authenticated users.",
    recommendation:
      "Implement CSRF tokens using a library like csurf or include anti-CSRF tokens in your framework's built-in protection.",
  },
  {
    id: "VULN-005",
    name: "Insecure Cookie Configuration",
    severity: "Medium",
    location: "src/middleware.ts:22",
    cve: "—",
    description:
      "Session cookies are missing the Secure, HttpOnly, and SameSite flags, making them susceptible to theft via XSS or man-in-the-middle attacks.",
    recommendation: "Set cookie flags: Secure=true, HttpOnly=true, SameSite='Lax' or 'Strict'.",
    code: `// ❌ Vulnerable
res.cookie('session', token, { maxAge: 86400000 });

// ✅ Fixed
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 86400000,
});`,
  },
  {
    id: "VULN-006",
    name: "Outdated Dependency: lodash",
    severity: "Medium",
    location: "package.json:23",
    cve: "CVE-2024-25680",
    description:
      "lodash@4.17.20 has a known prototype pollution vulnerability. Current version is 3 major versions behind.",
    recommendation: "Update lodash to the latest version: npm install lodash@latest",
  },
]

export const mockScans = [
  { id: "1", target: "my-ai-app.com", type: "url" as const, status: "completed" as const, risk: "Critical", date: "2026-06-05 14:23" },
  { id: "2", target: "ecommerce-test.zip", type: "source" as const, status: "scanning" as const, risk: "—", date: "2026-06-05 14:08" },
  { id: "3", target: "blog-platform.vercel.app", type: "url" as const, status: "completed" as const, risk: "Secure", date: "2026-06-05 12:00" },
  { id: "4", target: "dashboard-app.zip", type: "source" as const, status: "completed" as const, risk: "High", date: "2026-06-05 09:15" },
  { id: "5", target: "api-gateway.test.com", type: "url" as const, status: "completed" as const, risk: "Medium", date: "2026-06-04 22:30" },
]
