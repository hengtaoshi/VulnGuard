/**
 * Lightweight API authentication for VulnGuard.
 *
 * Authentication sources (checked in order):
 * 1. `Authorization: Bearer <token>` header (from server-side calls or scripts)
 * 2. `scan_auth_token` cookie (set by middleware.ts for client-side requests)
 *
 * When SCAN_AUTH_TOKEN is NOT set (development mode), all requests pass through
 * with a one-time warning on first use.
 */

let warned = false

function getTokenFromRequest(request: Request): string | null {
  // 1. Check Authorization header
  const auth = request.headers.get("authorization") || request.headers.get("Authorization") || ""
  const match = auth.match(/^Bearer\s+(.+)$/i)
  if (match?.[1]) return match[1]

  // 2. Check scan_auth_token cookie (set by middleware.ts)
  const cookieHeader = request.headers.get("cookie") || ""
  for (const c of cookieHeader.split(";")) {
    const [name, ...rest] = c.trim().split("=")
    if (name === "scan_auth_token") return rest.join("=")
  }

  return null
}

export function requireAuth(request: Request): Response | null {
  const expected = process.env.SCAN_AUTH_TOKEN

  if (!expected) {
    if (!warned) {
      console.warn(
        "[auth] SCAN_AUTH_TOKEN not set — API endpoints are unprotected. " +
        "Set SCAN_AUTH_TOKEN in .env.local to enable authentication.",
      )
      warned = true
    }
    return null // allow
  }

  const actual = getTokenFromRequest(request)

  if (actual !== expected) {
    return new Response(JSON.stringify({ error: "未授权，请提供有效的 SCAN_AUTH_TOKEN" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    })
  }

  return null // allow
}
