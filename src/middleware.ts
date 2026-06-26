/**
 * Next.js Middleware — sets SCAN_AUTH_TOKEN as an HttpOnly cookie on every page load.
 *
 * This eliminates the need for NEXT_PUBLIC_SCAN_AUTH_TOKEN (which gets inlined
 * into client JS bundles). The browser automatically sends the cookie with
 * every same-origin request, including API calls and EventSource (SSE).
 */
import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

export function middleware(request: NextRequest) {
  const token = process.env.SCAN_AUTH_TOKEN
  if (!token) return NextResponse.next()

  const response = NextResponse.next()

  // Check if the auth cookie is already present and correct
  const existing = request.cookies.get("scan_auth_token")
  if (existing?.value !== token) {
    response.cookies.set("scan_auth_token", token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24, // 24 hours
      secure: process.env.NODE_ENV === "production",
    })
  }

  return response
}

export const config = {
  matcher: [
    // 排除上传接口 — 避免 Next.js 15 缓冲请求体导致 10MB 限制
    "/((?!api/upload).*)",
  ],
}
