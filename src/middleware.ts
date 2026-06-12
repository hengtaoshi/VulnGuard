/**
 * Next.js Middleware — sets SCAN_AUTH_TOKEN as an HttpOnly cookie for API routes.
 *
 * This eliminates the need for NEXT_PUBLIC_SCAN_AUTH_TOKEN (which gets inlined
 * into client JS bundles). The client simply relies on the browser sending the
 * cookie with every same-origin API request.
 */
import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"

export function middleware(request: NextRequest) {
  const token = process.env.SCAN_AUTH_TOKEN
  if (!token) return NextResponse.next()

  // Only set the cookie on API responses to minimize scope
  const response = NextResponse.next()

  // Check if the auth cookie is already present and correct
  const existing = request.cookies.get("scan_auth_token")
  if (existing?.value !== token) {
    response.cookies.set("scan_auth_token", token, {
      httpOnly: true,
      sameSite: "lax",
      path: "/api",
      maxAge: 60 * 60 * 24, // 24 hours
      secure: process.env.NODE_ENV === "production",
    })
  }

  return response
}

export const config = {
  matcher: "/api/:path*",
}
