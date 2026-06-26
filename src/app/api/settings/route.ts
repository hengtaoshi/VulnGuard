import { NextResponse } from "next/server"
import { getSettings, updateSettings } from "@/lib/settings-store"
import { requireAuth } from "@/lib/api/auth"

export async function GET(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  await new Promise(r => setTimeout(r, 100))
  return NextResponse.json(getSettings())
}

export async function PUT(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  try {
    const body = await request.json()
    const updated = updateSettings(body)
    await new Promise(r => setTimeout(r, 100))
    return NextResponse.json(updated)
  } catch (e) {
    return NextResponse.json(
      { error: "无效的设置数据" },
      { status: 400 },
    )
  }
}
