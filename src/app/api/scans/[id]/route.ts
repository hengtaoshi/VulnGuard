import { NextResponse } from "next/server"
import { getSession, toScanDetail, deleteSession, cleanupUploadDir } from "@/lib/scanner/scan-store"
import { requireAuth } from "@/lib/api/auth"

export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const auth = requireAuth(request)
  if (auth) return auth

  await new Promise(r => setTimeout(r, 200))

  const session = getSession(id)
  if (!session) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  return NextResponse.json(toScanDetail(session))
}

export async function DELETE(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const auth = requireAuth(request)
  if (auth) return auth

  const session = getSession(id)
  if (!session) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  // 删除上传目录（如果有）
  cleanupUploadDir(session.target)

  deleteSession(id)
  return NextResponse.json({ success: true })
}
