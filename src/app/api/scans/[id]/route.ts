import { NextResponse } from "next/server"
import { getSession, toScanDetail } from "@/lib/scanner/scan-store"

export async function GET(_request: Request, { params }: { params: { id: string } }) {
  await new Promise(r => setTimeout(r, 200))

  const session = getSession(params.id)
  if (!session) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  return NextResponse.json(toScanDetail(session))
}
