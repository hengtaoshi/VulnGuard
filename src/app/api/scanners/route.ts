import { NextResponse } from "next/server"
import { getAllScanners } from "@/lib/scanner/registry"
import { SCANNER_MANIFEST } from "@/lib/scanner/manifest"
import { requireAuth } from "@/lib/api/auth"

const manifestMap = new Map(SCANNER_MANIFEST.map(m => [m.name, m]))

export async function GET(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  const scanners = getAllScanners().map(s => {
    const m = manifestMap.get(s.name)
    return {
      name: s.name,
      displayName: s.displayName,
      category: s.category,
      available: s.isAvailable(),
      description: m?.description || "",
      scanTypes: m?.scanTypes || [],
      typicalDuration: m?.typicalDuration || "medium",
      priority: m?.priority || 5,
    }
  })

  return NextResponse.json(scanners)
}
