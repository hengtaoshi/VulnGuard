import { NextResponse } from "next/server"
import { getAllScanners } from "@/lib/scanner/registry"
import { SCANNER_MANIFEST } from "@/lib/scanner/manifest"
import { requireAuth } from "@/lib/api/auth"

const manifestMap = new Map(SCANNER_MANIFEST.map(m => [m.name, m]))

// Cache scanner availability to avoid blocking the event loop with execSync
let cachedScanners: ReturnType<typeof buildScannerList> | null = null
let cacheTime = 0
const CACHE_TTL = 30_000 // 30 seconds

function buildScannerList() {
  return getAllScanners().map(s => {
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
}

export async function GET(request: Request) {
  const auth = requireAuth(request)
  if (auth) return auth

  const now = Date.now()
  if (!cachedScanners || now - cacheTime > CACHE_TTL) {
    cachedScanners = buildScannerList()
    cacheTime = now
  }

  return NextResponse.json(cachedScanners)
}
