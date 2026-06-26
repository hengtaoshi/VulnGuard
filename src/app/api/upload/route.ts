import { NextRequest, NextResponse } from "next/server"
import { writeFileSync, mkdirSync, existsSync, rmSync } from "fs"
import { join, resolve } from "path"
import { requireAuth } from "@/lib/api/auth"

export const maxDuration = 300

const UPLOAD_DIR = resolve(join(process.cwd(), "data", "uploads"))
const MAX_FILE_SIZE = 20 * 1024 * 1024
const MAX_TOTAL_FILES = 5000

export async function POST(request: NextRequest) {
  const auth = requireAuth(request)
  if (auth) return auth

  try {
    const formData = await request.formData()
    const id = `upload-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    const targetDir = resolve(join(UPLOAD_DIR, id))

    let fileCount = 0
    let totalBytes = 0
    const entries = Array.from(formData.entries())
    for (const [relativePath, value] of entries) {
      if (value instanceof File) {
        if (relativePath === "__meta__") continue

        const normalized = relativePath.replace(/\\/g, "/")
        if (normalized.includes("..")) {
          return NextResponse.json({ error: `非法路径: ${relativePath}` }, { status: 400 })
        }

        if (value.size > MAX_FILE_SIZE) {
          return NextResponse.json({ error: `文件过大(超过 ${MAX_FILE_SIZE / 1024 / 1024}MB): ${normalized}` }, { status: 400 })
        }

        const fullPath = resolve(join(targetDir, normalized))
        if (!fullPath.startsWith(targetDir + "\\") && !fullPath.startsWith(targetDir + "/")) {
          return NextResponse.json({ error: "路径越界" }, { status: 400 })
        }

        const dir = fullPath.slice(0, fullPath.lastIndexOf("\\"))
        if (!existsSync(dir)) mkdirSync(dir, { recursive: true })

        const buffer = Buffer.from(await value.arrayBuffer())
        writeFileSync(fullPath, buffer)
        fileCount++
        totalBytes += buffer.length
      }
    }

    if (fileCount > MAX_TOTAL_FILES) {
      rmSync(targetDir, { recursive: true, force: true })
      return NextResponse.json({ error: `文件数量超过上限(${MAX_TOTAL_FILES})` }, { status: 400 })
    }

    if (fileCount === 0) {
      return NextResponse.json({ error: "没有收到文件" }, { status: 400 })
    }

    return NextResponse.json({
      id,
      path: targetDir,
      displayPath: `uploads/${id}/`,
      fileCount,
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return NextResponse.json({ error: msg }, { status: 500 })
  }
}
