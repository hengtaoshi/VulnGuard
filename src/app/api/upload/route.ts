import { NextRequest, NextResponse } from "next/server"
import { writeFileSync, mkdirSync, existsSync } from "fs"
import { join } from "path"

const UPLOAD_DIR = join(process.cwd(), "data", "uploads")

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    const id = `upload-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    const targetDir = join(UPLOAD_DIR, id)

    // Collect all files and save them
    let fileCount = 0
    const entries = Array.from(formData.entries())
    for (const [relativePath, value] of entries) {
      if (value instanceof File) {
        // Skip the metadata field
        if (relativePath === "__meta__") continue

        const safePath = relativePath.replace(/\.\./g, "_").replace(/[/]/g, "\\")
        const fullPath = join(targetDir, safePath)
        const dir = fullPath.slice(0, fullPath.lastIndexOf("\\"))

        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true })
        }

        const buffer = Buffer.from(await value.arrayBuffer())
        writeFileSync(fullPath, buffer)
        fileCount++
      }
    }

    if (fileCount === 0) {
      return NextResponse.json({ error: "没有收到文件" }, { status: 400 })
    }

    return NextResponse.json({
      id,
      path: targetDir,
      fileCount,
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return NextResponse.json({ error: msg }, { status: 500 })
  }
}
