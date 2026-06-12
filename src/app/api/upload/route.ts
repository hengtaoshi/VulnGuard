import { NextRequest, NextResponse } from "next/server"
import { writeFileSync, mkdirSync, existsSync, rmSync } from "fs"
import { join, resolve, normalize } from "path"
import { requireAuth } from "@/lib/api/auth"

const UPLOAD_DIR = resolve(join(process.cwd(), "data", "uploads"))

// Limits
const MAX_FILE_SIZE = 20 * 1024 * 1024 // 20 MB per file
const MAX_TOTAL_FILES = 5000

// Non-source file extensions — silently skipped during upload, not an error
const NON_SOURCE_EXTS = new Set([
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".webp", ".svg",
  ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
  ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o", ".a", ".lib",
  ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
  ".ttf", ".otf", ".woff", ".woff2", ".eot",
])

export async function POST(request: NextRequest) {
  const auth = requireAuth(request)
  if (auth) return auth

  try {
    const formData = await request.formData()
    const id = `upload-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    const targetDir = resolve(join(UPLOAD_DIR, id))

    // Collect all files and save them
    let fileCount = 0
    let totalBytes = 0
    const entries = Array.from(formData.entries())
    for (const [relativePath, value] of entries) {
      if (value instanceof File) {
        // Skip the metadata field
        if (relativePath === "__meta__") continue

        // SECURITY: reject any path containing ".."
        const normalized = relativePath.replace(/\\/g, "/")
        if (normalized.includes("..")) {
          return NextResponse.json({ error: `非法路径: ${relativePath}` }, { status: 400 })
        }

        // Silently skip non-source files (PDF, images, binaries, etc.)
        const ext = normalized.slice(normalized.lastIndexOf(".")).toLowerCase()
        if (NON_SOURCE_EXTS.has(ext)) continue

        // LIMIT: per-file size cap
        if (value.size > MAX_FILE_SIZE) {
          return NextResponse.json({ error: `文件过大(超过 ${MAX_FILE_SIZE / 1024 / 1024}MB): ${normalized}` }, { status: 400 })
        }

        const fullPath = resolve(join(targetDir, normalized))

        // SECURITY: verify the resolved path is still inside the target directory
        if (!fullPath.startsWith(targetDir + "\\") && !fullPath.startsWith(targetDir + "/")) {
          return NextResponse.json({ error: "路径越界" }, { status: 400 })
        }

        const dir = fullPath.slice(0, fullPath.lastIndexOf("\\"))

        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true })
        }

        const buffer = Buffer.from(await value.arrayBuffer())
        writeFileSync(fullPath, buffer)
        fileCount++
        totalBytes += buffer.length
      }
    }

    // LIMIT: total file count cap
    if (fileCount > MAX_TOTAL_FILES) {
      // Clean up uploaded files before returning error
      rmSync(targetDir, { recursive: true, force: true })
      return NextResponse.json({ error: `文件数量超过上限(${MAX_TOTAL_FILES})` }, { status: 400 })
    }

    if (fileCount === 0) {
      return NextResponse.json({ error: "没有收到文件" }, { status: 400 })
    }

    // Return relative display path to avoid leaking server absolute paths
    const displayPath = `uploads/${id}/`

    return NextResponse.json({
      id,
      path: targetDir,
      displayPath,
      fileCount,
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return NextResponse.json({ error: msg }, { status: 500 })
  }
}
