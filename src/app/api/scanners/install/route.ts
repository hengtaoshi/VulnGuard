/**
 * VulnGuard Scanner Install API
 *
 * POST /api/scanners/install
 *   Body: { scanner: "gitleaks" }
 *   Returns: SSE stream with progress updates
 *
 * For Electron mode, use IPC (window.vulnguard.downloadScanner).
 * This API is for web-only mode (npm run dev).
 */

import { NextRequest } from "next/server"

// Dynamic import of scanner downloader (CommonJS module from electron/)
async function getDownloader() {
  const mod = await import("../../../../../electron/scanner-downloader.js")
  return mod
}

export async function POST(request: NextRequest) {
  try {
    const { scanner } = await request.json()
    if (!scanner) {
      return new Response(JSON.stringify({ error: "Missing scanner name" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      })
    }

    const { installScanner } = await getDownloader()
    const toolsDir = process.cwd() + "/tools"

    // Create SSE stream
    const encoder = new TextEncoder()
    const stream = new ReadableStream({
      async start(controller) {
        const sendEvent = (data: Record<string, unknown>) => {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`))
        }

        // 忽略 sendEvent 的参数，使用 any
        const result = await (installScanner as Function)(scanner, toolsDir, sendEvent)

        if (result?.ok) {
          sendEvent({ done: true, ok: true, skipped: !!result.skipped })
        } else {
          sendEvent({ done: true, ok: false, error: result?.error || "安装失败" })
        }
        controller.close()
      },
    })

    return new Response(stream, {
      headers: {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      },
    })
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message || "Internal error" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    })
  }
}
