/**
 * Server-Sent Events 实时推送扫描进度
 * GET /api/scan-progress/[id]
 *
 * 替代前端 1s 轮询，服务端在有新进度时主动推送。
 * 兼容方案：如果 SSE 不可用，前端回退到轮询。
 */

import { NextRequest } from "next/server"
import { getSession } from "@/lib/scanner/scan-store"

export async function GET(
  _request: NextRequest,
  { params }: { params: { id: string } },
) {
  const id = params.id
  if (!id) {
    return new Response("Missing scan ID", { status: 400 })
  }

  const encoder = new TextEncoder()
  let lastProgress: string | null = null
  let closed = false

  const stream = new ReadableStream({
    start(controller) {
      // 立即发送初始状态
      const session = getSession(id)
      if (!session) {
        controller.enqueue(encoder.encode(`event: error\ndata: Scan not found\n\n`))
        controller.close()
        return
      }
      controller.enqueue(encoder.encode(`data: ${JSON.stringify(session)}\n\n`))
      lastProgress = JSON.stringify(session.progress || {})

      // 轮询 scan-store 获取更新
      const timer = setInterval(() => {
        if (closed) {
          clearInterval(timer)
          return
        }

        const s = getSession(id)
        if (!s) {
          controller.enqueue(encoder.encode(`event: error\ndata: Scan deleted\n\n`))
          clearInterval(timer)
          controller.close()
          return
        }

        const currentProgress = JSON.stringify(s.progress || {})
        if (currentProgress !== lastProgress) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(s)}\n\n`))
          lastProgress = currentProgress
        }

        // 扫描完成时关闭
        if (s.status === "completed" || s.status === "failed") {
          controller.enqueue(encoder.encode(`event: done\ndata: ${JSON.stringify(s)}\n\n`))
          clearInterval(timer)
          controller.close()
        }
      }, 500)

      // 客户端断开
      _request.signal.onabort = () => {
        closed = true
        clearInterval(timer)
      }
    },
  })

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  })
}
