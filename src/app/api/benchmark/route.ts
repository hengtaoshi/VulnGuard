import { NextResponse } from "next/server"
import { getDefaultBenchmarkData } from "@/lib/benchmark/cwe-data"
import { existsSync, readFileSync } from "fs"
import { join } from "path"

/**
 * OWASP Benchmark 跑分数据。
 *
 * 如果 .benchmark-results.json 存在（由 CLI 脚本 node scripts/run-owasp-benchmark.js 生成），
 * 则返回该文件中的分数；否则返回 CWE 覆盖数据（分数为空）。
 */

function loadCachedResults() {
  const cacheFile = join(process.cwd(), ".benchmark-results.json")
  if (!existsSync(cacheFile)) return null
  try {
    const raw = readFileSync(cacheFile, "utf-8")
    return JSON.parse(raw)
  } catch {
    return null
  }
}

export async function GET() {
  const data = getDefaultBenchmarkData()
  const cached = loadCachedResults()
  if (cached?.owaspScores) {
    data.owaspScores = cached.owaspScores
    data.lastUpdated = cached.lastUpdated || ""
  }
  return NextResponse.json(data)
}

export async function POST() {
  // ponytail: 跑分需要下载 ~100MB 测试文件，耗时较长，当前通过外部 CLI 完成。
  // CLI: node scripts/run-owasp-benchmark.js /path/to/owasp-benchmark
  return NextResponse.json({
    ok: false,
    message: "请通过 CLI 运行基准测试：node scripts/run-owasp-benchmark.js /path/to/owasp-benchmark",
  })
}
