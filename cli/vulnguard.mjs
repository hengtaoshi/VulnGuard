#!/usr/bin/env node

const args = process.argv.slice(2)
const hostIdx = args.indexOf("--host")
const HOST = hostIdx >= 0 ? args[hostIdx + 1] : (process.env.VULNGUARD_HOST || "http://localhost:3000")
const cmd = args[0]

async function api(path, opts = {}) {
  const url = `${HOST}${path}`
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...opts.headers },
    ...opts,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => "")
    throw new Error(`${res.status}: ${text.slice(0, 200)}`)
  }
  return res.json()
}

async function cmdScan() {
  const target = process.argv[3]
  if (!target) {
    console.error("Usage: node cli/vulnguard.mjs scan <target> [--engine ai|all] [--output file] [--threshold k=v] [--format sarif]")
    process.exit(1)
  }

  const args = process.argv.slice(4)
  const engine = (args.includes("--engine") ? args[args.indexOf("--engine") + 1] : "ai") || "ai"
  const incremental = args.includes("--incremental")

  console.error(`[vulnguard] Scanning ${target} (engine: ${engine}${incremental ? ", incremental" : ""})...`)

  const session = await api("/api/scans", {
    method: "POST",
    body: JSON.stringify({ target, type: "source", engine, incremental }),
  })
  console.error(`[vulnguard] Scan session: ${session.id}`)

  await api(`/api/scans/${session.id}/start`, { method: "POST" })
  console.error(`[vulnguard] Scan started, waiting...`)

  let result
  for (;;) {
    await new Promise(r => setTimeout(r, 2000))
    result = await api(`/api/scans/${session.id}`)
    if (result.status === "completed") {
      console.error(`[vulnguard] Complete: ${result.vulnerabilities?.length ?? 0} findings`)
      break
    }
    if (result.status === "failed") {
      console.error(`[vulnguard] Scan failed`)
      process.exit(1)
    }
    console.error(`[vulnguard] ${result.progress?.percent ?? 0}%`)
  }

  const formatIdx = args.indexOf("--format")
  if (formatIdx >= 0 && args[formatIdx + 1] === "sarif") {
    const res = await api(`/api/scans/${session.id}`)
    const { convertToSarif, getSarifFilename } = await import("../src/lib/sarif-converter.js")
    console.log(convertToSarif(res))
    return
  }

  const outputIdx = args.indexOf("--output")
  if (outputIdx >= 0) {
    const fs = await import("fs")
    const outFile = args[outputIdx + 1]
    fs.writeFileSync(outFile, JSON.stringify({
      scanId: session.id,
      target,
      summary: result.summary,
      vulnerabilities: result.vulnerabilities,
    }, null, 2))
    console.error(`[vulnguard] Written to ${outFile}`)
  }

  const thresholdIdx = args.indexOf("--threshold")
  if (thresholdIdx >= 0) {
    const raw = args[thresholdIdx + 1]
    if (raw) {
      const thresholds = Object.fromEntries(raw.split(",").map(p => {
        const [k, v] = p.split("=")
        return [k.toLowerCase(), parseInt(v, 10)]
      }))
      const summary = result.summary || {}
      let failed = false
      for (const [sev, limit] of Object.entries(thresholds)) {
        const actual = summary[sev] || 0
        if (actual > limit) {
          console.error(`[vulnguard] THRESHOLD FAILED: ${sev} ${actual} > ${limit}`)
          failed = true
        }
      }
      if (failed) process.exit(1)
    }
  }

  if (formatIdx < 0 && outputIdx < 0) {
    console.log(JSON.stringify({
      scanId: session.id, target,
      summary: result.summary,
      vulnerabilities: result.vulnerabilities,
    }, null, 2))
  }
}

// ponytail: only "scan" subcommand; "baseline" and others when needed
async function main() {
  if (!cmd || cmd === "--help" || cmd === "-h") {
    console.log(`
VulnGuard CLI

Usage:
  node cli/vulnguard.mjs scan <target> [options]

Options:
  --host <url>        API server URL (default: http://localhost:3000)
  --engine ai|all     Scanner engine (default: ai)
  --incremental       仅扫描 git 变更文件
  --output <file>     Save results as JSON
  --threshold k=v     Exit non-zero if exceeded (e.g. critical=0,high=5)
  --format sarif      Output SARIF format

Env: VULNGUARD_HOST
`)
    return
  }
  if (cmd === "scan") return cmdScan()
  console.error(`Unknown: ${cmd}`)
  process.exit(1)
}

main().catch(err => {
  console.error(`[vulnguard] Error: ${err.message}`)
  process.exit(1)
})
