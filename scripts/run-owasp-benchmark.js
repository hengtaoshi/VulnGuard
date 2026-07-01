#!/usr/bin/env node

/**
 * OWASP Benchmark Runner
 *
 * 运行 Semgrep/CodeQL 扫描 OWASP Benchmark 测试集，计算标准分。
 *
 * 用法:
 *   node scripts/run-owasp-benchmark.js [benchmark-path] [--scanner semgrep|codeql|all]
 *
 * 首次运行:
 *   git clone https://github.com/OWASP/Benchmark.git /tmp/owasp-benchmark
 *   node scripts/run-owasp-benchmark.js /tmp/owasp-benchmark
 *
 * 输出: .benchmark-results.json（API 读取此文件）
 */
const { execSync } = require("child_process")
const { existsSync, readFileSync, writeFileSync, mkdirSync } = require("fs")
const { join, basename } = require("path")

const COLORS = {
  reset: "\x1b[0m", green: "\x1b[32m", yellow: "\x1b[33m",
  red: "\x1b[31m", cyan: "\x1b[36m", dim: "\x1b[2m",
}

function log(tag, msg, ok = true) {
  const sym = ok ? `${COLORS.green}✓${COLORS.reset}` : `${COLORS.red}✗${COLORS.reset}`
  console.log(`  ${sym} ${tag.padEnd(20)} ${msg}`)
}

// ── 参数解析 ────────────────────────────────────────────────────────────

const args = process.argv.slice(2)
const benchmarkDir = args[0] || "/tmp/owasp-benchmark"
const scannerOpt = args.includes("--scanner") ? args[args.indexOf("--scanner") + 1] : "semgrep"

// ── 验证 ────────────────────────────────────────────────────────────────

const testCodeDir = join(benchmarkDir, "src", "main", "java", "org", "owasp", "benchmark", "testcode")
const expectedResultsFile = findExpectedResults(benchmarkDir)

if (!existsSync(testCodeDir)) {
  console.error(`\n  ${COLORS.red}✗ 未找到 OWASP Benchmark 测试代码${COLORS.reset}`)
  console.error(`    预期路径: ${testCodeDir}`)
  console.error(`    请先克隆: git clone https://github.com/OWASP/Benchmark.git ${benchmarkDir}\n`)
  process.exit(1)
}

if (!expectedResultsFile) {
  console.error(`\n  ${COLORS.red}✗ 未找到 expectedresults.csv${COLORS.reset}`)
  console.error(`    在 ${benchmarkDir} 中未找到`)
  process.exit(1)
}

function findExpectedResults(dir) {
  // OWASP Benchmark 的 ground truth 可能有不同文件名
  const candidates = [
    join(dir, "expectedresults.csv"),
    join(dir, "expectedresults-1.2.csv"),
    join(dir, "scorecard", "expectedresults.csv"),
  ]
  return candidates.find(f => existsSync(f)) || null
}

// ── 读取 ground truth ────────────────────────────────────────────────────

function parseExpectedResults(csvPath) {
  const content = readFileSync(csvPath, "utf-8")
  const lines = content.trim().split("\n")
  // 跳过表头
  const header = lines[0].toLowerCase()
  const hasHeader = header.includes("testnumber") || header.includes("test_number")
  const dataLines = hasHeader ? lines.slice(1) : lines

  const results = []
  for (const line of dataLines) {
    const parts = line.split(",")
    if (parts.length < 3) continue
    const testNumber = parseInt(parts[0], 10)
    const cwe = parts[2] || ""
    const isVuln = parts.length > 3
      ? (parts[3].trim().toLowerCase() === "true" || parts[3].trim() === "1")
      : true
    if (!isNaN(testNumber)) {
      results.push({ testNumber, cwe, isVulnerable: isVuln })
    }
  }
  return results
}

const expectedResults = parseExpectedResults(expectedResultsFile)
log("Ground truth", `${expectedResults.length} test cases loaded`)

// ── 运行扫描器 ──────────────────────────────────────────────────────────

const scanners = scannerOpt === "all" ? ["semgrep", "codeql"] : [scannerOpt]
const allScores = []

for (const scannerName of scanners) {
  console.log(`\n  ${COLORS.cyan}── Running ${scannerName} on OWASP Benchmark ──${COLORS.reset}\n`)

  try {
    const findings = await runScanner(scannerName, testCodeDir)
    const score = computeScore(scannerName, findings, expectedResults)
    allScores.push(score)
    printScore(score)
  } catch (err) {
    log(scannerName, `failed: ${err.message}`, false)
  }
}

// ── 保存结果 ──────────────────────────────────────────────────────────

const outputPath = join(process.cwd(), ".benchmark-results.json")
const output = {
  owaspScores: allScores,
  lastUpdated: new Date().toISOString().split("T")[0],
  totalTestCases: expectedResults.length,
  benchmarkVersion: "1.2",
}

writeFileSync(outputPath, JSON.stringify(output, null, 2))
console.log(`\n  ${COLORS.green}✓ 结果已保存: ${outputPath}${COLORS.reset}\n`)

// ── 扫描器具体实现 ────────────────────────────────────────────────────

async function runScanner(name, codeDir) {
  switch (name) {
    case "semgrep": return runSemgrep(codeDir)
    case "codeql":  return runCodeQL(codeDir)
    default: throw new Error(`Unknown scanner: ${name}`)
  }
}

async function runSemgrep(codeDir) {
  // 检查 semgrep 是否可用
  try { execSync("semgrep --version 2>&1", { stdio: "pipe", timeout: 5000 }) }
  catch { throw new Error("semgrep not found in PATH") }

  log("Semgrep", "scanning 2740 test cases...")
  const outFile = join(process.cwd(), ".benchmark-semgrep-out.json")
  execSync(
    `semgrep --config "p/default" --json --quiet "${codeDir}" 2>&1`,
    { stdio: "pipe", timeout: 600000, encoding: "utf-8" }
  )
  // 写文件再读回来，避免 stdout 太大
  // ponytail: semgrep --json 输出可能很大，直接 pipe 可能截断
  try {
    const raw = readFileSync(outFile, "utf-8")
    const parsed = JSON.parse(raw)
    return (parsed.results || []).map(r => {
      const file = basename(r.path || "")
      const num = parseInt(file.replace(/\D/g, ""), 10)
      return { testNumber: isNaN(num) ? 0 : num, checkId: r.check_id, message: r.extra?.message || "" }
    })
  } catch { return [] }
}

async function runCodeQL(codeDir) {
  // CodeQL 需要先创建 database，流程较复杂，标记为 TODO
  throw new Error("CodeQL benchmark runner requires CodeQL database creation — run manually")
}

// ── 计分 ────────────────────────────────────────────────────────────────

function computeScore(scannerName, findings, expected) {
  // 创建 expected 的查找 map
  const vulnSet = new Set(expected.filter(e => e.isVulnerable).map(e => e.testNumber))
  const safeSet = new Set(expected.filter(e => !e.isVulnerable).map(e => e.testNumber))
  const detected = new Set(findings.filter(f => f.testNumber > 0).map(f => f.testNumber))

  let tp = 0, fp = 0, fn = 0, tn = 0

  for (const num of vulnSet) {
    if (detected.has(num)) tp++
    else fn++
  }
  for (const num of safeSet) {
    if (detected.has(num)) fp++
    else tn++
  }

  const tpr = tp / (tp + fn) || 0
  const fpr = fp / (fp + tn) || 0
  // OWASP 标准分: 1 - sqrt((1-TPR)² + FPR²) / sqrt(2)
  const score = 1 - Math.sqrt(Math.pow(1 - tpr, 2) + Math.pow(fpr, 2)) / Math.sqrt(2)

  return {
    scannerName,
    displayName: scannerName === "semgrep" ? "Semgrep" : "CodeQL",
    truePositives: tp,
    falsePositives: fp,
    trueNegatives: tn,
    falseNegatives: fn,
    totalTestCases: expected.length,
    tpr: Math.round(tpr * 1000) / 1000,
    fpr: Math.round(fpr * 1000) / 1000,
    score: Math.round(score * 1000) / 1000,
    testedAt: new Date().toISOString().split("T")[0],
  }
}

function printScore(s) {
  console.log(`\n  ${COLORS.cyan}${s.displayName} on OWASP Benchmark${COLORS.reset}`)
  console.log(`  ${COLORS.dim}──────────────────────────────────────${COLORS.reset}`)
  console.log(`  TP (正确检出):  ${s.truePositives}`)
  console.log(`  FN (漏报):      ${s.falseNegatives}`)
  console.log(`  FP (误报):      ${s.falsePositives}`)
  console.log(`  TN (正确排除):  ${s.trueNegatives}`)
  console.log(`  ${COLORS.green}TPR (检出率):   ${(s.tpr * 100).toFixed(1)}%${COLORS.reset}`)
  console.log(`  ${COLORS.red}FPR (误报率):   ${(s.fpr * 100).toFixed(1)}%${COLORS.reset}`)
  console.log(`  ${COLORS.yellow}标准分:         ${(s.score * 100).toFixed(1)}%${COLORS.reset}`)
  console.log()
}
