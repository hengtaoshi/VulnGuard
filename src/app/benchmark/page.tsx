"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useI18n } from "@/lib/i18n/context"
import { Shield, BarChart3, AlertCircle, ExternalLink, RefreshCw, CheckCircle2, XCircle, MinusCircle, TrendingUp, Target, Activity, Database, FileSearch, Fingerprint } from "lucide-react"
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts"
import type { BenchmarkData, ScannerCoverage, CweCoverage, BenchmarkScore, CoverageType } from "@/lib/benchmark/types"

export default function BenchmarkPage() {
  const { t } = useI18n()
  const [data, setData] = useState<BenchmarkData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [filterCwe, setFilterCwe] = useState("all")

  useEffect(() => {
    fetch("/api/benchmark")
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  if (loading) return <LoadingState />
  if (error) return <ErrorState error={error} />

  const { cweList, scannerCoverage, owaspScores, lastUpdated } = data!

  const filteredCwe = filterCwe === "all"
    ? cweList
    : cweList.filter(c => c.scanners.includes(filterCwe) || c.cveScanners?.includes(filterCwe))

  // 图表：规则级 + CVE 级覆盖数对比
  const ruleScanners = scannerCoverage.filter(s => s.coverageType === "rule")
  const chartData = ruleScanners
    .map(s => ({ name: s.displayName, cweCount: s.cweCount }))
    .sort((a, b) => b.cweCount - a.cweCount)

  const owaspChartData = owaspScores.map(s => ({
    name: s.displayName,
    "检出率 (TPR)": +(s.tpr * 100).toFixed(1),
    "标准分": +(s.score * 100).toFixed(1),
    "误报率 (FPR)": +(s.fpr * 100).toFixed(1),
  }))

  const totalCwe = cweList.length
  const ruleCweScanners = scannerCoverage.filter(s => s.coverageType === "rule" && s.cweCount > 0)
  const coveredCwe = ruleCweScanners.length > 0
    ? new Set(ruleCweScanners.flatMap(s => cweList.filter(c => c.scanners.includes(s.name)).map(c => c.cweId))).size
    : 0

  // Matrix columns: rule scanners + cve-db scanners
  const matrixScanners = scannerCoverage.filter(s => s.coverageType === "rule" && s.cweCount > 0)
  const cveDbScanners = scannerCoverage.filter(s => s.coverageType === "cve-db" && s.cweCount > 0)

  return (
    <div className="max-w-6xl mx-auto space-y-6 p-4 md:p-6">
      {/* ─── Header ──────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-primary" />
            {t("benchmark.title")}
          </h1>
          <p className="text-sm text-muted-foreground mt-1">{t("benchmark.subtitle")}</p>
        </div>
        {lastUpdated && (
          <p className="text-xs text-muted-foreground">
            {t("benchmark.lastUpdated")}: {lastUpdated}
          </p>
        )}
      </div>

      {/* ─── 统计总览卡片 ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <SummaryCard
          icon={<Target className="h-4 w-4" />}
          label={t("benchmark.cweCoverage")}
          value={`${coveredCwe}/${totalCwe}`}
          sub={`规则级覆盖 ${totalCwe} 类 CWE`}
          color="text-primary"
        />
        <SummaryCard
          icon={<Database className="h-4 w-4" />}
          label="CVE 数据库覆盖"
          value={`${cveDbScanners.length} 个`}
          sub="SCA 扫描器覆盖全部有 CVE 的 CWE"
          color="text-sky-500"
        />
        <SummaryCard
          icon={<Activity className="h-4 w-4" />}
          label={t("benchmark.scannerCount")}
          value={`${scannerCoverage.filter(s => s.cweCount > 0).length}`}
          sub={`共 ${scannerCoverage.length} 个扫描器`}
          color="text-emerald-500"
        />
        <SummaryCard
          icon={<TrendingUp className="h-4 w-4" />}
          label={t("benchmark.owaspScore")}
          value={owaspScores.some(s => s.score > 0) ? `${(Math.max(...owaspScores.filter(s => s.score > 0).map(s => s.score)) * 100).toFixed(0)}%` : t("benchmark.notTested")}
          sub={owaspScores.some(s => s.score > 0) ? t("benchmark.bestScore") : t("benchmark.runOwaspHint")}
          color="text-amber-500"
        />
      </div>

      {/* ─── OWASP Benchmark 跑分 ────────────────────────────────────────── */}
      {owaspScores.some(s => s.score > 0) && (
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-amber-500" />
              <CardTitle className="text-sm">{t("benchmark.owaspTitle")}</CardTitle>
            </div>
            <CardDescription className="text-xs">
              {t("benchmark.owaspDesc")} — <a href="https://owasp.org/www-project-benchmark/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-0.5">OWASP Benchmark<ExternalLink className="h-3 w-3" /></a>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-64 mb-6">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={owaspChartData.filter(d => d["标准分"] > 0)} barGap={4}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} stroke="hsl(var(--muted-foreground))" />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} stroke="hsl(var(--muted-foreground))" unit="%" />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }} formatter={(v: number) => [`${v.toFixed(1)}%`]} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="检出率 (TPR)" fill="hsl(142, 76%, 36%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="标准分" fill="hsl(38, 92%, 50%)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-2 px-2 text-muted-foreground font-medium">{t("benchmark.scanner")}</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">TP</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">FP</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">TN</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">FN</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">{t("benchmark.tpr")}</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">{t("benchmark.fpr")}</th>
                    <th className="text-right py-2 px-2 text-muted-foreground font-medium">{t("benchmark.score")}</th>
                  </tr>
                </thead>
                <tbody>
                  {owaspScores.filter(s => s.score > 0).map(s => (
                    <tr key={s.scannerName} className="border-b border-border/50 hover:bg-muted/30">
                      <td className="py-2 px-2 font-medium">{s.displayName}</td>
                      <td className="text-right py-2 px-2 font-mono">{s.truePositives}</td>
                      <td className="text-right py-2 px-2 font-mono">{s.falsePositives}</td>
                      <td className="text-right py-2 px-2 font-mono">{s.trueNegatives}</td>
                      <td className="text-right py-2 px-2 font-mono">{s.falseNegatives}</td>
                      <td className="text-right py-2 px-2 font-mono text-emerald-500">{(s.tpr * 100).toFixed(1)}%</td>
                      <td className="text-right py-2 px-2 font-mono text-red-500">{(s.fpr * 100).toFixed(1)}%</td>
                      <td className="text-right py-2 px-2 font-mono font-bold text-amber-500">{(s.score * 100).toFixed(1)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* ─── CWE 覆盖矩阵 ────────────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm">{t("benchmark.cweMatrix")}</CardTitle>
            </div>
            <select
              value={filterCwe}
              onChange={e => setFilterCwe(e.target.value)}
              className="h-7 text-xs bg-muted border border-border rounded-md px-2 text-foreground outline-none"
            >
              <option value="all">{t("benchmark.allScanners")}</option>
              {[...matrixScanners, ...cveDbScanners].map(s => (
                <option key={s.name} value={s.name}>{s.displayName}</option>
              ))}
            </select>
          </div>
          <CardDescription className="text-xs space-y-1">
            <p>
              {t("benchmark.cweMatrixDesc")} — <a href="https://cwe.mitre.org" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-0.5">cwe.mitre.org<ExternalLink className="h-3 w-3" /></a>
            </p>
            <p className="flex items-center gap-4 text-[11px]">
              <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-emerald-500" /> 规则覆盖</span>
              <span className="flex items-center gap-1"><Database className="h-3 w-3 text-sky-500" /> CVE 数据库覆盖</span>
            </p>
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 pr-3 text-muted-foreground font-medium min-w-[80px]">{t("benchmark.cweId")}</th>
                <th className="text-left py-2 pr-3 text-muted-foreground font-medium min-w-[100px]">{t("benchmark.vulnerability")}</th>
                <th className="text-left py-2 pr-3 text-muted-foreground font-medium hidden lg:table-cell min-w-[180px]">{t("benchmark.description")}</th>
                {/* 规则级扫描器列 */}
                {matrixScanners.map(s => (
                  <th key={s.name} className="text-center py-2 px-1 text-muted-foreground font-medium text-[10px]">{s.displayName}</th>
                ))}
                {/* CVE 级扫描器列 */}
                {cveDbScanners.map(s => (
                  <th key={s.name} className="text-center py-2 px-1 text-muted-foreground font-medium text-[10px] text-sky-500">
                    <span className="flex items-center justify-center gap-0.5"><Database className="h-2.5 w-2.5" />{s.displayName}</span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredCwe.map(cwe => (
                <tr key={cwe.cweId} className="border-b border-border/30 hover:bg-muted/20">
                  <td className="py-2 pr-3 font-mono text-primary">
                    <a href={`https://cwe.mitre.org/data/definitions/${cwe.cweId.split("-")[1]}.html`} target="_blank" rel="noopener noreferrer" className="hover:underline inline-flex items-center gap-0.5">
                      {cwe.cweId}<ExternalLink className="h-2.5 w-2.5" />
                    </a>
                  </td>
                  <td className="py-2 pr-3 font-medium">{cwe.name}</td>
                  <td className="py-2 pr-3 text-muted-foreground hidden lg:table-cell max-w-[200px] truncate">{cwe.description}</td>
                  {/* 规则级 */}
                  {matrixScanners.map(s => (
                    <td key={s.name} className="text-center py-2 px-1">
                      {cwe.scanners.includes(s.name)
                        ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 inline-block" />
                        : <MinusCircle className="h-3.5 w-3.5 text-muted-foreground/30 inline-block" />
                      }
                    </td>
                  ))}
                  {/* CVE 级 */}
                  {cveDbScanners.map(s => (
                    <td key={s.name} className="text-center py-2 px-1">
                      {cwe.cveScanners?.includes(s.name)
                        ? <Database className="h-3.5 w-3.5 text-sky-500 inline-block" />
                        : <MinusCircle className="h-3.5 w-3.5 text-muted-foreground/30 inline-block" />
                      }
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-[10px] text-muted-foreground mt-3 text-center">
            ✔ 绿色 = 规则精确匹配 &nbsp;|&nbsp; 💾 蓝色 = 通过 CVE 数据库映射（SCA 扫描器）&nbsp;|&nbsp; — 不适用
          </p>
        </CardContent>
      </Card>

      {/* ─── 扫描器覆盖概况 ──────────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm">{t("benchmark.scannerOverview")}</CardTitle>
          </div>
          <CardDescription className="text-xs">{t("benchmark.scannerOverviewDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {scannerCoverage.sort((a, b) => (b.cweCount || 0) - (a.cweCount || 0)).map(s => (
              <ScannerCard key={s.name} scanner={s} />
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ─── Benchmark 跑分指引 ──────────────────────────────────────────── */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-amber-500" />
            <CardTitle className="text-sm">{t("benchmark.howToRun")}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground space-y-2">
          <p>{t("benchmark.howToRunDesc")}</p>
          <pre className="bg-muted p-3 rounded-lg overflow-x-auto text-[11px]">
            <code>{`# 1. 克隆 OWASP Benchmark 项目\ngit clone https://github.com/OWASP/Benchmark.git /tmp/owasp-benchmark\n\n# 2. 运行基准测试\nnode scripts/run-owasp-benchmark.js /tmp/owasp-benchmark\n\n# 3. 刷新页面即可查看`}</code>
          </pre>
        </CardContent>
      </Card>
    </div>
  )
}

// ─── 子组件 ──────────────────────────────────────────────────────────────

function SummaryCard({ icon, label, value, sub, color }: { icon: React.ReactNode; label: string; value: string; sub: string; color: string }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-2 text-muted-foreground text-xs mb-2">
          {icon}
          <span>{label}</span>
        </div>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>
      </CardContent>
    </Card>
  )
}

const COVERAGE_LABELS: Record<CoverageType, { label: string; color: string }> = {
  "rule": { label: "规则匹配", color: "bg-emerald-500/10 text-emerald-500" },
  "cve-db": { label: "CVE 数据库", color: "bg-sky-500/10 text-sky-500" },
  "template": { label: "模板化", color: "bg-purple-500/10 text-purple-500" },
  "practice": { label: "最佳实践", color: "bg-amber-500/10 text-amber-500" },
}

function ScannerCard({ scanner }: { scanner: ScannerCoverage }) {
  const ct = COVERAGE_LABELS[scanner.coverageType]

  const details: string[] = []
  if (scanner.ruleCount) details.push(`${scanner.ruleCount} 条规则`)
  if (scanner.detectorCount) details.push(`${scanner.detectorCount} 个检测器`)
  if (scanner.ecosystemCount) details.push(`${scanner.ecosystemCount} 个生态`)
  if (scanner.policyCount) details.push(`${scanner.policyCount}+ 策略`)
  if (scanner.standards) details.push(scanner.standards.join("、"))

  return (
    <Card className="border-border/50">
      <CardContent className="p-3 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium">{scanner.displayName}</p>
            <span className={`text-[10px] px-1.5 py-0.5 rounded ${ct.color}`}>{ct.label}</span>
          </div>
          <Badge variant="secondary" className="text-[10px]">
            {scanner.cweCountDisplay
              ? (scanner.cweCountDisplay === "全部" ? "33 CWE" : scanner.cweCountDisplay)
              : `${scanner.cweCount} CWE`
            }
          </Badge>
        </div>
        {details.length > 0 && (
          <p className="text-[10px] text-muted-foreground">{details.join(" · ")}</p>
        )}
        {scanner.sourceUrl && (
          <a href={scanner.sourceUrl} target="_blank" rel="noopener noreferrer" className="text-[10px] text-primary hover:underline inline-flex items-center gap-0.5">
            官方文档 <ExternalLink className="h-2.5 w-2.5" />
          </a>
        )}
      </CardContent>
    </Card>
  )
}

function LoadingState() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="text-center space-y-3">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground mx-auto" />
        <p className="text-sm text-muted-foreground">加载中...</p>
      </div>
    </div>
  )
}

function ErrorState({ error }: { error: string }) {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <Card className="max-w-md">
        <CardContent className="p-6 text-center space-y-3">
          <AlertCircle className="h-8 w-8 text-destructive mx-auto" />
          <p className="text-sm font-medium text-destructive">加载失败</p>
          <p className="text-xs text-muted-foreground">{error}</p>
          <button className="text-xs text-primary hover:underline" onClick={() => window.location.reload()}>重试</button>
        </CardContent>
      </Card>
    </div>
  )
}
