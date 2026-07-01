"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { useI18n } from "@/lib/i18n/context"
import { Shield, BarChart3, AlertCircle, ExternalLink, RefreshCw, CheckCircle2, XCircle, MinusCircle, TrendingUp, Target, Activity } from "lucide-react"
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts"
import type { BenchmarkData, ScannerCoverage, CweCoverage, BenchmarkScore } from "@/lib/benchmark/types"

export default function BenchmarkPage() {
  const { t } = useI18n()
  const [data, setData] = useState<BenchmarkData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [filterCwe, setFilterCwe] = useState("all") // "all" | scanner name

  useEffect(() => {
    fetch("/api/benchmark")
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  if (loading) return <LoadingState />
  if (error) return <ErrorState error={error} />

  const { cweList, scannerCoverage, owaspScores, lastUpdated } = data!

  // CWE 筛选
  const filteredCwe = filterCwe === "all"
    ? cweList
    : cweList.filter(c => c.scanners.includes(filterCwe))

  // 图表数据
  const chartData = scannerCoverage
    .filter(s => s.cweCount > 0)
    .map(s => ({ name: s.displayName, cweCount: s.cweCount }))
    .sort((a, b) => b.cweCount - a.cweCount)

  const owaspChartData = owaspScores.map(s => ({
    name: s.displayName,
    "检出率 (TPR)": +(s.tpr * 100).toFixed(1),
    "标准分": +(s.score * 100).toFixed(1),
    "误报率 (FPR)": +(s.fpr * 100).toFixed(1),
  }))

  const totalCwe = cweList.length
  const coveredCwe = new Set(cweList.flatMap(c => c.scanners)).size > 0
    ? new Set(scannerCoverage.filter(s => s.cweCount > 0).flatMap(s => cweList.filter(c => c.scanners.includes(s.name)).map(c => c.cweId))).size
    : 0

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
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SummaryCard
          icon={<Target className="h-4 w-4" />}
          label={t("benchmark.cweCoverage")}
          value={`${coveredCwe}/${totalCwe}`}
          sub={`${t("benchmark.cweTotal")} ${totalCwe} ${t("benchmark.categories")}`}
          color="text-primary"
        />
        <SummaryCard
          icon={<Activity className="h-4 w-4" />}
          label={t("benchmark.scannerCount")}
          value={`${scannerCoverage.filter(s => s.cweCount > 0).length}`}
          sub={t("benchmark.activeScanners")}
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
            {owaspScores.filter(s => s.score > 0).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">{t("benchmark.noOwaspData")}</p>
            ) : (
              <>
                {/* 图表 */}
                <div className="h-64 mb-6">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={owaspChartData.filter(d => d["标准分"] > 0)} barGap={4}>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                      <XAxis dataKey="name" tick={{ fontSize: 12 }} stroke="hsl(var(--muted-foreground))" />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} stroke="hsl(var(--muted-foreground))" unit="%" />
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                        formatter={(v: number) => [`${v.toFixed(1)}%`]}
                      />
                      <Legend wrapperStyle={{ fontSize: 12 }} />
                      <Bar dataKey="检出率 (TPR)" fill="hsl(142, 76%, 36%)" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="标准分" fill="hsl(38, 92%, 50%)" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* 详细分数表格 */}
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
              </>
            )}
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
            {/* 筛选 */}
            <select
              value={filterCwe}
              onChange={e => setFilterCwe(e.target.value)}
              className="h-7 text-xs bg-muted border border-border rounded-md px-2 text-foreground outline-none"
            >
              <option value="all">{t("benchmark.allScanners")}</option>
              {scannerCoverage.filter(s => s.cweCount > 0).map(s => (
                <option key={s.name} value={s.name}>{s.displayName}</option>
              ))}
            </select>
          </div>
          <CardDescription className="text-xs">
            {t("benchmark.cweMatrixDesc")} — <a href="https://cwe.mitre.org" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-0.5">cwe.mitre.org<ExternalLink className="h-3 w-3" /></a>
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 pr-3 text-muted-foreground font-medium">{t("benchmark.cweId")}</th>
                <th className="text-left py-2 pr-3 text-muted-foreground font-medium">{t("benchmark.vulnerability")}</th>
                <th className="text-left py-2 pr-3 text-muted-foreground font-medium hidden md:table-cell">{t("benchmark.description")}</th>
                {scannerCoverage.filter(s => s.cweCount > 0).map(s => (
                  <th key={s.name} className="text-center py-2 px-1.5 text-muted-foreground font-medium text-[10px]">{s.displayName}</th>
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
                  <td className="py-2 pr-3 text-muted-foreground hidden md:table-cell max-w-xs truncate">{cwe.description}</td>
                  {scannerCoverage.filter(s => s.cweCount > 0).map(s => (
                    <td key={s.name} className="text-center py-2 px-1.5">
                      {cwe.scanners.includes(s.name)
                        ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 inline-block" />
                        : <MinusCircle className="h-3.5 w-3.5 text-muted-foreground/30 inline-block" />
                      }
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
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
            {scannerCoverage.filter(s => s.cweCount > 0).map(s => (
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
            <code>{`# 1. 克隆 OWASP Benchmark 项目\ngit clone https://github.com/OWASP/Benchmark.git /tmp/owasp-benchmark\n\n# 2. 运行基准测试\nnode scripts/run-owasp-benchmark.js /tmp/owasp-benchmark\n\n# 3. 结果写入 .benchmark-results.json，刷新页面即可查看`}</code>
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

function ScannerCard({ scanner }: { scanner: ScannerCoverage }) {
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
          <p className="text-sm font-medium">{scanner.displayName}</p>
          <Badge variant="secondary" className="text-[10px]">{scanner.cweCount} CWE</Badge>
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
          <Button variant="outline" size="sm" onClick={() => window.location.reload()}>重试</Button>
        </CardContent>
      </Card>
    </div>
  )
}
