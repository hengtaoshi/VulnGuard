"use client"

import { useMemo } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, AlertTriangle, CheckCircle, Activity, Loader2, BarChart3 } from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts"
import { useI18n } from "@/lib/i18n/context"
import { useStats, useScans } from "@/lib/api/hooks"
import type { ScanSummary } from "@/lib/api/types"

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f59e0b",
  medium: "#3b82f6",
  low: "#22c55e",
}

function getRiskBadge(risk: string) {
  const variants: Record<string, "destructive" | "success" | "warning" | "info" | "outline"> = {
    Critical: "destructive",
    High: "warning",
    Medium: "info",
    Secure: "success",
    "—": "outline",
  }
  return <Badge variant={variants[risk] || "outline"}>{risk}</Badge>
}

export default function Dashboard() {
  const { t } = useI18n()
  const { data: stats, isLoading: statsLoading } = useStats()
  const { data: scans, isLoading: scansLoading } = useScans()

  // Derive chart data from real scan results — severity counts per scan
  const { chartData, hiddenCount } = useMemo(() => {
    if (!scans || scans.length === 0) return { chartData: [], hiddenCount: 0 }
    const completed = [...scans]
      .filter(s => s.status === "completed" && s.summary)
      .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime())
    const hiddenCount = Math.max(0, completed.length - 10)
    const sliced = hiddenCount > 0 ? completed.slice(-10) : completed

    return {
      chartData: sliced.map(s => ({
        name: s.target,
        shortLabel: s.target.length > 10 ? s.target.slice(0, 10) + "…" : s.target,
        critical: s.summary!.critical,
        high: s.summary!.high,
        medium: s.summary!.medium,
        low: s.summary!.low,
      })),
      hiddenCount,
    }
  }, [scans])

  const typeLabels: Record<string, string> = {
    url: t("dashboard.typeUrl"),
    source: t("dashboard.typeSource"),
  }

  const statusLabels: Record<string, string> = {
    completed: t("dashboard.completed"),
    scanning: t("dashboard.scanning"),
  }

  const statCards = [
    {
      label: "dashboard.totalScans",
      value: stats?.totalScans ?? "—",
      icon: Shield,
      change: stats?.scanChange ?? "",
      color: "text-primary",
    },
    {
      label: "dashboard.vulnerabilities",
      value: stats?.totalVulnerabilities ?? "—",
      icon: AlertTriangle,
      change: stats?.vulnChange ?? "",
      color: "text-destructive",
    },
    {
      label: "dashboard.secure",
      value: stats?.secure ?? "—",
      icon: CheckCircle,
      change: stats?.secureChange ?? "",
      color: "text-emerald-500",
    },
    {
      label: "dashboard.riskScore",
      value: stats?.riskScore ?? "—",
      icon: Activity,
      change: stats?.riskChange ?? "",
      color: "text-amber-500",
    },
  ]

  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map(s => (
          <Card key={s.label}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-muted-foreground tracking-wider uppercase">
                  {t(s.label)}
                </span>
                <s.icon className={`h-4 w-4 ${s.color}`} />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                {statsLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                ) : (
                  <span className="text-3xl font-bold tracking-tight">{s.value}</span>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">{s.change}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Vulnerability Trend Chart */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              漏洞趋势（按严重等级）
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-1">
              最近 {chartData.length} 次扫描的漏洞数量分布
              {hiddenCount > 0 && (
                <span className="text-muted-foreground/60 ml-1">（仅展示最近 10 条，共 {hiddenCount + chartData.length} 条已完成扫描）</span>
              )}
            </p>
          </div>
          {chartData.length > 0 && (
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.critical }} /> {t("severity.critical")}</span>
              <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.high }} /> {t("severity.high")}</span>
              <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.medium }} /> {t("severity.medium")}</span>
              <span className="flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.low }} /> {t("severity.low")}</span>
            </div>
          )}
        </CardHeader>
        <CardContent>
          {scansLoading ? (
            <div className="h-[250px] flex items-center justify-center text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" />
              <span className="text-sm">{t("common.loading")}</span>
            </div>
          ) : chartData.length === 0 ? (
            <div className="h-[250px] flex flex-col items-center justify-center text-muted-foreground">
              <BarChart3 className="h-8 w-8 mb-2 opacity-50" />
              <p className="text-sm">暂无扫描数据</p>
              <p className="text-xs mt-1">完成一次扫描后，漏洞趋势将在此展示</p>
            </div>
          ) : (
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} barCategoryGap="25%">
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(228, 25%, 16%)" />
                  <XAxis
                    dataKey="shortLabel"
                    stroke="hsl(215, 20%, 65%)"
                    fontSize={11}
                    tick={{ fill: "hsl(215, 20%, 65%)" }}
                    angle={-20}
                    textAnchor="end"
                    height={50}
                  />
                  <YAxis stroke="hsl(215, 20%, 65%)" fontSize={11} tick={{ fill: "hsl(215, 20%, 65%)" }} allowDecimals={false} />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload || payload.length === 0) return null
                      const data = payload[0]?.payload
                      if (!data) return null
                      const total = data.critical + data.high + data.medium + data.low
                      return (
                        <div className="bg-card border border-border rounded-lg shadow-lg p-4 text-sm space-y-1.5">
                          <p className="font-medium text-foreground max-w-[260px] truncate" title={data.name}>{data.name}</p>
                          <div className="border-t border-border pt-1.5 space-y-1">
                            <div className="flex items-center justify-between gap-4">
                              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.critical }} />{t("severity.critical")}</span>
                              <span className="font-mono font-medium">{data.critical}</span>
                            </div>
                            <div className="flex items-center justify-between gap-4">
                              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.high }} />{t("severity.high")}</span>
                              <span className="font-mono font-medium">{data.high}</span>
                            </div>
                            <div className="flex items-center justify-between gap-4">
                              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.medium }} />{t("severity.medium")}</span>
                              <span className="font-mono font-medium">{data.medium}</span>
                            </div>
                            <div className="flex items-center justify-between gap-4">
                              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: SEVERITY_COLORS.low }} />{t("severity.low")}</span>
                              <span className="font-mono font-medium">{data.low}</span>
                            </div>
                          </div>
                          <div className="border-t border-border pt-1.5 flex justify-between text-muted-foreground">
                            <span>总计</span>
                            <span className="font-medium text-foreground">{total}</span>
                          </div>
                        </div>
                      )
                    }}
                    cursor={{ fill: "hsl(228, 25%, 16%)" }}
                  />
                  <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }} />
                  <Bar dataKey="critical" name={t("severity.critical")} fill={SEVERITY_COLORS.critical} radius={[2, 2, 0, 0]} stackId="a" />
                  <Bar dataKey="high" name={t("severity.high")} fill={SEVERITY_COLORS.high} radius={[2, 2, 0, 0]} stackId="a" />
                  <Bar dataKey="medium" name={t("severity.medium")} fill={SEVERITY_COLORS.medium} radius={[2, 2, 0, 0]} stackId="a" />
                  <Bar dataKey="low" name={t("severity.low")} fill={SEVERITY_COLORS.low} radius={[2, 2, 0, 0]} stackId="a" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent Scans */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">{t("dashboard.recentScans")}</CardTitle>
          <button className="text-xs text-primary hover:underline">{t("dashboard.viewAll")} →</button>
        </CardHeader>
        <CardContent>
          {scansLoading ? (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" />
              <span className="text-sm">{t("common.loading")}</span>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-muted-foreground text-xs uppercase tracking-wider">
                    <th className="text-left font-medium pb-3">{t("dashboard.target")}</th>
                    <th className="text-left font-medium pb-3">{t("dashboard.type")}</th>
                    <th className="text-left font-medium pb-3">{t("dashboard.status")}</th>
                    <th className="text-left font-medium pb-3">{t("dashboard.risk")}</th>
                    <th className="text-left font-medium pb-3">{t("dashboard.date")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(scans ?? []).map((scan: ScanSummary) => (
                    <tr key={scan.id} className="border-b border-border/50 last:border-0">
                      <td className="py-3 font-medium">{scan.target}</td>
                      <td className="py-3 text-muted-foreground">{typeLabels[scan.type] ?? scan.type}</td>
                      <td className="py-3">
                        <span className={scan.status === "completed" ? "text-emerald-500" : "text-amber-500"}>
                          {statusLabels[scan.status] ?? scan.status}
                        </span>
                      </td>
                      <td className="py-3">{getRiskBadge(scan.risk)}</td>
                      <td className="py-3 text-muted-foreground">{scan.date}</td>
                    </tr>
                  ))}
                  {scans?.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-muted-foreground text-sm">
                        {t("common.noScans")}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
