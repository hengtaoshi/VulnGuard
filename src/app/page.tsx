"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, AlertTriangle, CheckCircle, Activity, Loader2 } from "lucide-react"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { useI18n } from "@/lib/i18n/context"
import { useStats, useScans } from "@/lib/api/hooks"
import type { ScanSummary } from "@/lib/api/types"

const dayKeys = ["days.mon", "days.tue", "days.wed", "days.thu", "days.fri", "days.sat", "days.sun"]

const chartData = [
  { critical: 3, high: 5, medium: 8, low: 12 },
  { critical: 1, high: 7, medium: 4, low: 9 },
  { critical: 4, high: 2, medium: 6, low: 15 },
  { critical: 2, high: 8, medium: 3, low: 11 },
  { critical: 0, high: 4, medium: 7, low: 8 },
  { critical: 1, high: 3, medium: 5, low: 6 },
  { critical: 2, high: 6, medium: 9, low: 10 },
]

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

  // Chart data with translated day labels
  const labeledChartData = chartData.map((d, i) => ({
    ...d,
    name: t(dayKeys[i]),
  }))

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

      {/* Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">{t("dashboard.trends")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={labeledChartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(228, 25%, 16%)" />
                <XAxis dataKey="name" stroke="hsl(215, 20%, 65%)" fontSize={12} />
                <YAxis stroke="hsl(215, 20%, 65%)" fontSize={12} />
                <Tooltip
                  contentStyle={{
                    background: "hsl(228, 39%, 8%)",
                    border: "1px solid hsl(228, 25%, 16%)",
                    borderRadius: "8px",
                    color: "#f1f5f9",
                  }}
                />
                <Bar dataKey="critical" fill="#ef4444" radius={[2, 2, 0, 0]} />
                <Bar dataKey="high" fill="#f59e0b" radius={[2, 2, 0, 0]} />
                <Bar dataKey="medium" fill="#3b82f6" radius={[2, 2, 0, 0]} />
                <Bar dataKey="low" fill="#22c55e" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
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
