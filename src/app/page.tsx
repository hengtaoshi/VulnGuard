"use client"

import dynamic from "next/dynamic"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, AlertTriangle, CheckCircle, Activity, Loader2 } from "lucide-react"
import { useI18n } from "@/lib/i18n/context"
import { useStats, useScans } from "@/lib/api/hooks"
import type { ScanSummary } from "@/lib/api/types"
import { SetupWizard } from "@/components/scanner/setup-wizard"
import { useState, useEffect } from "react"

const VulnerabilityChart = dynamic(
  () => import("@/components/dashboard/vulnerability-chart").then(m => m.VulnerabilityChart),
  {
    ssr: false,
    loading: () => (
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="h-5 w-32 bg-muted rounded animate-pulse mb-4" />
        <div className="h-[250px] bg-muted/50 rounded animate-pulse" />
      </div>
    ),
  },
)

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

  const [showWizard, setShowWizard] = useState(false)
  const [wizardChecked, setWizardChecked] = useState(false)

  // 首次启动检测：如果没有任何扫描器可用，自动弹出安装向导
  useEffect(() => {
    if (wizardChecked) return
    fetch("/api/scanners")
      .then(r => r.json())
      .then((data: { available: boolean }[]) => {
        const anyAvailable = data.some(s => s.available)
        if (!anyAvailable) {
          setShowWizard(true)
        }
        setWizardChecked(true)
      })
      .catch(() => setWizardChecked(true))
  }, [wizardChecked])

  const typeLabels: Record<string, string> = {
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

      {/* Vulnerability Trend Chart — dynamically loaded (recharts is heavy) */}
      <VulnerabilityChart />

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

      {/* 首次启动安装向导 */}
      <SetupWizard
        open={showWizard}
        onFinish={() => {
          setShowWizard(false)
        }}
      />
    </div>
  )
}
