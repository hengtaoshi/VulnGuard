"use client"

import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import Link from "next/link"
import { Search, Loader2 } from "lucide-react"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/context"
import { useScans } from "@/lib/api/hooks"
import type { ScanSummary } from "@/lib/api/types"

export default function ScanHistoryPage() {
  const { t } = useI18n()
  const { data: scans, isLoading } = useScans()

  const typeLabels: Record<string, string> = {
    url: t("dashboard.typeUrl"),
    source: t("dashboard.typeSource"),
  }
  const statusLabels: Record<string, string> = {
    completed: t("scan.history.completed"),
    scanning: t("scan.history.scanning"),
  }
  const riskLabels: Record<string, string> = {
    Critical: t("severity.critical"),
    High: t("severity.high"),
    Medium: t("severity.medium"),
    Secure: t("dashboard.secureLabel"),
    "—": "—",
  }

  return (
    <div className="space-y-6">
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input placeholder={t("scan.history.search")} className="pl-9" />
      </div>
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" />
              <span className="text-sm">{t("common.loading")}</span>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs uppercase tracking-wider">
                  <th className="text-left font-medium p-4">{t("scan.history.target")}</th>
                  <th className="text-left font-medium p-4">{t("scan.history.type")}</th>
                  <th className="text-left font-medium p-4">{t("scan.history.status")}</th>
                  <th className="text-left font-medium p-4">{t("scan.history.risk")}</th>
                  <th className="text-left font-medium p-4">{t("scan.history.date")}</th>
                  <th className="text-right font-medium p-4">{t("scan.history.action")}</th>
                </tr>
              </thead>
              <tbody>
                {(scans ?? []).map((scan: ScanSummary) => (
                  <tr key={scan.id} className="border-b border-border/50 last:border-0 hover:bg-accent/30 transition-colors">
                    <td className="p-4 font-medium">{scan.target}</td>
                    <td className="p-4 text-muted-foreground">{typeLabels[scan.type] ?? scan.type}</td>
                    <td className="p-4">
                      <span className={scan.status === "completed" ? "text-emerald-500" : "text-amber-500"}>
                        {statusLabels[scan.status] ?? scan.status}
                      </span>
                    </td>
                    <td className="p-4">
                      <Badge
                        variant={
                          scan.risk === "Critical" ? "destructive" :
                          scan.risk === "High" ? "warning" :
                          scan.risk === "Medium" ? "info" :
                          scan.risk === "Secure" ? "success" : "outline"
                        }
                      >
                        {riskLabels[scan.risk] ?? scan.risk}
                      </Badge>
                    </td>
                    <td className="p-4 text-muted-foreground">{scan.date}</td>
                    <td className="p-4 text-right">
                      <Link href={`/scan/${scan.id}`} className="text-primary text-xs hover:underline">
                        {t("scan.history.viewReport")}
                      </Link>
                    </td>
                  </tr>
                ))}
                {scans?.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-muted-foreground text-sm">
                      {t("common.noHistory")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
