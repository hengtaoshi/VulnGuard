"use client"

import { useState } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { Search, Loader2, Trash2, AlertCircle, X } from "lucide-react"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/context"
import { useScans, useDeleteScan, useClearScans } from "@/lib/api/hooks"
import type { ScanSummary } from "@/lib/api/types"

export default function ScanHistoryPage() {
  const { t } = useI18n()
  const { data: scans, isLoading } = useScans()
  const deleteScan = useDeleteScan()
  const clearScans = useClearScans()
  const [confirmClear, setConfirmClear] = useState(false)

  const typeLabels: Record<string, string> = {
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

  const handleDelete = (id: string, e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (confirm(`确定要删除扫描记录 ${id} 吗？`)) {
      deleteScan.mutate(id)
    }
  }

  const handleClearAll = () => {
    clearScans.mutate(undefined, {
      onSuccess: () => setConfirmClear(false),
    })
  }

  const list = scans ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div className="relative max-w-md flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder={t("scan.history.search")} className="pl-9" />
        </div>
        {list.length > 0 && !confirmClear && (
          <Button
            variant="outline"
            size="sm"
            className="text-destructive gap-2"
            onClick={() => setConfirmClear(true)}
          >
            <Trash2 className="h-4 w-4" />
            清除全部
          </Button>
        )}
        {confirmClear && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-destructive">确认清除全部记录？</span>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleClearAll}
              disabled={clearScans.isPending}
            >
              {clearScans.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                "确认"
              )}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setConfirmClear(false)}
            >
              取消
            </Button>
          </div>
        )}
      </div>
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" />
              <span className="text-sm">{t("common.loading")}</span>
            </div>
          ) : list.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <div className="h-12 w-12 rounded-full bg-muted flex items-center justify-center mb-4">
                <AlertCircle className="h-6 w-6" />
              </div>
              <p className="text-sm font-medium">{t("common.noHistory")}</p>
              <p className="text-xs mt-1">创建一次扫描后，记录将显示在这里</p>
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
                {list.map((scan: ScanSummary) => (
                  <tr key={scan.id} className="border-b border-border/50 last:border-0 hover:bg-accent/30 transition-colors group">
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
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          href={`/scan/${scan.id}`}
                          className="text-primary text-xs hover:underline"
                        >
                          {t("scan.history.viewReport")}
                        </Link>
                        <button
                          onClick={(e) => handleDelete(scan.id, e)}
                          className="opacity-0 group-hover:opacity-100 p-1 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-all"
                          title="删除此记录"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
