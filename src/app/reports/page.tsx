"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { FileText } from "lucide-react"
import { useI18n } from "@/lib/i18n/context"

export default function ReportsPage() {
  const { t } = useI18n()

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t("reports.title")}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-12 text-muted-foreground">
            <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>{t("reports.empty")}</p>
            <p className="text-sm mt-1">{t("reports.emptyDesc")}</p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
