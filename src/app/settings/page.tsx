"use client"

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/context"

export default function SettingsPage() {
  const { t } = useI18n()

  return (
    <div className="max-w-2xl space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t("settings.title")}</CardTitle>
          <CardDescription>{t("settings.desc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{t("settings.maxDuration")}</p>
              <p className="text-sm text-muted-foreground">{t("settings.maxDurationDesc")}</p>
            </div>
            <span className="text-sm font-mono">30</span>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium">{t("settings.autoReport")}</p>
              <p className="text-sm text-muted-foreground">{t("settings.autoReportDesc")}</p>
            </div>
            <span className="text-sm text-emerald-500">{t("settings.enabled")}</span>
          </div>
          <Button variant="outline" size="sm">{t("settings.save")}</Button>
        </CardContent>
      </Card>
    </div>
  )
}
