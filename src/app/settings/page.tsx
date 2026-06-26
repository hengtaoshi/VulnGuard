"use client"

import { useState, useEffect, useCallback } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/context"
import { Loader2, CheckCircle2, AlertCircle, Trash2, RotateCcw, Download } from "lucide-react"
import type { AppSettings } from "@/lib/settings-store"
import { useRouter } from "next/navigation"

const DEFAULT_SETTINGS: AppSettings = {
  maxDuration: 30,
  autoReport: true,
  defaultEngine: "ai",
  aiAggregation: true,
  concurrentScanners: 4,
  retentionDays: 0,
}

function Toggle({ value, onChange, id }: { value: boolean; onChange: (v: boolean) => void; id: string }) {
  return (
    <button
      id={id}
      type="button"
      role="switch"
      aria-checked={value}
      onClick={() => onChange(!value)}
      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
        value ? "bg-primary" : "bg-input"
      }`}
    >
      <span
        className={`pointer-events-none block h-5 w-5 rounded-full bg-background shadow-lg ring-0 transition-transform ${
          value ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  )
}

export default function SettingsPage() {
  const { t } = useI18n()
  const router = useRouter()
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch("/api/settings")
      .then(r => {
        if (!r.ok) throw new Error("HTTP " + r.status)
        return r.json()
      })
      .then((data: AppSettings) => {
        setSettings({ ...DEFAULT_SETTINGS, ...data })
        setLoading(false)
      })
      .catch(() => {
        setError(t("settings.loadError"))
        setLoading(false)
      })
  }, [t])

  const handleSave = useCallback(async () => {
    setSaving(true)
    setSaved(false)
    setError(null)
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings),
      })
      if (!res.ok) throw new Error("HTTP " + res.status)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch {
      setError(t("settings.saveError"))
    } finally {
      setSaving(false)
    }
  }, [settings, t])

  const handleClear = useCallback(async () => {
    if (!confirm(t("settings.clearDataConfirm"))) return
    setClearing(true)
    try {
      await fetch("/api/scans", { method: "DELETE" })
      router.refresh()
    } catch {
      setError("清除失败")
    } finally {
      setClearing(false)
    }
  }, [t, router])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        <span className="text-sm">{t("common.loading")}</span>
      </div>
    )
  }

  return (
    <div className="max-w-2xl space-y-6">

      {/* 扫描配置 */}
      <Card>
        <CardHeader>
          <CardTitle>{t("settings.title")}</CardTitle>
          <CardDescription>{t("settings.desc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">

          {/* 最大扫描时长 */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1">
              <p className="font-medium text-sm">{t("settings.maxDuration")}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{t("settings.maxDurationDesc")}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Input
                type="number"
                min={5}
                max={120}
                value={settings.maxDuration}
                onChange={e => setSettings(s => ({ ...s, maxDuration: Math.max(5, Math.min(120, parseInt(e.target.value) || 30)) }))}
                className="w-20 h-8 text-xs text-center font-mono"
              />
              <span className="text-xs text-muted-foreground">{t("settings.minutes")}</span>
            </div>
          </div>

          <hr className="border-border/50" />

          {/* 默认扫描引擎 */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1">
              <p className="font-medium text-sm">{t("settings.defaultEngine")}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{t("settings.defaultEngineDesc")}</p>
            </div>
            <select
              value={settings.defaultEngine}
              onChange={e => setSettings(s => ({ ...s, defaultEngine: e.target.value as "ai" | "all" }))}
              className="h-8 rounded-lg border border-border bg-background px-2.5 text-xs text-foreground shrink-0"
            >
              <option value="ai">{t("settings.engineAi")}</option>
              <option value="all">{t("settings.engineAll")}</option>
            </select>
          </div>

          <hr className="border-border/50" />

          {/* 并行扫描器数 */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1">
              <p className="font-medium text-sm">{t("settings.concurrentScanners")}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{t("settings.concurrentScannersDesc")}</p>
            </div>
            <div className="flex items-center gap-1 shrink-0">
              {[2, 4, 6, 8].map(n => (
                <button
                  key={n}
                  onClick={() => setSettings(s => ({ ...s, concurrentScanners: n }))}
                  className={`h-8 w-8 rounded-lg text-xs font-mono transition-colors ${
                    settings.concurrentScanners === n
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground hover:bg-accent"
                  }`}
                >
                  {n}
                </button>
              ))}
            </div>
          </div>

          <hr className="border-border/50" />

          {/* 自动报告 */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1">
              <p className="font-medium text-sm">{t("settings.autoReport")}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{t("settings.autoReportDesc")}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Toggle
                id="autoReport"
                value={settings.autoReport}
                onChange={v => setSettings(s => ({ ...s, autoReport: v }))}
              />
              <span className={`text-xs w-10 ${settings.autoReport ? "text-emerald-500" : "text-muted-foreground"}`}>
                {settings.autoReport ? t("settings.enabled") : t("settings.disabled")}
              </span>
            </div>
          </div>

          <hr className="border-border/50" />

          {/* AI 聚合分析 */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1">
              <p className="font-medium text-sm">{t("settings.aiAggregation")}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{t("settings.aiAggregationDesc")}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Toggle
                id="aiAggregation"
                value={settings.aiAggregation}
                onChange={v => setSettings(s => ({ ...s, aiAggregation: v }))}
              />
              <span className={`text-xs w-10 ${settings.aiAggregation ? "text-emerald-500" : "text-muted-foreground"}`}>
                {settings.aiAggregation ? t("settings.enabled") : t("settings.disabled")}
              </span>
            </div>
          </div>

          <hr className="border-border/50" />

          {/* 数据保留 */}
          <div className="flex items-center justify-between gap-4">
            <div className="flex-1">
              <p className="font-medium text-sm">{t("settings.retentionDays")}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{t("settings.retentionDaysDesc")}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Input
                type="number"
                min={0}
                max={365}
                value={settings.retentionDays}
                onChange={e => setSettings(s => ({ ...s, retentionDays: Math.max(0, Math.min(365, parseInt(e.target.value) || 0)) }))}
                className="w-20 h-8 text-xs text-center font-mono"
              />
              <span className="text-xs text-muted-foreground">{t("settings.days")}</span>
            </div>
          </div>

        </CardContent>
      </Card>

      {/* 操作按钮 */}
      <div className="flex items-center gap-3">
        <Button onClick={handleSave} disabled={saving} size="sm" className="gap-1.5">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
          {t("settings.save")}
        </Button>
        {saved && (
          <span className="text-xs text-emerald-500 flex items-center gap-1">
            <CheckCircle2 className="h-3.5 w-3.5" /> {t("settings.saved")}
          </span>
        )}
        {error && (
          <span className="text-xs text-destructive flex items-center gap-1">
            <AlertCircle className="h-3.5 w-3.5" /> {error}
          </span>
        )}
      </div>

      {/* 检查更新 */}
      <Card>
        <CardHeader>
          <CardTitle>检查更新</CardTitle>
          <CardDescription>检查 GitHub 上的最新版本</CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={async () => {
              const btn = document.activeElement as HTMLButtonElement
              btn.disabled = true
              try {
                const res: any = await (window as any).vulnguard?.checkForUpdates()
                if (res?.ok) alert("正在检查更新...")
                else alert(res?.error || "检查更新失败")
              } finally {
                btn.disabled = false
              }
            }}
          >
            <Download className="h-3.5 w-3.5" />
            检查更新
          </Button>
        </CardContent>
      </Card>

      {/* 危险区域 */}
      <Card className="border-destructive/20">
        <CardHeader>
          <CardTitle className="text-destructive">{t("settings.clearData")}</CardTitle>
          <CardDescription>{t("settings.clearDataDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            variant="destructive"
            size="sm"
            onClick={handleClear}
            disabled={clearing}
            className="gap-1.5"
          >
            {clearing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
            {clearing ? t("settings.clearing") : t("settings.clearDataBtn")}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
