"use client"

import { useState, useEffect, useCallback } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/context"
import { Loader2, CheckCircle2, AlertCircle, Trash2, RotateCcw, Download, Tag, Shield, Globe, Bell, Cpu } from "lucide-react"

interface ScannerInfo {
  name: string
  displayName: string
  category: string
  available: boolean
  description: string
  scanTypes: string[]
  typicalDuration: string
  priority: number
}
import { DEFAULT_SETTINGS } from "@/lib/settings-store"
import type { AppSettings } from "@/lib/settings-store"
import { useRouter } from "next/navigation"

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
  const [scanners, setScanners] = useState<ScannerInfo[]>([])
  const [scannersLoading, setScannersLoading] = useState(true)

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

    fetch("/api/scanners")
      .then(r => r.json())
      .then(data => { setScanners(data); setScannersLoading(false) })
      .catch(() => setScannersLoading(false))
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

  const toggleScanner = useCallback((name: string, disabled: boolean) => {
    setSettings(s => {
      const list = disabled
        ? [...new Set([...s.disabledScanners, name])]
        : s.disabledScanners.filter(n => n !== name)
      return { ...s, disabledScanners: list }
    })
  }, [])

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

      {/* 扫描器管理 */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-primary" />
            <CardTitle>{t("settings.scannerManagement")}</CardTitle>
          </div>
          <CardDescription>{t("settings.scannerManagementDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          {scannersLoading ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> {t("common.loading")}
            </div>
          ) : (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs text-muted-foreground px-2 py-1">
                <span>{t("dashboard.type")}</span>
                <span>{t("reports.status")}</span>
              </div>
              {scanners.map(sc => {
                const isDisabled = settings.disabledScanners.includes(sc.name)
                return (
                  <div key={sc.name} className="flex items-center justify-between rounded-lg px-2 py-1.5 hover:bg-accent/50 transition-colors">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${sc.available ? "bg-emerald-500" : "bg-muted"}`} />
                      <span className="text-xs font-medium">{sc.displayName}</span>
                      <span className="text-[10px] text-muted-foreground uppercase">{sc.category}</span>
                      {!sc.available && (
                        <span className="text-[10px] text-muted-foreground italic">{t("settings.scannerUnavailable")}</span>
                      )}
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={!isDisabled}
                      disabled={!sc.available}
                      onClick={() => toggleScanner(sc.name, !isDisabled)}
                      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none disabled:opacity-30 disabled:cursor-not-allowed ${
                        !isDisabled ? "bg-primary" : "bg-input"
                      }`}
                    >
                      <span className={`pointer-events-none block h-3.5 w-3.5 rounded-full bg-background shadow-lg ring-0 transition-transform ${
                        !isDisabled ? "translate-x-4" : "translate-x-0"
                      }`} />
                    </button>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* DeepSeek API 配置 */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <CardTitle>{t("settings.deepseekConfig")}</CardTitle>
          </div>
          <CardDescription>{t("settings.deepseekConfigDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <p className="text-xs font-medium mb-1">{t("settings.deepseekApiKey")}</p>
            <p className="text-[10px] text-muted-foreground mb-1.5">{t("settings.deepseekApiKeyDesc")}</p>
            <Input
              type="password"
              value={settings.deepseekApiKey}
              onChange={e => setSettings(s => ({ ...s, deepseekApiKey: e.target.value }))}
              className="h-8 text-xs font-mono"
              placeholder="sk-..."
            />
          </div>
          <div>
            <p className="text-xs font-medium mb-1">{t("settings.deepseekBaseUrl")}</p>
            <p className="text-[10px] text-muted-foreground mb-1.5">{t("settings.deepseekBaseUrlDesc")}</p>
            <Input
              type="text"
              value={settings.deepseekBaseUrl}
              onChange={e => setSettings(s => ({ ...s, deepseekBaseUrl: e.target.value }))}
              className="h-8 text-xs font-mono"
              placeholder="https://api.deepseek.com"
            />
          </div>
          <div>
            <p className="text-xs font-medium mb-1">{t("settings.deepseekModel")}</p>
            <p className="text-[10px] text-muted-foreground mb-1.5">{t("settings.deepseekModelDesc")}</p>
            <select
              value={settings.deepseekModel}
              onChange={e => setSettings(s => ({ ...s, deepseekModel: e.target.value }))}
              className="h-8 rounded-lg border border-border bg-background px-2.5 text-xs text-foreground w-full"
            >
              <option value="deepseek-v4-flash">{t("settings.modelFlash")}</option>
              <option value="deepseek-v4-pro">{t("settings.modelPro")}</option>
            </select>
          </div>
        </CardContent>
      </Card>

      {/* 代理设置 */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-primary" />
            <CardTitle>{t("settings.proxySettings")}</CardTitle>
          </div>
          <CardDescription>{t("settings.proxySettingsDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <p className="text-xs font-medium">{t("settings.proxyEnabled")}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{t("settings.proxyEnabledDesc")}</p>
            </div>
            <Toggle
              id="proxyEnabled"
              value={settings.proxyEnabled}
              onChange={v => setSettings(s => ({ ...s, proxyEnabled: v }))}
            />
          </div>
          {settings.proxyEnabled && (
            <>
              <div>
                <p className="text-xs font-medium mb-1">{t("settings.httpProxy")}</p>
                <p className="text-[10px] text-muted-foreground mb-1.5">{t("settings.httpProxyDesc")}</p>
                <Input
                  type="text"
                  value={settings.httpProxy}
                  onChange={e => setSettings(s => ({ ...s, httpProxy: e.target.value }))}
                  className="h-8 text-xs font-mono"
                  placeholder="http://127.0.0.1:7897"
                />
              </div>
              <div>
                <p className="text-xs font-medium mb-1">{t("settings.httpsProxy")}</p>
                <p className="text-[10px] text-muted-foreground mb-1.5">{t("settings.httpsProxyDesc")}</p>
                <Input
                  type="text"
                  value={settings.httpsProxy}
                  onChange={e => setSettings(s => ({ ...s, httpsProxy: e.target.value }))}
                  className="h-8 text-xs font-mono"
                  placeholder="http://127.0.0.1:7897"
                />
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* 通知设置 */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Bell className="h-4 w-4 text-primary" />
            <CardTitle>{t("settings.notificationSettings")}</CardTitle>
          </div>
          <CardDescription>{t("settings.notificationSettingsDesc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <p className="text-xs font-medium">{t("settings.webhookEnabled")}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{t("settings.webhookEnabledDesc")}</p>
            </div>
            <Toggle
              id="webhookEnabled"
              value={settings.webhookEnabled}
              onChange={v => setSettings(s => ({ ...s, webhookEnabled: v }))}
            />
          </div>
          {settings.webhookEnabled && (
            <div>
              <p className="text-xs font-medium mb-1">{t("settings.webhookUrl")}</p>
              <p className="text-[10px] text-muted-foreground mb-1.5">{t("settings.webhookUrlDesc")}</p>
              <Input
                type="url"
                value={settings.webhookUrl}
                onChange={e => setSettings(s => ({ ...s, webhookUrl: e.target.value }))}
                className="h-8 text-xs font-mono"
                placeholder="https://hooks.example.com/scan-complete"
              />
            </div>
          )}
        </CardContent>
      </Card>

      {/* 检查更新 */}
      <Card>
        <CardHeader>
          <CardTitle>检查更新</CardTitle>
          <CardDescription>检查 GitHub 上的最新版本</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Tag className="h-3.5 w-3.5" />
            当前版本：v{typeof window !== "undefined" ? (window as any).vulnguard?.version || "0.3.0" : "0.3.0"}
          </div>
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={async () => {
              const btn = document.activeElement as HTMLButtonElement
              btn.disabled = true
              try {
                const res: any = await (window as any).vulnguard?.checkForUpdates()
                if (res?.canUpdate) alert(`新版本 v${res.version} 可用，请在主界面上方查看`)
                else if (res?.ok) alert("已是最新版本")
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
