"use client"

import { useState, useEffect, useCallback, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useI18n } from "@/lib/i18n/context"
import {
  Loader2, CheckCircle2, AlertCircle, Trash2, RotateCcw,
  Download, Tag, Shield, Globe, Bell, Cpu, Key, Server,
  Sliders, Gauge, ScrollText, Database, Zap, Wrench,
} from "lucide-react"
import { UpdateDialog } from "@/components/update-dialog"

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
import type { AppSettings } from "@/lib/settings-store"
import { useRouter } from "next/navigation"
import { InstallDialog } from "@/components/scanner/install-dialog"
import { SetupWizard } from "@/components/scanner/setup-wizard"

const DEFAULT_SETTINGS: AppSettings = {
  maxDuration: 30,
  autoReport: true,
  defaultEngine: "ai",
  aiAggregation: true,
  concurrentScanners: 4,
  retentionDays: 0,
  deepseekApiKey: "",
  deepseekBaseUrl: "",
  deepseekModel: "deepseek-v4-flash",
  proxyEnabled: false,
  httpProxy: "",
  httpsProxy: "",
  webhookEnabled: false,
  webhookUrl: "",
  disabledScanners: [],
}

function InlineSelect({ value, options, onChange }: { value: string; options: { value: string; label: string }[]; onChange: (v: string) => void }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [])

  const selected = options.find(o => o.value === value)
  return (
    <div ref={ref} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 h-8 rounded-lg border border-border bg-card px-2.5 text-xs text-foreground hover:bg-accent transition-colors whitespace-nowrap"
      >
        {selected?.label || value}
        <svg className="h-3 w-3 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-50 min-w-[140px] rounded-lg border border-border bg-card shadow-xl overflow-hidden">
          {options.map(opt => (
            <button
              key={opt.value}
              type="button"
              onClick={() => { onChange(opt.value); setOpen(false) }}
              className={`w-full px-3 py-1.5 text-xs text-left transition-colors hover:bg-accent ${
                opt.value === value ? "text-primary font-medium" : "text-foreground"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
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
  const [scanners, setScanners] = useState<ScannerInfo[]>([])
  const [scannersLoading, setScannersLoading] = useState(true)
  const [installTarget, setInstallTarget] = useState<{ name: string; label: string } | null>(null)
  const [showWizard, setShowWizard] = useState(false)

  // Update dialog state
  const [updateDialogOpen, setUpdateDialogOpen] = useState(false)
  const [updateInfo, setUpdateInfo] = useState<{ version: string; currentVersion: string } | null>(null)
  const [updateError, setUpdateError] = useState<string | null>(null)
  const [updateChecking, setUpdateChecking] = useState(false)
  const [updateLatest, setUpdateLatest] = useState(false)

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

  const handleInstallComplete = useCallback((ok: boolean) => {
    setInstallTarget(null)
    if (ok) {
      fetch("/api/scanners")
        .then(r => r.json())
        .then(data => setScanners(data))
        .catch(() => {})
    }
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

  const handleCheckUpdate = useCallback(async () => {
    const vg = window.vulnguard
    if (!vg) {
      setUpdateError("更新检查仅在桌面版可用")
      setUpdateInfo(null)
      setUpdateDialogOpen(true)
      return
    }

    setUpdateChecking(true)
    setUpdateError(null)
    setUpdateInfo(null)
    setUpdateDialogOpen(true)

    try {
      const res = await vg.checkForUpdates()
      if (res.ok && res.canUpdate && res.version) {
        setUpdateInfo({
          version: res.version,
          currentVersion: vg.version || "?",
        })
      } else if (res.ok) {
        // Already latest — close dialog, show brief inline success
        setUpdateDialogOpen(false)
        setUpdateLatest(true)
        setTimeout(() => setUpdateLatest(false), 3000)
      } else {
        setUpdateError(res.error || "检查更新失败")
      }
    } catch (e: any) {
      setUpdateError(e.message || "检查更新失败")
    } finally {
      setUpdateChecking(false)
    }
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        <span className="text-sm">{t("common.loading")}</span>
      </div>
    )
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header + Save bar */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{t("settings.title")}</h1>
          <p className="text-sm text-muted-foreground">{t("settings.desc")}</p>
        </div>
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
      </div>

      {/* 2-column grid for main settings cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* 扫描配置 — full width */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center gap-2">
              <Sliders className="h-4 w-4 text-primary" />
              <CardTitle>{t("settings.scanConfig")}</CardTitle>
            </div>
            <CardDescription>{t("settings.scanConfigDesc")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-5">
              {/* 最大扫描时长 */}
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
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

              {/* 默认扫描引擎 */}
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm">{t("settings.defaultEngine")}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{t("settings.defaultEngineDesc")}</p>
                </div>
                <InlineSelect
                  value={settings.defaultEngine}
                  options={[
                    { value: "ai", label: t("settings.engineAi") },
                    { value: "all", label: t("settings.engineAll") },
                  ]}
                  onChange={v => setSettings(s => ({ ...s, defaultEngine: v as "ai" | "all" }))}
                />
              </div>

              {/* 并行扫描器数 */}
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
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

              {/* 数据保留 */}
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
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

              {/* 自动报告 */}
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
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

              {/* AI 聚合分析 */}
              <div className="flex items-center justify-between gap-4">
                <div className="flex-1 min-w-0">
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
            </div>
          </CardContent>
        </Card>

        {/* DeepSeek API 配置 */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Key className="h-4 w-4 text-primary" />
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
              <InlineSelect
                value={settings.deepseekModel}
                options={[
                  { value: "deepseek-v4-flash", label: t("settings.modelFlash") },
                  { value: "deepseek-v4-pro", label: t("settings.modelPro") },
                ]}
                onChange={v => setSettings(s => ({ ...s, deepseekModel: v }))}
              />
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
              <div className="flex-1 min-w-0">
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
              <div className="flex-1 min-w-0">
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
            <div className="flex items-center gap-2">
              <Download className="h-4 w-4 text-primary" />
              <CardTitle>{t("settings.checkUpdates")}</CardTitle>
            </div>
            <CardDescription>{t("settings.checkUpdatesDesc")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Tag className="h-3.5 w-3.5" />
              当前版本：v{typeof window !== "undefined" ? (window as any).vulnguard?.version || "?" : "?"}
            </div>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              disabled={updateChecking}
              onClick={handleCheckUpdate}
            >
              {updateChecking ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Download className="h-3.5 w-3.5" />
              )}
              {updateChecking ? "检查中…" : t("settings.checkUpdates")}
            </Button>
            {updateLatest && (
              <span className="inline-flex items-center gap-1 text-xs text-emerald-500">
                <CheckCircle2 className="h-3 w-3" /> 已是最新版本
              </span>
            )}
          </CardContent>
        </Card>

      </div>

      {/* 危险区域 */}
      <Card className="border-destructive/20">
        <CardHeader>
          <CardTitle className="text-destructive flex items-center gap-2">
            <Trash2 className="h-4 w-4" />
            {t("settings.clearData")}
          </CardTitle>
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

      {/* 扫描器安装对话框 */}
      {installTarget && (
        <InstallDialog
          scannerName={installTarget.name}
          scannerLabel={installTarget.label}
          open={!!installTarget}
          onClose={() => setInstallTarget(null)}
          onComplete={handleInstallComplete}
        />
      )}

      {/* 首次启动 / 批量安装向导 */}
      <SetupWizard
        open={showWizard}
        onFinish={() => {
          setShowWizard(false)
          fetch("/api/scanners")
            .then(r => r.json())
            .then(data => setScanners(data))
            .catch(() => {})
        }}
      />

      {/* 更新对话框 */}
      <UpdateDialog
        open={updateDialogOpen}
        onClose={() => setUpdateDialogOpen(false)}
        info={updateInfo}
        error={updateError}
        onRetry={handleCheckUpdate}
      />
    </div>
  )
}
