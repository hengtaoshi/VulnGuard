"use client"

import { useState, useEffect, useCallback } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { useI18n } from "@/lib/i18n/context"
import {
  Loader2, CheckCircle2, AlertCircle, Cpu, Server, Sliders,
} from "lucide-react"
import { InstallDialog } from "@/components/scanner/install-dialog"
import { SetupWizard } from "@/components/scanner/setup-wizard"

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

interface AppSettings {
  disabledScanners: string[]
  concurrentScanners: number
}

export default function ScannersPage() {
  const { t } = useI18n()
  const [scanners, setScanners] = useState<ScannerInfo[]>([])
  const [scannersLoading, setScannersLoading] = useState(true)
  const [settings, setSettings] = useState<AppSettings>({ disabledScanners: [], concurrentScanners: 4 })
  const [installTarget, setInstallTarget] = useState<{ name: string; label: string } | null>(null)
  const [showWizard, setShowWizard] = useState(false)

  useEffect(() => {
    fetch("/api/scanners")
      .then(r => r.json())
      .then(data => { setScanners(data); setScannersLoading(false) })
      .catch(() => setScannersLoading(false))
    fetch("/api/settings")
      .then(r => r.json())
      .then(data => setSettings(data))
      .catch(() => {})
  }, [])

  const toggleScanner = useCallback((name: string, disabled: boolean) => {
    setSettings(prev => {
      const list = disabled
        ? [...new Set([...prev.disabledScanners, name])]
        : prev.disabledScanners.filter(n => n !== name)
      return { ...prev, disabledScanners: list }
    })
    fetch("/api/settings", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ disabledScanners: settings.disabledScanners }),
    })
  }, [settings.disabledScanners])

  const handleInstallComplete = () => {
    setInstallTarget(null)
    fetch("/api/scanners")
      .then(r => r.json())
      .then(data => setScanners(data))
  }

  const disabledCount = settings.disabledScanners.length

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("settings.scannerManagement")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{t("settings.scannerManagementDesc")}</p>
        </div>
        <button
          onClick={() => setShowWizard(true)}
          className="rounded-md bg-primary/10 px-3 py-1.5 text-sm font-medium text-primary hover:bg-primary/20 transition-colors shrink-0"
        >
          {t("settings.batchInstall")}
        </button>
      </div>

      {/* 并发扫描数 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="h-4 w-4 text-primary" />
            <CardTitle className="text-sm">{t("settings.concurrentScanners")}</CardTitle>
          </div>
          <CardDescription className="text-xs">{t("settings.concurrentScannersDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            {[2, 4, 6, 8].map(n => (
              <button
                key={n}
                onClick={() => {
                  setSettings(s => ({ ...s, concurrentScanners: n }))
                  fetch("/api/settings", {
                    method: "PATCH",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({ concurrentScanners: n }),
                  })
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  settings.concurrentScanners === n
                    ? "bg-primary text-primary-foreground"
                    : "bg-accent text-muted-foreground hover:text-foreground"
                }`}
              >
                {n}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* 扫描器列表 */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              <CardTitle className="text-sm">{t("settings.scannerAllEnabled")}</CardTitle>
            </div>
            {disabledCount > 0 && (
              <span className="text-xs text-muted-foreground">
                {t("settings.scannerDisabledCount", { count: disabledCount })}
              </span>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {scannersLoading ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" /> {t("common.loading")}
            </div>
          ) : (
            <div className="space-y-1">
              <div className="hidden sm:flex items-center justify-between text-xs text-muted-foreground px-2 py-1">
                <div className="flex items-center gap-2 flex-1">
                  <span className="w-3" />
                  <span>{t("dashboard.type")}</span>
                </div>
                <span className="w-16 text-right">{t("reports.status")}</span>
              </div>
              {scanners.map(sc => {
                const isDisabled = settings.disabledScanners.includes(sc.name)
                return (
                  <div key={sc.name} className="flex items-center justify-between rounded-lg px-2 py-1.5 hover:bg-accent/50 transition-colors">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${sc.available ? "bg-emerald-500" : "bg-muted"}`} />
                      <span className="text-xs font-medium">{sc.displayName}</span>
                      <span className="text-[10px] text-muted-foreground uppercase">{sc.category}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {!sc.available ? (
                        <button
                          onClick={() => setInstallTarget({ name: sc.name, label: sc.displayName })}
                          className="rounded-md bg-primary/10 px-2 py-1 text-[10px] font-medium text-primary hover:bg-primary/20 transition-colors"
                        >
                          {t("settings.install")}
                        </button>
                      ) : (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={!isDisabled}
                          onClick={() => toggleScanner(sc.name, !isDisabled)}
                          className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none ${
                            !isDisabled ? "bg-primary" : "bg-input"
                          }`}
                        >
                          <span className={`pointer-events-none block h-3.5 w-3.5 rounded-full bg-background shadow-lg ring-0 transition-transform ${
                            !isDisabled ? "translate-x-4" : "translate-x-0"
                          }`} />
                        </button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {installTarget && (
        <InstallDialog
          scannerName={installTarget.name}
          scannerLabel={installTarget.label}
          open={!!installTarget}
          onClose={() => setInstallTarget(null)}
          onComplete={handleInstallComplete}
        />
      )}

      <SetupWizard
        open={showWizard}
        onFinish={() => {
          setShowWizard(false)
          fetch("/api/scanners")
            .then(r => r.json())
            .then(data => setScanners(data))
        }}
      />
    </div>
  )
}
