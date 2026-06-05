"use client"

import { useState, useCallback } from "react"
import { useRouter } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Globe, Upload, Check, ChevronRight, Loader2, FolderOpen, AlertCircle } from "lucide-react"
import { useI18n } from "@/lib/i18n/context"

export default function NewScanPage() {
  const router = useRouter()
  const { t } = useI18n()
  const [mode, setMode] = useState<"url" | "source">("source")
  const [target, setTarget] = useState("")
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState("")

  const handleScan = useCallback(async () => {
    if (!target.trim()) return
    setScanning(true)
    setError("")

    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), mode }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.error || "扫描失败")
      }
      const { id } = await res.json()
      router.push(`/scan/${id}`)
    } catch (err) {
      setScanning(false)
      setError(err instanceof Error ? err.message : "扫描启动失败")
    }
  }, [target, mode, router])

  const handleQuickScan = useCallback(async () => {
    setTarget("")
    setScanning(true)
    setError("")

    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: "test-target", mode: "source" }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.error || "扫描失败")
      }
      const { id } = await res.json()
      router.push(`/scan/${id}`)
    } catch (err) {
      setScanning(false)
      setError(err instanceof Error ? err.message : "扫描启动失败")
    }
  }, [router])

  const scanModules = [
    { id: "owasp", labelKey: "scan.new.moduleOwasp", color: "destructive" as const },
    { id: "sca", labelKey: "scan.new.moduleSca", color: "warning" as const },
    { id: "infra", labelKey: "scan.new.moduleInfra", color: "info" as const },
    { id: "logic", labelKey: "scan.new.moduleLogic", color: "secondary" as const },
    { id: "attack", labelKey: "scan.new.moduleAttack", color: "default" as const },
    { id: "quality", labelKey: "scan.new.moduleQuality", color: "success" as const },
  ]

  if (scanning) {
    return (
      <div className="max-w-3xl mx-auto">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-20">
            <Loader2 className="h-10 w-10 animate-spin text-primary mb-6" />
            <h3 className="text-lg font-semibold mb-2">正在执行安全扫描</h3>
            <p className="text-sm text-muted-foreground mb-1">目标: {target || "test-target"}</p>
            <p className="text-sm text-muted-foreground">基于 Semgrep 引擎进行静态代码分析...</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Mode Selection */}
      <Card>
        <CardHeader>
          <CardTitle>{t("scan.new.scanMode")}</CardTitle>
          <CardDescription>{t("scan.new.scanModeDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4">
            <button
              onClick={() => setMode("url")}
              role="radio"
              aria-checked={mode === "url"}
              aria-label={t("scan.new.urlScan")}
              className={`relative rounded-xl border-2 p-6 text-left transition-all ${
                mode === "url"
                  ? "border-primary bg-primary/5"
                  : "border-border hover:border-muted-foreground/30"
              }`}
            >
              {mode === "url" && (
                <div className="absolute top-3 right-3 h-5 w-5 rounded-full bg-primary flex items-center justify-center">
                  <Check className="h-3 w-3 text-primary-foreground" />
                </div>
              )}
              <Globe className="h-8 w-8 text-primary mb-3" />
              <h3 className="font-semibold mb-1">{t("scan.new.urlScan")}</h3>
              <p className="text-sm text-muted-foreground">{t("scan.new.urlScanDesc")}</p>
            </button>
            <button
              onClick={() => setMode("source")}
              role="radio"
              aria-checked={mode === "source"}
              aria-label={t("scan.new.sourceScan")}
              className={`relative rounded-xl border-2 p-6 text-left transition-all ${
                mode === "source"
                  ? "border-primary bg-primary/5"
                  : "border-border hover:border-muted-foreground/30"
              }`}
            >
              {mode === "source" && (
                <div className="absolute top-3 right-3 h-5 w-5 rounded-full bg-primary flex items-center justify-center">
                  <Check className="h-3 w-3 text-primary-foreground" />
                </div>
              )}
              <FolderOpen className="h-8 w-8 text-blue-500 mb-3" />
              <h3 className="font-semibold mb-1">{t("scan.new.sourceScan")}</h3>
              <p className="text-sm text-muted-foreground">{t("scan.new.sourceScanDesc")}</p>
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Input Area */}
      <Card>
        <CardHeader>
          <CardTitle>{mode === "url" ? t("scan.new.targetUrl") : t("scan.new.uploadSource")}</CardTitle>
          <CardDescription>
            {mode === "url" ? t("scan.new.targetUrlDesc") : "输入本地源码目录路径进行 Semgrep 静态分析"}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {mode === "url" ? (
            <div className="flex gap-3">
              <Input
                placeholder={t("scan.new.placeholder")}
                value={target}
                onChange={e => setTarget(e.target.value)}
                className="flex-1"
              />
              <Button disabled={!target || scanning} onClick={handleScan}>
                {t("scan.new.scanBtn")}
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <Input
                placeholder="例如: D:\project\src 或 /home/user/project"
                value={target}
                onChange={e => setTarget(e.target.value)}
                className="flex-1"
              />
              <div className="flex gap-3">
                <Button disabled={!target || scanning} onClick={handleScan} className="gap-2">
                  {t("scan.new.scanBtn")}
                </Button>
                <Button variant="outline" onClick={handleQuickScan} disabled={scanning}>
                  快速扫描 (Demo)
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                使用 Semgrep 引擎进行 OWASP Top 10 静态代码安全分析。
                支持 JavaScript, TypeScript, Python, Java, Go 等 30+ 语言。
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {error && (
        <Card className="border-destructive/50">
          <CardContent className="flex items-center gap-3 p-4">
            <AlertCircle className="h-5 w-5 text-destructive shrink-0" />
            <p className="text-sm text-destructive">{error}</p>
          </CardContent>
        </Card>
      )}

      {/* Scan Modules Selection */}
      <Card>
        <CardHeader>
          <CardTitle>{t("scan.new.scanModules")}</CardTitle>
          <CardDescription>{t("scan.new.scanModulesDesc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {scanModules.map(mod => (
              <Badge key={mod.id} variant={mod.color} className="cursor-pointer px-3 py-1.5 text-sm">
                {t(mod.labelKey)}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Start Scan Button */}
      <div className="flex justify-end">
        <Button size="lg" className="gap-2" onClick={handleQuickScan}>
          {t("scan.new.startScan")}
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  )
}
