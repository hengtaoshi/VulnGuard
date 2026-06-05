"use client"

import { useEffect, useState, useCallback, useRef } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ChevronDown, Loader2, AlertCircle, Sparkles, Brain, AlertTriangle, CheckCircle2, Lightbulb, Shield, Search, Eye, Lock, Package, FileScan } from "lucide-react"
import { useI18n } from "@/lib/i18n/context"
import { useLLMAnalysis } from "@/lib/api/hooks"
import type { ScanDetail, ScanProgress } from "@/lib/api/types"

const POLL_INTERVAL = 1000

function SeverityBadge({ severity }: { severity: string }) {
  const { t } = useI18n()
  const variantMap: Record<string, "destructive" | "warning" | "info" | "success"> = {
    Critical: "destructive",
    High: "warning",
    Medium: "info",
    Low: "success",
  }
  const labelMap: Record<string, string> = {
    Critical: t("severity.critical"),
    High: t("severity.high"),
    Medium: t("severity.medium"),
    Low: t("severity.low"),
  }
  return <Badge variant={variantMap[severity] || "outline"}>{labelMap[severity] || severity}</Badge>
}

const scannerColors: Record<string, string> = {
  sast: "bg-blue-500/10 text-blue-500 border-blue-500/20",
  secret: "bg-red-500/10 text-red-500 border-red-500/20",
  dependency: "bg-amber-500/10 text-amber-500 border-amber-500/20",
  filesystem: "bg-purple-500/10 text-purple-500 border-purple-500/20",
}

const scannerIcons: Record<string, React.ReactNode> = {
  semgrep: <Search className="h-3 w-3" />,
  gitleaks: <Lock className="h-3 w-3" />,
  "npm-audit": <Package className="h-3 w-3" />,
  "pip-audit": <Package className="h-3 w-3" />,
  trivy: <FileScan className="h-3 w-3" />,
  wapiti: <Shield className="h-3 w-3" />,
  sqlmap: <Search className="h-3 w-3" />,
}

const defaultScannerIcon = <Shield className="h-3 w-3" />

function ScanProgressView({ progress }: { progress: ScanProgress | null }) {
  const percent = progress?.percent ?? 0
  const currentScanner = progress?.currentScanner ?? ""
  const scannerStatuses = progress?.scannerStatuses ?? []

  return (
    <div className="space-y-8 w-full max-w-lg mx-auto">
      <div className="text-center space-y-4">
        <Loader2 className="h-10 w-10 animate-spin mx-auto text-primary" />
        <div>
          <h2 className="text-xl font-bold">Security Scan In Progress</h2>
          {currentScanner && (
            <p className="text-muted-foreground mt-1">
              Scanning with: <span className="font-medium text-foreground">{currentScanner}</span>
            </p>
          )}
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex justify-between text-sm">
          <span className="text-muted-foreground">Progress</span>
          <span className="font-medium">{percent}%</span>
        </div>
        <div className="h-3 bg-muted rounded-full overflow-hidden">
          <div
            className="h-full bg-primary rounded-full transition-all duration-500 ease-out"
            style={{ width: `${percent}%` }}
          />
        </div>
      </div>

      {scannerStatuses.length > 0 && (
        <div className="space-y-2">
          {scannerStatuses.map(s => (
            <div key={s.scannerName} className="flex items-center gap-3 p-2 rounded-lg border border-border/50">
              {s.status === "completed" && <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />}
              {s.status === "running" && <Loader2 className="h-4 w-4 animate-spin text-primary shrink-0" />}
              {s.status === "pending" && <div className="h-4 w-4 rounded-full border-2 border-muted-foreground/30 shrink-0" />}
              {s.status === "failed" && <AlertCircle className="h-4 w-4 text-destructive shrink-0" />}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`inline-flex items-center justify-center h-5 w-5 rounded ${s.status === "completed" ? "bg-emerald-500/10 text-emerald-500" : s.status === "running" ? "bg-primary/10 text-primary" : s.status === "failed" ? "bg-destructive/10 text-destructive" : "bg-muted text-muted-foreground"}`}>
                    {scannerIcons[s.scannerName] || defaultScannerIcon}
                  </span>
                  <span className={`text-sm font-medium ${s.status === "pending" ? "text-muted-foreground" : ""}`}>
                    {s.displayName}
                  </span>
                </div>
              </div>
              <span className={`text-xs ${s.status === "completed" ? "text-emerald-500" : s.status === "running" ? "text-primary" : s.status === "failed" ? "text-destructive" : "text-muted-foreground"}`}>
                {s.status === "completed" ? `${s.count} issues` : s.status === "running" ? "Scanning..." : s.status === "failed" ? "Failed" : "Pending"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ScanResultsView({ scan }: { scan: ScanDetail }) {
  const { t } = useI18n()
  const llm = useLLMAnalysis()

  const handleAnalyze = () => {
    llm.mutate({
      target: scan.target,
      riskScore: scan.riskScore,
      summary: scan.summary,
      vulnerabilities: scan.vulnerabilities.map(v => ({
        name: v.name,
        severity: v.severity,
        location: v.location,
        description: v.description,
      })),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">
            {t("scan.detail.scanReport")}: {scan.target}
          </h2>
          <p className="text-muted-foreground mt-1">
            {scan.id} · {scan.totalChecks} {t("scan.detail.checksPerformed")}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="destructive" className="text-sm px-3 py-1">
            {t("scan.detail.riskScore")}: {scan.riskScore}
          </Badge>
        </div>
      </div>

      <div className="grid gap-4 grid-cols-2 sm:grid-cols-4">
        <Card className="border-destructive/30">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-destructive">{scan.summary.critical}</div>
            <div className="text-xs text-muted-foreground mt-1">{t("severity.critical")}</div>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-amber-500">{scan.summary.high}</div>
            <div className="text-xs text-muted-foreground mt-1">{t("severity.high")}</div>
          </CardContent>
        </Card>
        <Card className="border-blue-500/30">
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-blue-500">{scan.summary.medium}</div>
            <div className="text-xs text-muted-foreground mt-1">{t("severity.medium")}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-emerald-500">{scan.summary.passed}</div>
            <div className="text-xs text-muted-foreground mt-1">{t("scan.detail.passed")}</div>
          </CardContent>
        </Card>
      </div>

      {scan.scanners && scan.scanners.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4" />
              扫描引擎
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {scan.scanners.map(s => (
                <div key={s.scannerName} className={`rounded-lg border p-3 ${s.count > 0 ? (s.scannerName === "semgrep" ? "border-blue-500/20" : s.scannerName === "gitleaks" ? "border-red-500/20" : s.scannerName === "trivy" ? "border-purple-500/20" : "border-amber-500/20") : "border-border/50"}`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`inline-flex items-center justify-center h-6 w-6 rounded ${s.count > 0 ? (s.category === "secret" ? "bg-red-500/10 text-red-500" : s.category === "dependency" ? "bg-amber-500/10 text-amber-500" : s.category === "filesystem" ? "bg-purple-500/10 text-purple-500" : "bg-blue-500/10 text-blue-500") : "bg-muted text-muted-foreground"}`}>
                      {s.scannerName === "semgrep" ? <Search className="h-3 w-3" /> : s.scannerName === "gitleaks" ? <Lock className="h-3 w-3" /> : s.scannerName === "npm-audit" || s.scannerName === "pip-audit" ? <Package className="h-3 w-3" /> : s.scannerName === "trivy" ? <FileScan className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
                    </span>
                    <span className="text-sm font-medium">{s.displayName}</span>
                    <span className="text-xs text-muted-foreground ml-auto">
                      {s.category === "sast" ? "SAST" : s.category === "secret" ? "密钥" : s.category === "dependency" ? "依赖" : "文件系统"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mt-2">
                    <span className={`text-lg font-bold ${s.count > 0 ? "text-foreground" : "text-muted-foreground"}`}>
                      {s.count > 0 ? `${s.count} 个问题` : "无问题"}
                    </span>
                    {s.errors && s.errors.length > 0 && (
                      <span className="text-xs text-destructive" title={s.errors[0]}>异常</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t("scan.detail.vulnerabilities")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {scan.vulnerabilities.map(vuln => (
            <details key={vuln.id} className="group border border-border rounded-lg overflow-hidden">
              <summary className="flex items-center gap-3 p-4 cursor-pointer hover:bg-accent/50 transition-colors list-none">
                <ChevronDown className="h-4 w-4 text-muted-foreground group-open:rotate-180 transition-transform shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium">{vuln.name}</span>
                    <SeverityBadge severity={vuln.severity} />
                    {vuln.source && (
                      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${scannerColors[vuln.source === "gitleaks" ? "secret" : vuln.source === "npm-audit" || vuln.source === "pip-audit" ? "dependency" : vuln.source === "trivy" ? "filesystem" : "sast"]}`}>
                        {scannerIcons[vuln.source] || defaultScannerIcon}
                        {vuln.source}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5 font-mono">{vuln.location}</p>
                </div>
                {vuln.cve !== "—" && (
                  <Badge variant="outline" className="text-[10px]">{vuln.cve}</Badge>
                )}
                <code className="text-xs text-muted-foreground">{vuln.id}</code>
              </summary>
              <div className="px-4 pb-4 border-t border-border pt-4 space-y-4">
                <div>
                  <h4 className="text-sm font-medium mb-1">{t("scan.detail.description")}</h4>
                  <p className="text-sm text-muted-foreground">{vuln.description}</p>
                </div>
                <div>
                  <h4 className="text-sm font-medium text-emerald-500 mb-1">{t("scan.detail.fixRecommendation")}</h4>
                  <p className="text-sm text-muted-foreground mb-2">{vuln.recommendation}</p>
                  {vuln.code && (
                    <pre className="bg-black/40 rounded-lg p-4 overflow-x-auto text-sm">
                      <code className="text-xs">{vuln.code}</code>
                    </pre>
                  )}
                </div>
              </div>
            </details>
          ))}
        </CardContent>
      </Card>

      <Card className="border-violet-500/30">
        <CardHeader className="flex flex-row items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-violet-500/10 flex items-center justify-center">
              <Brain className="h-5 w-5 text-violet-500" />
            </div>
            <div>
              <CardTitle className="flex items-center gap-2">
                {t("ai.analysis")}
                <span className="text-[10px] font-normal px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-500">DeepSeek</span>
              </CardTitle>
              <p className="text-sm text-muted-foreground">{t("ai.analysisDesc")}</p>
            </div>
          </div>
          {!llm.data && !llm.isPending && (
            <button
              onClick={handleAnalyze}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-500/10 hover:bg-violet-500/20 text-violet-500 text-sm font-medium transition-colors"
            >
              <Sparkles className="h-4 w-4" />
              {t("ai.analyze")}
            </button>
          )}
        </CardHeader>
        <CardContent>
          {llm.isPending && (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-3" />
              <span>{t("ai.analyzing")}</span>
            </div>
          )}
          {llm.error && (
            <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
              <AlertCircle className="h-10 w-10 mb-3 text-destructive" />
              <p className="font-medium">{t("ai.error")}</p>
              <p className="text-sm mt-1">{t("ai.errorDesc")}</p>
              <button
                onClick={handleAnalyze}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-sm font-medium hover:bg-accent transition-colors"
              >
                {t("ai.retry")}
              </button>
            </div>
          )}
          {llm.data && (
            <div className="space-y-6">
              <div>
                <h4 className="flex items-center gap-2 text-sm font-semibold mb-2">
                  <Shield className="h-4 w-4 text-violet-500" />
                  {t("ai.riskAssessment")}
                </h4>
                <p className="text-sm text-muted-foreground leading-relaxed bg-muted/50 rounded-lg p-4">{llm.data.riskAssessment}</p>
              </div>
              <div className="grid gap-6 sm:grid-cols-2">
                <div>
                  <h4 className="flex items-center gap-2 text-sm font-semibold mb-2">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    {t("ai.priorityFixes")}
                  </h4>
                  <ul className="space-y-2">
                    {llm.data.priorityFixes.map((fix, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 shrink-0" />
                        <span>{fix}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h4 className="flex items-center gap-2 text-sm font-semibold mb-2">
                    <AlertCircle className="h-4 w-4 text-destructive" />
                    {t("ai.architectureRisks")}
                  </h4>
                  <ul className="space-y-2">
                    {llm.data.architectureRisks.map((risk, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <span className="text-destructive mt-0.5 shrink-0">•</span>
                        <span>{risk}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              {llm.data.complianceNotes.length > 0 && (
                <div>
                  <h4 className="flex items-center gap-2 text-sm font-semibold mb-2">
                    <Shield className="h-4 w-4 text-blue-500" />
                    {t("ai.complianceNotes")}
                  </h4>
                  <ul className="space-y-1">
                    {llm.data.complianceNotes.map((note, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                        <span className="text-blue-500 mt-0.5 shrink-0">•</span>
                        <span>{note}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <div className="border-t border-border pt-4">
                <h4 className="flex items-center gap-2 text-sm font-semibold mb-2">
                  <Lightbulb className="h-4 w-4 text-amber-500" />
                  {t("ai.overallAdvice")}
                </h4>
                <p className="text-sm text-muted-foreground leading-relaxed bg-amber-500/5 border border-amber-500/10 rounded-lg p-4">{llm.data.overallAdvice}</p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  const { t } = useI18n()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const prePollRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    const id = params.id
    if (!id) return

    setLoading(true)
    setError("")

    const fetchScan = () => {
      fetch(`/api/scans/${id}`)
        .then(r => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`)
          return r.json() as Promise<ScanDetail>
        })
        .then(data => {
          setScan(data)
          setLoading(false)
          // Stop polling when done
          if (data.status === "completed" || data.status === "failed") {
            if (timerRef.current) clearInterval(timerRef.current)
            timerRef.current = null
          }
        })
        .catch(err => {
          if (!loading) return // only set error on first load
          setError(err.message)
          setLoading(false)
        })
    }

    // First fetch immediately
    fetchScan()

    // Then poll every second
    timerRef.current = setInterval(fetchScan, POLL_INTERVAL)

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [params.id])

  const isInProgress = !scan || scan.status === "pending" || scan.status === "scanning"

  if (isInProgress) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <ScanProgressView progress={scan?.progress ?? null} />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
        <AlertCircle className="h-10 w-10 mb-3 text-destructive" />
        <p className="font-medium">{t("common.failedToLoad")}</p>
        <p className="text-sm mt-1">{error}</p>
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex items-center justify-center py-20 text-muted-foreground">
        <Loader2 className="h-6 w-6 animate-spin mr-3" />
        <span>{t("common.loading")}</span>
      </div>
    )
  }

  return <ScanResultsView scan={scan} />
}
