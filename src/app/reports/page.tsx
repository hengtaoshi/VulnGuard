// @ts-nocheck
"use client"

import { useState, useMemo, useCallback } from "react"
import { useRouter } from "next/navigation"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Shield, AlertTriangle, CheckCircle2, Loader2, Search,
  ChevronDown, ChevronRight, ExternalLink, Trash2, FileText,
  Bug, MapPin, Lightbulb, AlertCircle, BarChart3, Clock, Brain,
  FileScan, XCircle, Filter, FileDown,
} from "lucide-react"
import { openHtmlReport } from "@/lib/report-html"
import { useI18n } from "@/lib/i18n/context"
import { useScans, useDeleteScan } from "@/lib/api/hooks"
import type { ScanSummary, ScanDetail, Vulnerability } from "@/lib/api/types"
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
const SEVERITY_STYLES = {
  Critical: { badge: "destructive" },
  High: { badge: "warning" },
  Medium: { badge: "info" },
  Low: { badge: "success" },
}
function sColor(sev) {
  const m = { Critical: "#ef4444", High: "#f59e0b", Medium: "#3b82f6", Low: "#22c55e" }
  return m[sev] || "#666"
}

function computeVulnStats(vulns) {
  const r = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const v of vulns) {
    const k = v.severity.toLowerCase()
    if (k in r) r[k]++
  }
  return r
}

// generateReportHtml 已移至 @/lib/report-html
// openHtmlReport 已移至 @/lib/report-html

function SeverityBar({ critical, high, medium, low, total }) {
  const tv = critical + high + medium + low
  if (tv === 0) return <div className="h-2 rounded-full bg-muted/50 w-full" />
  return <div className="flex items-center gap-2">
    <div className="h-2 rounded-full overflow-hidden flex flex-1 bg-muted/30">
      {critical > 0 && <div className="bg-destructive h-full" style={{width:(critical/tv)*100+"%"}} />}
      {high > 0 && <div className="bg-orange-500 h-full" style={{width:(high/tv)*100+"%"}} />}
      {medium > 0 && <div className="bg-blue-500 h-full" style={{width:(medium/tv)*100+"%"}} />}
      {low > 0 && <div className="bg-emerald-500 h-full" style={{width:(low/tv)*100+"%"}} />}
    </div>
    <span className="text-xs text-muted-foreground font-mono shrink-0">{tv}/{total}</span>
  </div>
}

function VulnerabilityCard({ vuln, index }) {
  const [expanded, setExpanded] = useState(false)
  const c = sColor(vuln.severity)
  return <div className="border rounded-lg overflow-hidden" style={{borderColor: c + "40"}}>
    <button onClick={() => setExpanded(!expanded)}
      className="w-full flex items-center gap-3 p-3 text-left hover:bg-black/5 transition-colors">
      <span className="text-xs font-mono text-muted-foreground w-6 shrink-0">#{index + 1}</span>
      <Badge variant={SEVERITY_STYLES[vuln.severity]?.badge || "outline"} className="shrink-0 text-[10px] px-1.5 py-0">{vuln.severity}</Badge>
      <span className="flex-1 text-sm font-medium truncate">{vuln.name}</span>
      {expanded ? <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />}
    </button>
    {expanded && <div className="px-3 pb-3 pt-0 space-y-3 border-t border-border/30">
      {vuln.location && <div className="pt-3 flex items-start gap-2"><MapPin className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
        <div><p className="text-xs font-medium text-muted-foreground mb-0.5">位置</p><span className="text-xs bg-black/20 px-1.5 py-0.5 rounded break-all">{vuln.location}</span></div></div>}
      {vuln.description && <div className="flex items-start gap-2"><Bug className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
        <div><p className="text-xs font-medium text-muted-foreground mb-0.5">描述</p><p className="text-sm">{vuln.description}</p></div></div>}
      {vuln.recommendation && <div className="flex items-start gap-2"><Lightbulb className="h-3.5 w-3.5 text-amber-500 mt-0.5 shrink-0" />
        <div><p className="text-xs font-medium text-muted-foreground mb-0.5">修复建议</p><p className="text-sm">{vuln.recommendation}</p></div></div>}
      {(vuln.cve || vuln.source) && <div className="flex items-start gap-2"><AlertCircle className="h-3.5 w-3.5 text-muted-foreground mt-0.5 shrink-0" />
        <div className="flex gap-3 text-xs text-muted-foreground">
          {vuln.cve && vuln.cve !== "—" && (
            vuln.isRealCve
              ? <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`} target="_blank" rel="noopener noreferrer" className="text-red-400 hover:text-red-300 underline underline-offset-2">CVE: {vuln.cve}</a>
              : <span>CVE: {vuln.cve}</span>
          )}
          {vuln.source && <span>来源: {vuln.source}</span>}
        </div></div>}
    </div>}
  </div>
}

function VulnerabilitySection({ severity, vulns }) {
  if (!vulns || vulns.length === 0) return null
  return <div className="space-y-2">
    <div className="flex items-center gap-2 sticky top-0 bg-card z-10 py-1">
      <div className="h-3 w-3 rounded-full" style={{background: sColor(severity)}} />
      <span className="text-sm font-semibold" style={{color: sColor(severity)}}>{severity}</span>
      <Badge variant="outline" className="text-xs ml-1">{vulns.length}</Badge>
    </div>
    <div className="space-y-1.5">{vulns.map((v, i) => <VulnerabilityCard key={v.id || i} vuln={v} index={i} />)}</div>
  </div>
}

function ReportDetail({ scan, onClose }) {
  const router = useRouter()
  const { t } = useI18n()
  const [loading, setLoading] = useState(false)
  const [detail, setDetail] = useState(null)
  useState(() => {
    if (!scan.vulnerabilities || scan.vulnerabilities.length === 0) {
      setLoading(true)
      fetch("/api/scans/" + scan.id).then(r => r.json()).then(d => { setDetail(d); setLoading(false) }).catch(() => setLoading(false))
    } else { setDetail(scan) }
  })
  const vulns = (detail?.vulnerabilities || scan.vulnerabilities || [])
  const groups = { Critical: [], High: [], Medium: [], Low: [] }
  for (const v of vulns) { if (groups[v.severity]) groups[v.severity].push(v) }
  const aggregation = detail?.aiAggregation

  return <div className="space-y-4">
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <h3 className="text-base font-bold">{t("reports.vulnerabilityDetails")}</h3>
        <Badge variant="outline" className="text-xs">{vulns.length} {t("reports.totalFindings")}</Badge>
      </div>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5" onClick={() => openHtmlReport(detail || scan)}>
          <FileText className="h-3.5 w-3.5" />HTML 预览
        </Button>
        <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5" onClick={() => router.push("/scan/" + scan.id)}>
          <ExternalLink className="h-3.5 w-3.5" />{t("reports.viewScan")}
        </Button>
        <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={onClose}>{t("reports.expandedView")}</Button>
      </div>
    </div>
    {aggregation && <Card className="border-violet-500/20 bg-violet-500/[0.02]"><CardContent className="p-3">
      <div className="flex items-start gap-3">
        <div className="h-7 w-7 rounded-lg bg-violet-500/10 flex items-center justify-center shrink-0 mt-0.5"><Brain className="h-3.5 w-3.5 text-violet-500" /></div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1"><span className="text-sm font-semibold">AI {t("ai.aggregation")}</span>
            {aggregation.falsePositivesRemoved > 0 && <Badge variant="outline" className="border-emerald-500/30 text-emerald-500 text-[10px]">-{aggregation.falsePositivesRemoved} {t("reports.falsePositives")}</Badge>}</div>
          {aggregation.summary && <p className="text-sm text-muted-foreground leading-relaxed">{aggregation.summary}</p>}
          {aggregation.priorityActions?.length > 0 && <div className="mt-2"><p className="text-xs font-medium text-muted-foreground mb-1">{t("ai.priorityActions")}:</p>
            <ul className="space-y-0.5">{aggregation.priorityActions.map((a, i) => <li key={i} className="text-xs text-muted-foreground flex items-start gap-1.5"><span className="text-amber-500 mt-0.5">\u2022</span>{a}</li>)}</ul></div>}
        </div>
      </div>
    </CardContent></Card>}
    {vulns.length === 0 && !loading && <Card className="border-emerald-500/20 bg-emerald-500/[0.02]"><CardContent className="flex items-center gap-3 p-4">
      <CheckCircle2 className="h-6 w-6 text-emerald-500 shrink-0" />
      <div><p className="font-semibold text-emerald-500 text-sm">{t("reports.noFindings")}</p><p className="text-xs text-muted-foreground">{t("reports.noFindingsDesc")}</p></div>
    </CardContent></Card>}
    {loading && <div className="flex items-center justify-center py-8 text-muted-foreground"><Loader2 className="h-5 w-5 animate-spin mr-2" /><span className="text-sm">{t("common.loading")}</span></div>}
    {!loading && SEVERITY_ORDER.map(sev => <VulnerabilitySection key={sev} severity={sev} vulns={groups[sev] || []} />)}
  </div>
}

function ReportDetailWrapper({ scanId, onClose }) {
  const { t } = useI18n()
  const [data, setData] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState(null)
  useState(() => {
    fetch("/api/scans/" + scanId)
      .then(r => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json() })
      .then(d => { setData(d); setIsLoading(false) })
      .catch(e => { setError(e); setIsLoading(false) })
  })
  if (isLoading) return <div className="flex items-center justify-center py-6 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin mr-2" /><span className="text-xs">{t("reports.loading")}</span></div>
  if (error || !data) return <div className="flex flex-col items-center justify-center py-6 text-muted-foreground"><AlertCircle className="h-5 w-5 mb-1 text-destructive" /><p className="text-xs">{t("reports.error")}</p></div>
  return <ReportDetail scan={data} onClose={onClose} />
}

const ENGINE_LABELS = { ai: "智能扫描", all: "全量扫描" }

function ReportCard({ scan, isExpanded, onToggle }) {
  const router = useRouter()
  const { t } = useI18n()
  const deleteScan = useDeleteScan()
  const [deleting, setDeleting] = useState(false)
  const summary = scan.summary || { critical: 0, high: 0, medium: 0, low: 0, passed: 0 }
  const totalVulns = summary.critical + summary.high + summary.medium + summary.low
  const total = totalVulns + summary.passed
  const handleDelete = (e) => { e.stopPropagation(); if (!confirm(t("reports.deleteConfirm"))) return; setDeleting(true); deleteScan.mutateAsync(scan.id).catch(() => {}) }

  return <Card className={"border-border/50 transition-all duration-200 " + (isExpanded ? "ring-1 ring-primary/20" : "hover:border-border/80")}>
    <button onClick={onToggle} className="w-full text-left focus:outline-none"><CardContent className="p-4">
      <div className="flex items-start gap-4">
        <div className={"h-10 w-10 rounded-full flex items-center justify-center text-sm font-black shrink-0 " + (
          scan.risk === "Secure" || scan.risk === "A" ? "bg-emerald-500/15 text-emerald-500"
          : scan.risk === "Critical" || scan.risk === "F" ? "bg-destructive/15 text-destructive"
          : "bg-amber-500/15 text-amber-500")}>{scan.risk}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-semibold truncate">{scan.target}</h3>
              <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><FileScan className="h-3 w-3" />{"源码"}</span>
                <span className="flex items-center gap-1"><Clock className="h-3 w-3" />{scan.date}</span>
                {scan.engine && <span className="flex items-center gap-1"><Brain className="h-3 w-3" />{ENGINE_LABELS[scan.engine] || scan.engine}</span>}
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {summary.critical > 0 && <Badge variant="destructive" className="text-[10px] px-1.5 py-0">{summary.critical}</Badge>}
              {summary.high > 0 && <Badge variant="warning" className="text-[10px] px-1.5 py-0">{summary.high}</Badge>}
              {summary.medium > 0 && <Badge variant="info" className="text-[10px] px-1.5 py-0">{summary.medium}</Badge>}
            </div>
          </div>
          <div className="mt-2.5"><SeverityBar critical={summary.critical} high={summary.high} medium={summary.medium} low={summary.low} total={total} /></div>
          <div className="flex items-center gap-2 mt-2">
            {scan.status === "completed" ? <span className="text-[10px] text-emerald-500 flex items-center gap-0.5"><CheckCircle2 className="h-3 w-3" /> 已完成</span>
            : scan.status === "failed" ? <span className="text-[10px] text-destructive flex items-center gap-0.5"><XCircle className="h-3 w-3" /> 失败</span>
            : <span className="text-[10px] text-amber-500 flex items-center gap-0.5"><Loader2 className="h-3 w-3 animate-spin" /> 扫描中</span>}
            <span className="text-[10px] text-muted-foreground">{total} 项检测</span>
          </div>
        </div>
        <div className="flex flex-col items-center gap-1 shrink-0">
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={e => { e.stopPropagation(); onToggle() }}>
            {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
          <Button variant="ghost" size="sm" className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive" onClick={handleDelete} disabled={deleting}>
            {deleting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>
    </CardContent></button>
    {isExpanded && <div className="border-t border-border/50 px-4 pb-4"><ReportDetailWrapper scanId={scan.id} onClose={onToggle} /></div>}
  </Card>
}

export default function ReportsPage() {
  const { t } = useI18n()
  const router = useRouter()
  const { data: scans, isLoading, error } = useScans()
  const [search, setSearch] = useState("")
  const [riskFilter, setRiskFilter] = useState("all")
  const [expandedId, setExpandedId] = useState(null)

  const { stats, filteredScans } = useMemo(() => {
    const completed = (scans || []).filter(s => s.status === "completed")
    let tc = 0, th = 0
    for (const s of completed) { if (s.summary) { tc += s.summary.critical; th += s.summary.high } }
    let filtered = completed
    if (search.trim()) { const q = search.toLowerCase(); filtered = filtered.filter(s => s.target.toLowerCase().includes(q)) }
    if (riskFilter !== "all") { filtered = filtered.filter(s => s.risk === riskFilter) }
    return { stats: { totalReports: completed.length, totalCritical: tc, totalHigh: th }, filteredScans: filtered }
  }, [scans, search, riskFilter])

  const toggleExpand = useCallback((id) => { setExpandedId(p => p === id ? null : id) }, [])

  return <div className="space-y-5">
    <div><h1 className="text-xl font-bold flex items-center gap-2"><FileText className="h-5 w-5 text-primary" />{t("reports.title")}</h1><p className="text-sm text-muted-foreground mt-1">{t("reports.emptyDesc")}</p></div>

    <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
      <Card><CardContent className="p-3 flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0"><FileText className="h-4 w-4 text-primary" /></div>
        <div><p className="text-xs text-muted-foreground">{t("reports.statsReports")}</p><p className="text-lg font-bold">{stats.totalReports}</p></div>
      </CardContent></Card>
      <Card><CardContent className="p-3 flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-destructive/10 flex items-center justify-center shrink-0"><AlertTriangle className="h-4 w-4 text-destructive" /></div>
        <div><p className="text-xs text-muted-foreground">{t("reports.statsCritical")}</p><p className="text-lg font-bold text-destructive">{stats.totalCritical}</p></div>
      </CardContent></Card>
      <Card><CardContent className="p-3 flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-orange-500/10 flex items-center justify-center shrink-0"><AlertCircle className="h-4 w-4 text-orange-500" /></div>
        <div><p className="text-xs text-muted-foreground">{t("reports.statsHigh")}</p><p className="text-lg font-bold text-orange-500">{stats.totalHigh}</p></div>
      </CardContent></Card>
      <Card><CardContent className="p-3 flex items-center gap-3">
        <div className="h-8 w-8 rounded-lg bg-emerald-500/10 flex items-center justify-center shrink-0"><CheckCircle2 className="h-4 w-4 text-emerald-500" /></div>
        <div><p className="text-xs text-muted-foreground">通过率</p><p className="text-lg font-bold text-emerald-500">{stats.totalReports > 0 ? Math.round((stats.totalReports - stats.totalCritical - stats.totalHigh) / stats.totalReports * 100) : 100}%</p></div>
      </CardContent></Card>
    </div>

    <div className="flex items-center gap-3 flex-wrap">
      <div className="relative flex-1 min-w-[200px]"><Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input className="pl-9 h-9 text-xs" placeholder={t("reports.searchReports")} value={search} onChange={e => setSearch(e.target.value)} /></div>
      <select className="h-9 rounded-lg border border-border bg-background px-3 text-xs text-muted-foreground" value={riskFilter} onChange={e => setRiskFilter(e.target.value)}>
        <option value="all">{t("reports.filterAll")}</option>
        <option value="Critical">{t("reports.filterCritical")}</option>
        <option value="High">{t("reports.filterHigh")}</option>
        <option value="Medium">{t("reports.filterMedium")}</option>
        <option value="Low">{t("reports.filterLow")}</option>
        <option value="Secure">{t("reports.filterSecure")}</option>
      </select>
    </div>

    {isLoading && <div className="flex items-center justify-center py-12 text-muted-foreground"><Loader2 className="h-5 w-5 animate-spin mr-2" /><span className="text-sm">{t("reports.loading")}</span></div>}
    {error && <Card><CardContent className="text-center py-12 text-muted-foreground"><AlertCircle className="h-10 w-10 mx-auto mb-3 text-destructive" /><p>{t("reports.error")}</p><p className="text-sm mt-1">{t("reports.errorDesc")}</p></CardContent></Card>}
    {!isLoading && !error && scans && scans.length === 0 && <Card><CardContent className="text-center py-12 text-muted-foreground"><FileText className="h-12 w-12 mx-auto mb-4 opacity-50" /><p>{t("reports.empty")}</p><p className="text-sm mt-1">{t("reports.emptyDesc")}</p></CardContent></Card>}
    {!isLoading && !error && scans && scans.length > 0 && filteredScans.length === 0 && <Card><CardContent className="text-center py-12 text-muted-foreground"><Filter className="h-10 w-10 mx-auto mb-3 opacity-50" /><p>{t("reports.noResults")}</p></CardContent></Card>}

    {!isLoading && !error && filteredScans.length > 0 && <div className="space-y-2.5">
      {filteredScans.map(scan => <ReportCard key={scan.id} scan={scan} isExpanded={expandedId === scan.id} onToggle={() => toggleExpand(scan.id)} />)}
    </div>}
  </div>
}
