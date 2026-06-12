"use client"

import { useState, useCallback, useRef } from "react"
import { useRouter } from "next/navigation"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Check, Loader2, FolderOpen, AlertCircle, Brain, Cpu, Upload, File, X } from "lucide-react"
import { useI18n } from "@/lib/i18n/context"

type ScannerEngine = "ai" | "all"
type PageState = "idle" | "uploading" | "scanning" | "error"

export default function NewScanPage() {
  const router = useRouter()
  const { t } = useI18n()
  const [state, setState] = useState<PageState>("idle")
  const [target, setTarget] = useState("")
  const [error, setError] = useState("")
  const [engine, setEngine] = useState<ScannerEngine>("ai")
  const [dragging, setDragging] = useState(false)
  const [uploadProgress, setUploadProgress] = useState("")
  const [uploadedInfo, setUploadedInfo] = useState<{ path: string; displayPath?: string; fileCount: number } | null>(null)
  const [fileFilterInfo, setFileFilterInfo] = useState<{ total: number; skipped: number } | null>(null)
  const dropRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleScan = useCallback(async (scanTarget: string, projectName?: string) => {
    setState("scanning")
    setError("")
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: scanTarget,
          mode: "source",
          engine,
          projectName: projectName,
          totalFiles: fileFilterInfo?.total,
          skippedFiles: fileFilterInfo?.skipped,
        }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.error || "扫描失败")
      }
      const { id } = await res.json()
      router.push(`/scan/${id}`)
    } catch (err) {
      setState("error")
      setError(err instanceof Error ? err.message : "扫描启动失败")
    }
  }, [engine, router])

  const uploadFolder = useCallback(async (files: File[], projectName?: string) => {
    setState("uploading")
    setError("")
    setUploadProgress(`正在读取 ${files.length} 个文件...`)

    try {
      const formData = new FormData()
      let count = 0
      for (const file of files) {
        const relPath = (file as any).webkitRelativePath || file.name
        formData.append(relPath, file)
        count++
        if (count % 500 === 0) {
          // Yield to UI for very large uploads
          await new Promise(r => setTimeout(r, 0))
          setUploadProgress(`正在打包 ${count}/${files.length} 个文件...`)
        }
      }

      setUploadProgress(`正在上传 ${files.length} 个文件到服务器...`)
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || "上传失败")
      }

      const data = await res.json()
      setUploadedInfo({ path: data.path, displayPath: data.displayPath, fileCount: data.fileCount })
      setTarget(data.path)

      // Auto-start scan after upload
      await handleScan(data.path, projectName)
    } catch (err) {
      setState("error")
      setError(err instanceof Error ? err.message : "上传失败")
    }
  }, [handleScan])

  // ── Drag & Drop Handlers ──────────────────────────────────────────────

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    // Only set false if actually leaving the drop zone
    if (dropRef.current && !dropRef.current.contains(e.relatedTarget as Node)) {
      setDragging(false)
    }
  }, [])

  const handleFolderPicked = useCallback(async (files: FileList | null) => {
    if (!files || files.length === 0) return
    const allFiles = Array.from(files)
    await processFiles(allFiles)
  }, [])

  const processFiles = useCallback(async (allFiles: File[]) => {
    if (allFiles.length === 0) {
      setError("未找到有效文件，请选择一个文件夹")
      return
    }

    // Filter out node_modules and other large non-source dirs
    const filtered = allFiles.filter(f => {
      const path = (f as any).webkitRelativePath || f.name
      return !/\/node_modules\//.test(path) &&
             !/\/\.git\//.test(path) &&
             !/\/dist\//.test(path) &&
             !/\/\.next\//.test(path) &&
             !/\/__pycache__\//.test(path) &&
             !/\/vendor\//.test(path) &&
             !/\/build\//.test(path) &&
             !/\/\.trivy-cache\//.test(path) &&
             !/\/data\/uploads\//.test(path) &&
             !/\/\.scans\//.test(path) &&
             !/\/\.dc-report\//.test(path) &&
             !/\/tools\/bin\//.test(path) &&
             !/\/\.reasonix\//.test(path) &&
             !/\/\.superpowers\//.test(path) &&
             !/\/\.claude\//.test(path) &&
             !/\/target\//.test(path) &&
             !/\/\.terraform\//.test(path) &&
             !/\/venv\//.test(path) &&
             !/\/\.venv\//.test(path) &&
             !/\/\.pytest_cache\//.test(path)
    })

    if (filtered.length === 0) {
      setError("文件夹中没有可扫描的源码文件（所有文件都在排除目录中）")
      return
    }

    // 从文件路径中提取项目名（webkitRelativePath 第一段 = 用户选择的文件夹名）
    const firstFile = allFiles.find(f => (f as any).webkitRelativePath)
    const projectName = firstFile
      ? ((f: any) => f.webkitRelativePath.split("/")[0] || "")(firstFile)
      : ""
    const skipped = allFiles.length - filtered.length
    setFileFilterInfo({ total: allFiles.length, skipped })
    const msg = skipped > 0 ? `（已跳过 ${skipped} 个非源码文件，实际扫描 ${filtered.length} 个文件）` : ""
    setUploadProgress(msg)

    await uploadFolder(filtered, projectName)
  }, [uploadFolder])

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragging(false)

    const items = e.dataTransfer.items
    if (!items || items.length === 0) {
      setError("请拖入一个文件夹")
      return
    }

    // Collect all files from dropped folder(s)
    const allFiles: File[] = []
    const promises: Promise<void>[] = []

    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      if (item.webkitGetAsEntry) {
        const entry = item.webkitGetAsEntry()
        if (entry) {
          promises.push(traverseEntry(entry, allFiles))
        }
      } else if (item.kind === "file") {
        const file = item.getAsFile()
        if (file) allFiles.push(file)
      }
    }

    await Promise.all(promises)
    await processFiles(allFiles)
  }, [processFiles])

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Scanner Engine Selection */}
      <Card>
        <CardHeader>
          <CardTitle>扫描引擎</CardTitle>
          <CardDescription>选择使用传统扫描器、AI 扫描或同时使用</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3">
            {engineOptions(engine, setEngine).map(opt => (
              <button
                key={opt.value}
                onClick={() => setEngine(opt.value)}
                role="radio"
                aria-checked={engine === opt.value}
                className={`relative rounded-lg border-2 p-4 text-left transition-all ${
                  engine === opt.value
                    ? "border-primary bg-primary/5"
                    : "border-border hover:border-muted-foreground/30"
                }`}
              >
                {engine === opt.value && (
                  <div className="absolute top-2 right-2 h-4 w-4 rounded-full bg-primary flex items-center justify-center">
                    <Check className="h-2.5 w-2.5 text-primary-foreground" />
                  </div>
                )}
                <div className="mb-2">{opt.icon}</div>
                <h3 className="font-semibold text-sm mb-1">{opt.label}</h3>
                <p className="text-xs text-muted-foreground">{opt.desc}</p>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Drop Zone / Upload Area */}
      <div
        ref={dropRef}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <Card className={`transition-all duration-200 ${
          dragging
            ? "border-primary border-dashed bg-primary/5 scale-[1.01]"
            : state === "uploading" || state === "scanning"
              ? "border-muted"
              : ""
        }`}>
          <CardHeader>
            <CardTitle>{t("scan.new.uploadSource")}</CardTitle>
            <CardDescription>将源码文件夹拖入此处，或手动输入路径</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Uploading / Scanning state */}
            {(state === "uploading" || state === "scanning") && (
              <div className="flex flex-col items-center justify-center py-8 gap-3">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
                <p className="text-sm font-medium">
                  {state === "uploading" ? uploadProgress : "正在执行安全扫描..."}
                </p>
                {uploadedInfo && (
                  <p className="text-xs text-muted-foreground">
                    已上传 {uploadedInfo.fileCount} 个文件
                  </p>
                )}
              </div>
            )}

            {/* Drop zone (idle state) */}
            {state === "idle" && !uploadedInfo && (
              <>
                {/* Hidden directory picker */}
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={e => handleFolderPicked(e.target.files)}
                  className="hidden"
                  {...{ webkitdirectory: "", directory: "" } as any}
                />

                <div
                  onClick={() => fileInputRef.current?.click()}
                  className={`flex flex-col items-center justify-center py-10 gap-4 rounded-xl border-2 cursor-pointer transition-all ${
                    dragging
                      ? "border-primary bg-primary/5"
                      : "border-dashed border-muted-foreground/30 hover:border-muted-foreground/50 hover:bg-accent/30"
                  }`}>
                  <Upload className={`h-10 w-10 ${dragging ? "text-primary" : "text-muted-foreground"}`} />
                  <div className="text-center">
                    <p className="text-sm font-medium">
                      {dragging ? "松开以上传" : "点击选择或拖拽文件夹到此处"}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      支持拖拽文件夹 · 点击选择 · 也可手动输入路径
                    </p>
                  </div>
                </div>

                {/* Manual path input */}
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="例如: D:\project\src 或 /home/user/project"
                    value={target}
                    onChange={e => setTarget(e.target.value)}
                    className="flex-1 h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    onKeyDown={e => { if (e.key === "Enter" && target.trim()) handleScan(target.trim()) }}
                  />
                  <Button
                    disabled={!target.trim()}
                    onClick={() => handleScan(target.trim())}
                    className="gap-2 shrink-0"
                  >
                    <FolderOpen className="h-4 w-4" />
                    开始扫描
                  </Button>
                </div>
              </>
            )}

            {/* After upload, show success */}
            {uploadedInfo && state === "idle" && (
              <div className="flex items-center justify-between rounded-lg bg-emerald-500/10 border border-emerald-500/20 px-4 py-3">
                <div className="flex items-center gap-3">
                  <File className="h-5 w-5 text-emerald-500" />
                  <div>
                    <p className="text-sm font-medium text-emerald-600 dark:text-emerald-400">
                      已上传 {uploadedInfo.fileCount} 个文件
                    </p>
                    <p className="text-xs text-muted-foreground mt-0.5">{uploadedInfo.displayPath || uploadedInfo.path}</p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => { setUploadedInfo(null); setTarget("") }}>
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            )}

            <p className="text-xs text-muted-foreground">
              {engine === "ai"
                ? "AI 扫描将代码发送至 DeepSeek 进行智能安全审计，分析 OWASP Top 10 及更多漏洞。"
                : "使用 Semgrep 引擎进行 OWASP Top 10 静态代码安全分析。支持 JavaScript, TypeScript, Python, Java, Go 等 30+ 语言。"}
            </p>
          </CardContent>
        </Card>
      </div>

      {error && (
        <Card className="border-destructive/50">
          <CardContent className="flex items-center gap-3 p-4">
            <AlertCircle className="h-5 w-5 text-destructive shrink-0" />
            <p className="text-sm text-destructive">{error}</p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Traverse a FileSystemEntry recursively, collecting all files */
function traverseEntry(entry: FileSystemEntry, results: File[]): Promise<void> {
  return new Promise(resolve => {
    if (entry.isFile) {
      (entry as FileSystemFileEntry).file(
        (file) => { results.push(file); resolve() },
        () => resolve(),
      )
    } else if (entry.isDirectory) {
      const dirReader = (entry as FileSystemDirectoryEntry).createReader()
      const readBatch = () => {
        dirReader.readEntries(
          async (entries) => {
            if (entries.length === 0) {
              resolve()
            } else {
              await Promise.all(entries.map(e => traverseEntry(e, results)))
              readBatch()
            }
          },
          () => resolve(),
        )
      }
      readBatch()
    } else {
      resolve()
    }
  })
}

function engineOptions(
  engine: ScannerEngine,
  setEngine: (v: ScannerEngine) => void,
): { value: ScannerEngine; label: string; desc: string; icon: React.ReactNode }[] {
  return [
    {
      value: "ai",
      label: "AI 智能扫描",
      desc: "DeepSeek AI 对源码进行智能安全审计，分析潜在漏洞",
      icon: <Brain className="h-6 w-6 text-violet-500" />,
    },
    {
      value: "all",
      label: "全量扫描（AI + 全部引擎）",
      desc: "运行所有可用扫描器 + AI 深度代码审计",
      icon: <Cpu className="h-6 w-6 text-emerald-500" />,
    },
  ]
}
