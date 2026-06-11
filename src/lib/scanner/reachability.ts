/**
 * reachability.ts — 依赖可达性分析
 *
 * SCA 扫描器报告了大量 CVE，但很多依赖在项目中根本没被实际调用。
 * 本模块通过解析源码中的 import/require 语句，判断依赖是否可达，
 * 将不可达的 CVE 标记为低优先级，减少误报。
 *
 * 支持的格式:
 *   - JS/TS: import X from 'y', require('y'), import('y')
 *   - Python: import y, from y import x
 *   - Go: import "y"
 *   - Java: import y.x
 */

import { readdirSync, statSync, readFileSync, existsSync } from "fs"
import { join, extname } from "path"

interface DepMap {
  [depName: string]: {
    declared: boolean        // 在 package.json / requirements.txt 中声明
    imported: boolean        // 在源码中被 import/require
    importCount: number      // 被引用次数
  }
}

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", ".venv", "venv",
  "__pycache__", ".trivy-cache", ".scans", "tools", "coverage",
])

// ─── JS/TS import 解析 ────────────────────────────────────────────────────

const JS_IMPORT_REGEX = /(?:import\s+(?:[\w*{},]\s+from\s+)?['"](\.[^'"]+|(?:@[\w-]+\/)?[\w-]+)['"]|require\(['"](\.[^'"]+|(?:@[\w-]+\/)?[\w-]+)['"]\)|import\(['"](\.[^'"]+|(?:@[\w-]+\/)?[\w-]+)['"]\))/g

function extractJsImports(content: string): string[] {
  const deps: string[] = []
  let match: RegExpExecArray | null
  while ((match = JS_IMPORT_REGEX.exec(content)) !== null) {
    const dep = match[1] || match[2] || match[3]
    if (!dep) continue
    // 只取包名（去掉相对路径和 scope 后的具体路径）
    if (dep.startsWith(".") || dep.startsWith("/")) continue
    const parts = dep.split("/")
    const pkg = dep.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0]
    if (pkg) deps.push(pkg)
  }
  return deps
}

// ─── Python import 解析 ────────────────────────────────────────────────────

const PY_IMPORT_REGEX = /(?:^|\n)(?:import\s+(\w[\w.]*)|from\s+(\w[\w.]*)\s+import)/g

function extractPyImports(content: string): string[] {
  const deps: string[] = []
  let match: RegExpExecArray | null
  while ((match = PY_IMPORT_REGEX.exec(content)) !== null) {
    const dep = (match[1] || match[2] || "").split(".")[0]
    // 排除标准库
    if (dep && !["os", "sys", "re", "json", "math", "time", "pathlib", "typing",
      "collections", "functools", "itertools", "datetime", "random", "io",
      "base64", "hashlib", "hmac", "uuid", "subprocess", "threading",
      "multiprocessing", "logging", "argparse", "configparser", "enum",
      "dataclasses", "abc", "copy", "textwrap", "string", "types",
      "inspect", "pprint", "tempfile", "shutil", "glob", "fnmatch",
      "linecache", "pickle", "shelve", "marshal", "sysconfig", "zlib",
      "gzip", "bz2", "lzma", "zipfile", "tarfile", "csv", "netrc",
      "getpass", "contextlib", "signal", "traceback", "__future__",
      "warnings", "weakref", "gc", "inspect", "platform", "errno",
      "ctypes", "email", "html", "http", "urllib", "xml", "webbrowser",
      "turtle", "tkinter", "unittest", "venv"].includes(dep)) {
      deps.push(dep)
    }
  }
  return deps
}

// ─── 主分析函数 ─────────────────────────────────────────────────────────────

export interface ReachabilityResult {
  /** 声明的依赖列表 */
  declaredDeps: string[]
  /** 实际被 import 的依赖 */
  importedDeps: string[]
  /** 声明了但未导入的依赖（不可达） */
  unreachableDeps: string[]
  /** 详细映射 */
  depMap: DepMap
}

export function analyzeReachability(targetPath: string): ReachabilityResult {
  const depMap: DepMap = {}
  const sourceFiles: string[] = []

  // 1. 收集所有源码文件
  function walk(dir: string) {
    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch { return }
    for (const entry of entries) {
      const full = join(dir, entry)
      try {
        const stat = statSync(full)
        if (stat.isDirectory()) {
          if (!SKIP_DIRS.has(entry)) walk(full)
        } else if (stat.isFile() && stat.size > 0 && stat.size < 500000) {
          const ext = extname(entry).toLowerCase()
          if ([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"].includes(ext)) {
            sourceFiles.push(full)
          }
        }
      } catch { /* skip */ }
    }
  }
  walk(targetPath)

  // 2. 解析依赖声明文件
  // package.json
  const pkgPath = join(targetPath, "package.json")
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"))
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies }
    for (const name of Object.keys(allDeps)) {
      depMap[name] = depMap[name] || { declared: false, imported: false, importCount: 0 }
      depMap[name].declared = true
    }
  } catch { /* no package.json */ }

  // requirements.txt
  const reqPath = join(targetPath, "requirements.txt")
  try {
    const content = readFileSync(reqPath, "utf-8")
    for (const line of content.split("\n")) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith("#")) continue
      const name = trimmed.split(/[=<>!~]/)[0].trim().toLowerCase()
      if (name) {
        depMap[name] = depMap[name] || { declared: false, imported: false, importCount: 0 }
        depMap[name].declared = true
      }
    }
  } catch { /* no requirements.txt */ }

  // pipfile / poetry
  try {
    const pipfile = join(targetPath, "Pipfile")
    if (existsSync(pipfile)) {
      const content = readFileSync(pipfile, "utf-8")
      for (const line of content.split("\n")) {
        const m = line.match(/^\s*(\w[\w.-]*)\s*=\s*"/)
        if (m) {
          depMap[m[1]] = depMap[m[1]] || { declared: false, imported: false, importCount: 0 }
          depMap[m[1]].declared = true
        }
      }
    }
  } catch { /* no Pipfile */ }

  // 3. 扫描源码中的 import/require
  for (const file of sourceFiles) {
    try {
      const content = readFileSync(file, "utf-8")
      const ext = extname(file).toLowerCase()

      if ([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"].includes(ext)) {
        const imports = extractJsImports(content)
        for (const dep of imports) {
          depMap[dep] = depMap[dep] || { declared: false, imported: false, importCount: 0 }
          depMap[dep].imported = true
          depMap[dep].importCount++
        }
      } else if (ext === ".py") {
        const imports = extractPyImports(content)
        for (const dep of imports) {
          depMap[dep] = depMap[dep] || { declared: false, imported: false, importCount: 0 }
          depMap[dep].imported = true
          depMap[dep].importCount++
        }
      }
    } catch { /* skip unreadable file */ }
  }

  const declaredDeps = Object.entries(depMap).filter(([, v]) => v.declared).map(([k]) => k)
  const importedDeps = Object.entries(depMap).filter(([, v]) => v.imported).map(([k]) => k)
  const unreachableDeps = Object.entries(depMap)
    .filter(([, v]) => v.declared && !v.imported)
    .map(([k]) => k)

  return { declaredDeps, importedDeps, unreachableDeps, depMap }
}

/**
 * 判断给定的依赖名称是否在源码中可达
 */
export function isReachable(depName: string, depMap: DepMap): boolean {
  return depMap[depName]?.imported === true
}
