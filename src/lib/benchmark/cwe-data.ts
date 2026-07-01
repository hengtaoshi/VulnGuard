import type { CweCoverage, ScannerCoverage, BenchmarkScore, BenchmarkData } from "./types"

/**
 * CWE 覆盖数据 — 数据来源为各扫描器官方文档：
 * - Semgrep:  https://semgrep.dev/registry
 * - CodeQL:   https://github.com/github/codeql
 * - Bandit:   https://bandit.readthedocs.io
 * - Gitleaks: https://github.com/gitleaks/gitleaks
 * - TruffleHog: https://github.com/trufflesecurity/trufflehog
 * - Checkov:  https://www.checkov.io
 * - OSV-Scanner: https://osv.dev
 *
 * 两种覆盖方式:
 *   scanners[]    — 规则级精确匹配（SAST/Secret/IaC）
 *   cveScanners[] — 通过 CVE 数据库间接覆盖（SCA 类），只要某 CWE 存在已知 CVE
 *                   就可检出（如 lodash → CWE-400）
 *
 * CWE 列表基于 MITRE CWE Top 25 + OWASP Top 10。
 * 用户可在 cwe.mitre.org 核实每个 CWE 条目。
 */

// SCA 扫描器（通过 CVE 数据库覆盖全部有 CVE 的 CWE）
const CVE_SCANNERS = ["osv-scanner", "npm-audit", "pip-audit", "trivy"]

export const CWE_LIST: CweCoverage[] = [
  // ── CWE Top 25 (2024) ──────────────────────────────────────────────────
  { cweId: "CWE-79",  name: "跨站脚本 (XSS)",          description: "未正确过滤用户输入，导致恶意脚本注入页面",                       scanners: ["semgrep", "codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-89",  name: "SQL 注入",                 description: "未转义用户输入直接拼接 SQL 语句",                               scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-78",  name: "OS 命令注入",              description: "用户输入直接传给系统命令执行",                                 scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-20",  name: "输入验证不当",             description: "未对用户输入进行合法性校验",                                   scanners: ["semgrep", "codeql", "bandit", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-22",  name: "路径遍历",                 description: "用户输入控制文件路径导致任意文件读取",                          scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-352", name: "跨站请求伪造 (CSRF)",       description: "未验证请求来源导致用户被恶意触发操作",                          scanners: ["semgrep", "codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-434", name: "文件上传限制不当",         description: "未限制上传文件类型导致恶意文件上传",                            scanners: ["semgrep", "codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-502", name: "不安全的反序列化",         description: "未安全验证反序列化数据导致远程代码执行",                        scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-287", name: "认证绕过",                 description: "认证机制缺陷导致未授权访问",                                   scanners: ["semgrep", "codeql", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-200", name: "信息泄露",                 description: "敏感信息暴露（错误信息、堆栈跟踪、调试接口等）",                scanners: ["semgrep", "codeql", "bandit", "gitleaks", "trufflehog", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-862", name: "缺少授权",                 description: "未验证操作权限导致越权访问",                                   scanners: ["semgrep", "codeql", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-306", name: "缺少认证",                 description: "关键功能未要求身份认证",                                       scanners: ["checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-918", name: "服务端请求伪造 (SSRF)",    description: "服务器未验证用户提供的 URL 发起请求",                            scanners: ["semgrep", "codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-611", name: "XML 外部实体 (XXE)",       description: "XML 解析器未禁用外部实体导致文件泄露或 SSRF",                   scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-400", name: "资源耗尽",                 description: "未限制资源消耗导致拒绝服务",                                   scanners: ["semgrep", "codeql", "bandit", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-94",  name: "代码注入",                 description: "用户输入被当作代码执行（eval、动态执行等）",                     scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-190", name: "整数溢出",                 description: "算术运算未检查边界导致数据损坏或逻辑错误",                      scanners: ["codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-476", name: "空指针解引用",             description: "使用空指针导致程序崩溃",                                       scanners: ["codeql"], cveScanners: CVE_SCANNERS },

  // ── OWASP Top 10 扩展 ──────────────────────────────────────────────────
  { cweId: "CWE-798", name: "硬编码凭证",               description: "源代码中硬编码密码、密钥等敏感凭据",                            scanners: ["semgrep", "codeql", "bandit", "gitleaks", "trufflehog"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-312", name: "敏感数据明文存储",         description: "未加密存储敏感数据（密码、Token 等）",                           scanners: ["semgrep", "codeql", "bandit", "gitleaks", "trufflehog", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-327", name: "使用已破译的加密算法",     description: "使用 MD5、SHA1、DES 等不安全加密算法",                           scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-295", name: "SSL/TLS 证书验证不当",      description: "跳过或错误验证 SSL 证书导致中间人攻击",                        scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-326", name: "加密强度不足",             description: "使用过短密钥（如 1024 位 RSA）",                                scanners: ["semgrep", "codeql", "bandit", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-338", name: "使用不安全的随机数",       description: "使用可预测的随机数生成器（如 Math.random() 用于安全场景）",     scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-522", name: "凭证保护不足",             description: "凭证存储或传输保护措施不足",                                   scanners: ["trufflehog"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-377", name: "不安全的临时文件",         description: "创建临时文件时未使用安全权限或随机名称",                        scanners: ["semgrep", "codeql", "bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-276", name: "默认权限不正确",           description: "文件或资源配置了过于宽松的默认权限",                            scanners: ["checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-732", name: "权限控制不正确",           description: "关键资源权限配置不当（如 IAM 策略过于宽松）",                  scanners: ["checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-269", name: "权限管理不当",             description: "未正确管理用户权限导致提权风险",                               scanners: ["semgrep", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-250", name: "不必要的权限执行",         description: "以过高权限执行操作（如 root 运行 Web 服务）",                   scanners: ["semgrep", "checkov"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-113", name: "HTTP 响应拆分",            description: "用户输入污染 HTTP 响应头导致缓存污染或 XSS",                     scanners: ["semgrep", "codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-601", name: "URL 重定向到不信任站点",   description: "未验证的重定向可能导致钓鱼攻击",                               scanners: ["codeql"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-347", name: "签名验证不充分",           description: "未正确验证数字签名导致篡改数据被接受",                          scanners: ["bandit"], cveScanners: CVE_SCANNERS },
  { cweId: "CWE-703", name: "异常处理不当",             description: "捕获异常过于宽泛或泄露敏感信息",                               scanners: ["bandit"], cveScanners: CVE_SCANNERS },
]

/** 各扫描器覆盖概况 */
export const SCANNER_COVERAGE: ScannerCoverage[] = [
  // ── SAST ──
  { name: "semgrep",     displayName: "Semgrep",           category: "sast",        coverageType: "rule",     cweCount: 0, ruleCount: 2000,   sourceUrl: "https://semgrep.dev/registry" },
  { name: "codeql",      displayName: "CodeQL",            category: "sast",        coverageType: "rule",     cweCount: 0, ruleCount: 104,    sourceUrl: "https://github.com/github/codeql" },
  { name: "bandit",      displayName: "Bandit",            category: "sast",        coverageType: "rule",     cweCount: 0, ruleCount: 100,    sourceUrl: "https://bandit.readthedocs.io" },
  // ── Secret ──
  { name: "gitleaks",    displayName: "Gitleaks",          category: "secret",      coverageType: "rule",     cweCount: 0, detectorCount: 150, sourceUrl: "https://github.com/gitleaks/gitleaks" },
  { name: "trufflehog",  displayName: "TruffleHog",        category: "secret",      coverageType: "rule",     cweCount: 0, detectorCount: 800, sourceUrl: "https://github.com/trufflesecurity/trufflehog" },
  // ── SCA（通过 CVE 数据库匹配） ──
  { name: "osv-scanner", displayName: "OSV-Scanner",       category: "dependency",  coverageType: "cve-db",  cweCount: 0, cweCountDisplay: "全部", ecosystemCount: 12, sourceUrl: "https://osv.dev" },
  { name: "npm-audit",   displayName: "npm audit",         category: "dependency",  coverageType: "cve-db",  cweCount: 0, cweCountDisplay: "全部", ecosystemCount: 1,  sourceUrl: "https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities" },
  { name: "pip-audit",   displayName: "pip-audit",         category: "dependency",  coverageType: "cve-db",  cweCount: 0, cweCountDisplay: "全部", ecosystemCount: 1,  sourceUrl: "https://pypi.org/project/pip-audit/" },
  // ── 文件系统 ──
  { name: "trivy",       displayName: "Trivy",             category: "filesystem",  coverageType: "cve-db",  cweCount: 0, cweCountDisplay: "全部", ecosystemCount: 12, sourceUrl: "https://trivy.dev" },
  // ── IaC ──
  { name: "checkov",     displayName: "Checkov",           category: "filesystem",  coverageType: "rule",     cweCount: 0, policyCount: 1000, standards: ["CIS AWS", "CIS K8s", "CIS Docker", "PCI-DSS", "NIST 800-53"], sourceUrl: "https://www.checkov.io" },
  // ── 模板化检测 ──
  { name: "nuclei",      displayName: "Nuclei",            category: "filesystem",  coverageType: "template", cweCount: 0, cweCountDisplay: "N/A", ruleCount: 8000,   sourceUrl: "https://github.com/projectdiscovery/nuclei" },
  // ── 安全实践 ──
  { name: "scorecard",   displayName: "OpenSSF Scorecard", category: "sast",        coverageType: "practice", cweCount: 0, cweCountDisplay: "N/A", ruleCount: 20,     sourceUrl: "https://securityscorecards.dev" },
]

/** 计算每个扫描器的实际 CWE 覆盖数 */
function computeCweCounts(): void {
  for (const sc of SCANNER_COVERAGE) {
    if (sc.cweCountDisplay === "全部") {
      // SCA 类扫描器：通过 CVE 数据库覆盖全部 CWE
      sc.cweCount = CWE_LIST.length
    } else if (sc.cweCountDisplay === "N/A") {
      sc.cweCount = 0
    } else {
      sc.cweCount = CWE_LIST.filter(c => c.scanners.includes(sc.name)).length
    }
  }
}
computeCweCounts()

// ─── OWASP Benchmark 跑分（缓存） ───────────────────────────────────────

export const DEFAULT_OWASP_SCORES: BenchmarkScore[] = [
  {
    scannerName: "semgrep",
    displayName: "Semgrep",
    truePositives: 0, falsePositives: 0,
    trueNegatives: 0, falseNegatives: 0,
    totalTestCases: 2740,
    tpr: 0, fpr: 0, score: 0,
    testedAt: "",
  },
  {
    scannerName: "codeql",
    displayName: "CodeQL",
    truePositives: 0, falsePositives: 0,
    trueNegatives: 0, falseNegatives: 0,
    totalTestCases: 2740,
    tpr: 0, fpr: 0, score: 0,
    testedAt: "",
  },
]

export function getDefaultBenchmarkData(): BenchmarkData {
  return {
    cweList: CWE_LIST,
    scannerCoverage: SCANNER_COVERAGE,
    owaspScores: DEFAULT_OWASP_SCORES,
    lastUpdated: "",
  }
}
