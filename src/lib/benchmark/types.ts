/** CWE 条目——一个扫描器覆盖的一类漏洞 */
export interface CweCoverage {
  cweId: string           // "CWE-89"
  name: string             // "SQL注入"
  description: string      // 简短说明
  scanners: string[]       // 规则级覆盖此 CWE 的扫描器 name
  cveScanners?: string[]   // 通过 CVE 数据库覆盖的扫描器（SCA 类）
}

/** 检测方式 */
export type CoverageType = "rule" | "cve-db" | "template" | "practice"

/** 单个扫描器的总体覆盖信息 */
export interface ScannerCoverage {
  name: string
  displayName: string
  category: string
  coverageType: CoverageType
  cweCount: number
  cweCountDisplay?: string  // 非精确数字时显示文字（如"全部有CVE的CWE"）
  ruleCount?: number       // 该扫描器总规则数
  detectorCount?: number   // Secret 扫描器用检测器数
  ecosystemCount?: number  // SCA 扫描器支持生态数
  policyCount?: number     // IaC 扫描器用策略数
  standards?: string[]     // 合规标准映射 CIS / PCI-DSS
  sourceUrl?: string       // 数据来源链接
}

/** OWASP Benchmark 单项跑分 */
export interface BenchmarkScore {
  scannerName: string
  displayName: string
  truePositives: number
  falsePositives: number
  trueNegatives: number
  falseNegatives: number
  totalTestCases: number
  tpr: number              // True Positive Rate (召回率)
  fpr: number              // False Positive Rate
  score: number            // OWASP 标准分 = 1 - sqrt((1-TPR)²+FPR²)/√2
  testedAt: string         // ISO 日期
}

/** Benchmark 页面完整数据 */
export interface BenchmarkData {
  cweList: CweCoverage[]
  scannerCoverage: ScannerCoverage[]
  owaspScores: BenchmarkScore[]
  lastUpdated: string
}
