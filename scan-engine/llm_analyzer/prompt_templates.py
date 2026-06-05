"""
Prompt 模板生成器

为不同类型的审计场景生成结构化的 Prompt 模板，
引导 LLM 输出标准化的分析结果。
"""

from enum import Enum
from typing import Optional


class AnalysisType(Enum):
    FULL_AUDIT = "full_audit"
    CODE_REVIEW = "code_review"
    VULN_VERIFICATION = "vuln_verification"
    COMPLIANCE_CHECK = "compliance_check"


def build_scan_analysis_prompt(
    target_name: str,
    scan_mode: str,
    source_snippet: Optional[str] = None,
    findings: Optional[list[dict]] = None,
) -> str:
    """
    生成扫描分析引导 Prompt。

    参数:
        target_name: 扫描目标名称
        scan_mode: "url" 或 "source"
        source_snippet: 源码片段（可选）
        findings: 传统工具发现的潜在漏洞（可选）

    返回:
        结构化的 Prompt，可直接作为 LLM 的输入
    """

    prompt = f"""# Security Analysis Request

## Target
- **Name:** {target_name}
- **Scan Mode:** {"Live URL Scan" if scan_mode == "url" else "Source Code Analysis"}

## Instructions
You are acting as a professional security auditor. Analyze the target above for security vulnerabilities.

Please follow this analysis structure:

### 1. Vulnerability Analysis
For each vulnerability found, provide:

| Field | Description |
|-------|-------------|
| **name** | Vulnerability name (e.g., "SQL Injection in Login") |
| **severity** | critical / high / medium / low |
| **location** | File path:line number or URL path |
| **cve** | CVE ID if applicable (null if none) |
| **description** | Detailed explanation of the vulnerability |
| **impact** | What an attacker can achieve |
| **fix_recommendation** | Specific steps to fix |
| **code_example** | Before/after code showing the fix |

### 2. Security Score
Rate the overall security: A+ (excellent) through F (very poor)

### 3. Risk Summary
- Critical: count
- High: count
- Medium: count
- Low: count

### 4. Top 3 Priority Fixes
List the 3 most critical issues that must be fixed first.

### 5. Compliance Notes
Any relevant compliance frameworks (OWASP Top 10, PCI-DSS, GDPR, etc.)

---

"""
    if findings:
        prompt += "## Initial Findings (from automated scanners)\n\n"
        prompt += "The following potential issues were detected by automated tools. Please verify and deep-dive:\n\n"
        for f in findings[:10]:
            prompt += f"- [{f.get('severity', 'info').upper()}] {f.get('name', 'Unknown')} at {f.get('location', 'N/A')}\n"
        prompt += "\n## Additional Analysis Required\n"
        prompt += "Beyond the findings above, please also check for:\n"
        prompt += "1. Business logic vulnerabilities (not detectable by automated tools)\n"
        prompt += "2. Authentication/authorization flaws\n"
        prompt += "3. Cryptographic implementation issues\n"
        prompt += "4. Race conditions and concurrency issues\n"
        prompt += "5. AI-generated code specific patterns (hallucinations, insecure defaults)\n\n"

    if source_snippet:
        prompt += f"## Source Code for Review\n\n```\n{source_snippet[:5000]}\n```\n\n"

    prompt += """
## Output Format
Return your analysis in JSON format:

```json
{
  "summary": {
    "score": "B+",
    "total_vulnerabilities": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0
  },
  "vulnerabilities": [
    {
      "name": "string",
      "severity": "critical|high|medium|low",
      "location": "string",
      "cve": "string|null",
      "description": "string",
      "impact": "string",
      "fix_recommendation": "string",
      "code_example": "string"
    }
  ],
  "top_p3_fixes": ["string"],
  "compliance": ["string"]
}
```
"""
    return prompt


def build_vuln_verification_prompt(
    vuln_name: str,
    vuln_location: str,
    source_context: str,
) -> str:
    """
    生成漏洞验证 Prompt。

    用于对传统工具发现的潜在漏洞进行深度验证，
    由独立验证器判断是否为真实漏洞，降低误报。
    """

    return f"""# Vulnerability Verification Request

## Suspected Vulnerability
- **Name:** {vuln_name}
- **Location:** {vuln_location}

## Context (surrounding source code)
```{source_context[:3000]}
```

## Task
Verify whether this is a REAL vulnerability or a FALSE POSITIVE.

### Analysis Steps:
1. Is the data source user-controllable? (Check entry points)
2. Is there proper sanitization/validation? (Check filters)
3. Is the sink dangerous in this context? (Check execution)
4. Are there compensating controls? (WAF, CSP, etc.)

### Decision:
- **REAL VULNERABILITY** - Provide exploitation scenario and fix
- **FALSE POSITIVE** - Explain why it's not exploitable
- **UNCERTAIN** - What additional information is needed?

Return as JSON:
```json
{{
  "verdict": "real|false_positive|uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "detailed explanation",
  "exploitation_scenario": "if real",
  "fix": "if real"
}}
```"""


__all__ = [
    "AnalysisType",
    "build_scan_analysis_prompt",
    "build_vuln_verification_prompt",
]
