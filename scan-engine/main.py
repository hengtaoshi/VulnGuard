"""
VulnGuard Scan Engine - MVP Simulation Mode
Returns mock vulnerability data for demo purposes.
"""

import json
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="VulnGuard Scan Engine", version="0.1.0")

# In-memory scan storage (MVP)
scans: dict = {}


class ScanRequest(BaseModel):
    target: str
    mode: str  # "url" or "source"
    modules: list[str] = []


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    target: str


# Mock vulnerability templates
MOCK_VULNS = [
    {
        "name": "SQL Injection",
        "severity": "Critical",
        "location": "src/api/auth/login.ts:42",
        "cve": "CVE-2024-21626",
        "description": "User input is directly concatenated into SQL query strings without parameterization.",
        "recommendation": "Use parameterized queries (prepared statements) instead of string concatenation.",
        "code_fix": "--safe\nconst query = 'SELECT * FROM users WHERE username = $1';\nawait pool.query(query, [username]);",
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "Critical",
        "location": "src/components/Comment.tsx:28",
        "cve": "CVE-2024-21887",
        "description": "User content rendered using dangerouslySetInnerHTML without sanitization.",
        "recommendation": "Use DOMPurify to sanitize HTML content before rendering.",
        "code_fix": "--safe\nimport DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />",
    },
    {
        "name": "Hardcoded API Key",
        "severity": "High",
        "location": "src/config/constants.ts:15",
        "cve": "—",
        "description": "Secret API key hardcoded in source code.",
        "recommendation": "Move secrets to environment variables.",
        "code_fix": "--safe\nconst API_KEY = process.env.API_KEY;",
    },
    {
        "name": "Missing CSRF Protection",
        "severity": "High",
        "location": "src/api/payments/checkout.ts:1-50",
        "cve": "—",
        "description": "Payment endpoint lacks CSRF token validation.",
        "recommendation": "Implement CSRF tokens using your framework's built-in protection.",
        "code_fix": "--safe\nimport { csrf } from '@/lib/csrf';\nexport const POST = csrf(async (req) => { ... });",
    },
    {
        "name": "Insecure Cookie Configuration",
        "severity": "Medium",
        "location": "src/middleware.ts:22",
        "cve": "—",
        "description": "Session cookies missing Secure, HttpOnly, and SameSite flags.",
        "recommendation": "Set cookie flags: Secure=true, HttpOnly=true, SameSite='Lax'.",
        "code_fix": "--safe\nres.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'lax',\n});",
    },
    {
        "name": "Outdated Dependency: lodash",
        "severity": "Medium",
        "location": "package.json:23",
        "cve": "CVE-2024-25680",
        "description": "lodash@4.17.20 has a known prototype pollution vulnerability.",
        "recommendation": "Update lodash to the latest version.",
        "code_fix": "--safe\nnpm install lodash@latest",
    },
]


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/scans")
def create_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "scan_id": scan_id,
        "target": req.target,
        "mode": req.mode,
        "status": "queued",
        "progress": 0,
        "created_at": datetime.utcnow().isoformat(),
        "vulnerabilities": [],
    }
    return {"scan_id": scan_id, "status": "queued"}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    # Simulate scan completion
    if scan["status"] == "queued":
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["completed_at"] = datetime.utcnow().isoformat()
        scan["vulnerabilities"] = MOCK_VULNS

    return scan


@app.get("/scans")
def list_scans():
    return [
        ScanStatus(
            scan_id=sid,
            status=s["status"],
            progress=s["progress"],
            target=s["target"],
        )
        for sid, s in scans.items()
    ]


# ============================================================
# LLM 分析引导资源端点
# ============================================================

@app.get("/llm-context/full-audit")
def get_llm_audit_context():
    """获取完整的安全审计 LLM 引导上下文"""
    from llm_analyzer.owasp_context import get_full_audit_context
    return {
        "type": "system_prompt",
        "description": "Use this as system prompt for LLM security audit",
        "content": get_full_audit_context(),
    }


@app.post("/llm-context/build-prompt")
def build_llm_prompt(target: str, mode: str = "url", findings: list[dict] | None = None):
    """为特定扫描任务构建分析 Prompt"""
    from llm_analyzer.prompt_templates import build_scan_analysis_prompt
    prompt = build_scan_analysis_prompt(
        target_name=target,
        scan_mode=mode,
        findings=findings or [],
    )
    return {"prompt": prompt, "tokens_estimate": len(prompt.split())}


@app.post("/llm-context/parse-result")
def parse_llm_result(llm_response: str):
    """解析 LLM 返回的分析结果"""
    from llm_analyzer.result_parser import LLMResultParser
    return {
        "vulnerabilities": LLMResultParser.parse_vulnerabilities(llm_response),
        "score": LLMResultParser.parse_score(llm_response),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
