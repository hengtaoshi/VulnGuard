"""
LLM 输出结果解析器

将 LLM 返回的 JSON 格式分析结果解析为 VulnGuard 内部数据结构。
支持 DeepSeek 及其他兼容 OpenAI API 格式的大模型输出。
"""

import json
import re
from typing import Optional


class LLMResultParser:
    """解析 LLM 返回的安全分析结果"""

    @staticmethod
    def extract_json(text: str) -> Optional[dict]:
        """从 LLM 回复中提取 JSON 内容"""
        # Try direct JSON parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from code blocks
        json_match = re.search(r'```(?:json)?\s*\n(.+?)\n```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding JSON object
        json_match = re.search(r'\{.*"vulnerabilities".*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        return None

    @staticmethod
    def parse_vulnerabilities(llm_response: str) -> list[dict]:
        """
        从 LLM 回复中提取漏洞列表。

        返回标准化格式:
        [
            {
                "name": str,
                "severity": str,
                "location": str,
                "cve": str | None,
                "description": str,
                "impact": str,
                "fix_recommendation": str,
                "code_example": str,
            }
        ]
        """
        data = LLMResultParser.extract_json(llm_response)
        if not data:
            return []

        vulns = data.get("vulnerabilities", data.get("findings", []))
        if isinstance(vulns, list):
            return vulns

        return []

    @staticmethod
    def parse_score(llm_response: str) -> Optional[str]:
        """提取安全评分 (A+ ~ F)"""
        data = LLMResultParser.extract_json(llm_response)
        if data:
            summary = data.get("summary", data)
            score = summary.get("score")
            if score:
                return score

        # Fallback: regex search
        score_match = re.search(r'\b([A-F][+-]?)\b', llm_response)
        if score_match:
            return score_match.group(1)

        return None


__all__ = ["LLMResultParser"]
