"""
LLM 分析引导模块

此模块提供专业的安全审计 Prompt 框架和结构化上下文，
用于引导通用大模型（如 DeepSeek）进行深度安全分析。

使用方式:
    1. 调用 build_security_prompt() 获取完整的审计引导
    2. 将返回的 prompt 输入给 DeepSeek
    3. 解析 LLM 返回的结构化结果
"""
