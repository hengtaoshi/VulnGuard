# VulnGuard - Security Vulnerability Scanner

自动化代码安全审查平台，专为检测 AI 开发的网站项目中的安全漏洞而设计。

## 快速开始

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 启动扫描引擎 (另一个终端)
cd scan-engine
pip install -r requirements.txt
python main.py
```

## 功能

- URL 扫描 + 源码分析双模式
- OWASP Top 10 漏洞检测
- 依赖安全分析 (SCA)
- 基础设施安全配置审计
- 业务逻辑漏洞检测
- 抗攻击能力测试
- 详细安全报告 + 修复建议
- LLM 分析引导框架（支持 DeepSeek 集成）

## 技术栈

- **Frontend:** Next.js 14, Tailwind CSS, shadcn/ui, Recharts
- **Engine:** Python FastAPI
- **Infra:** PostgreSQL, Redis, Docker
- **LLM Analysis:** 结构化 Prompt 框架（引导 DeepSeek 等大模型进行专业安全审计）

## 项目结构

```
vulnguard/
├── src/                    # Next.js 前端
│   ├── app/                # 页面路由
│   │   ├── scan/new/       # 新建扫描
│   │   ├── scan/[id]/      # 扫描报告详情
│   │   └── scan/history/   # 扫描历史
│   ├── components/
│   │   ├── layout/         # 布局组件
│   │   └── ui/             # UI 基础组件
│   └── lib/                # 工具函数
├── scan-engine/            # Python 扫描引擎
│   ├── llm_analyzer/       # LLM 分析引导模块
│   ├── main.py             # FastAPI 应用
│   └── Dockerfile
├── prisma/                 # 数据模型
├── docker-compose.yml
└── package.json
```
