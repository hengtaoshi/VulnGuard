/**
 * chinese-descriptions.ts — 漏洞描述中文翻译映射
 *
 * 将各扫描器返回的英文漏洞名称/描述/修复建议翻译为中文。
 * 覆盖所有内置扫描器的常见规则类型，未匹配的保留原文。
 */

import type { Vulnerability } from "@/lib/api/types"

/**
 * 按照关键词匹配的中文描述映射表
 * 规则: 原文包含某关键词 → 替换为中文描述
 */
interface DescriptionMap {
  name: string           // 匹配后的中文名称
  description: string    // 中文描述
  recommendation: string // 中文修复建议
}

type MatchRule = {
  keywords: string[]     // 关键词列表（任一匹配即命中）
  result: DescriptionMap
}

// ─── 通用安全漏洞关键词映射 ────────────────────────────────────────────────

const COMMON_RULES: MatchRule[] = [
  // === 硬编码密钥/Secret 类 ===
  {
    keywords: ["hardcoded", "hard-coded", "secret", "password", "credential", "api.key", "api_key", "api-secret"],
    result: {
      name: "硬编码密钥",
      description: "在源代码中发现了硬编码的密钥、密码或凭据。硬编码凭据可能导致未授权访问、数据泄露等安全风险。",
      recommendation: "1. 将密钥移至环境变量或密钥管理服务（如 AWS Secrets Manager、Vault）\n2. 立即轮换已泄露的凭据\n3. 使用 .gitignore 排除配置文件中的敏感信息",
    },
  },
  {
    keywords: ["token", "auth.token", "auth_token", "bearer"],
    result: {
      name: "硬编码令牌",
      description: "代码中包含硬编码的访问令牌。令牌泄露可能导致攻击者冒充合法用户执行操作。",
      recommendation: "1. 使用环境变量或密钥管理服务存储令牌\n2. 设置令牌过期机制并定期轮换\n3. 检查 Git 历史中是否已泄露此令牌",
    },
  },
  {
    keywords: ["private key", "ssh key", "rsa", "dsa", "ecdsa", "ed25519", "pgp", "-----BEGIN"],
    result: {
      name: "私钥泄露",
      description: "源代码中发现了私钥文件内容。私钥泄露可使攻击者伪装成合法服务或用户。",
      recommendation: "1. 立即从仓库中移除该私钥并生成新密钥对\n2. 轮换所有使用该私钥的访问权限\n3. 审核 Git 历史以确保密钥已被彻底清除",
    },
  },

  // === SQL 注入 ===
  {
    keywords: ["sql injection", "sql-injection", "sqli", "sql.concat", "sql.format", "$query", "raw sql"],
    result: {
      name: "SQL 注入",
      description: "代码中存在 SQL 注入漏洞。攻击者可通过构造恶意 SQL 语句操作数据库，可能导致数据泄露、篡改或删除。",
      recommendation: "1. 使用参数化查询（Prepared Statements）替代字符串拼接\n2. 使用 ORM 框架的内置查询构建器\n3. 对用户输入进行严格的验证和过滤",
    },
  },

  // === XSS 跨站脚本 ===
  {
    keywords: ["xss", "cross-site", "cross site", "scripting", "dangerouslySetInnerHTML", "innerHTML"],
    result: {
      name: "跨站脚本攻击 (XSS)",
      description: "代码中存在跨站脚本漏洞。攻击者可在页面中注入恶意脚本，窃取用户 Cookie、会话信息或重定向到恶意网站。",
      recommendation: "1. 对所有用户输入进行 HTML 转义\n2. 使用安全的模板引擎自动转义（如 React JSX 默认转义）\n3. 避免使用 dangerouslySetInnerHTML / innerHTML\n4. 设置 Content-Security-Policy 头",
    },
  },

  // === 命令注入 ===
  {
    keywords: ["command injection", "cmd injection", "shell injection", "exec(", "child_process", "os.system", "subprocess"],
    result: {
      name: "命令注入",
      description: "代码中存在命令注入漏洞。攻击者可通过注入恶意系统命令执行未授权操作。",
      recommendation: "1. 避免将用户输入直接拼接到系统命令中\n2. 使用专门的 API 替代系统命令调用\n3. 对必须执行的命令进行严格的输入白名单验证",
    },
  },

  // === 路径遍历 ===
  {
    keywords: ["path traversal", "directory traversal", "file inclusion", "../", "..\\", "path.combine", "join.*\.\."],
    result: {
      name: "路径遍历",
      description: "代码中存在路径遍历漏洞。攻击者可通过构造特殊路径访问受限文件或目录。",
      recommendation: "1. 使用 path.resolve/normalize 规范化路径\n2. 验证解析后的路径是否在预期的根目录内\n3. 避免将用户输入直接用作文件路径",
    },
  },

  // === XPath/XSLT 注入 ===
  {
    keywords: ["xpath", "xslt", "xml injection"],
    result: {
      name: "XML/XPath 注入",
      description: "代码中存在 XML/XPath 注入漏洞。攻击者可通过构造恶意 XML 查询访问未授权的数据。",
      recommendation: "1. 使用参数化 XPath 查询\n2. 对 XML 输入进行严格的 DTD/Schema 验证\n3. 禁用外部实体解析（XXE）",
    },
  },

  // === 开放重定向 ===
  {
    keywords: ["open redirect", "unvalidated redirect", "url redirect", "redirect.*user", "redirect.*param"],
    result: {
      name: "开放重定向",
      description: "代码中存在开放重定向漏洞。攻击者可将用户重定向到恶意网站，用于钓鱼攻击。",
      recommendation: "1. 对重定向 URL 进行白名单验证\n2. 只允许重定向到同站地址\n3. 使用映射表而非直接在 URL 中传递跳转地址",
    },
  },

  // === CSRF ===
  {
    keywords: ["csrf", "cross-site request forgery", "cross site request forgery", "xsrf"],
    result: {
      name: "跨站请求伪造 (CSRF)",
      description: "代码中缺少跨站请求伪造保护。攻击者可诱使用户在不知情的情况下执行非预期操作。",
      recommendation: "1. 使用 Anti-CSRF Token\n2. 设置 SameSite Cookie 属性\n3. 对关键操作验证 Referer/Origin 头",
    },
  },

  // === SSRF ===
  {
    keywords: ["ssrf", "server-side request forgery", "server side request forgery"],
    result: {
      name: "服务端请求伪造 (SSRF)",
      description: "代码中存在服务端请求伪造漏洞。攻击者可利用服务器发起内部网络请求，访问内网服务。",
      recommendation: "1. 对用户提供的 URL 进行白名单验证\n2. 禁止访问内网/私有 IP 地址\n3. 使用专门的网络代理并限制目标地址范围",
    },
  },

  // === 反序列化 ===
  {
    keywords: ["deserialization", "deserialize", "unserialize", "pickle.load", "yaml.load", "eval("],
    result: {
      name: "不安全的反序列化",
      description: "代码中存在不安全的反序列化操作。攻击者可构造恶意的序列化数据在服务器上执行任意代码。",
      recommendation: "1. 避免反序列化不可信数据\n2. 使用安全的序列化格式（如 JSON）\n3. 必须使用时，对数据进行完整性校验和类型验证",
    },
  },

  // === 权限提升 ===
  {
    keywords: ["privilege escalation", "auth bypass", "authorization bypass", "access control", "permission"],
    result: {
      name: "权限控制缺陷",
      description: "代码中缺少适当的权限验证。用户可能访问其权限范围之外的功能或数据。",
      recommendation: "1. 在每个 API 端点执行权限检查\n2. 使用 RBAC（基于角色的访问控制）模型\n3. 遵循最小权限原则",
    },
  },
]

// ─── 扫描器特定规则映射 ────────────────────────────────────────────────────

/**
 * 按扫描器 + 规则 ID/名称前缀匹配
 */
const BUILTIN_RULES: Record<string, MatchRule[]> = {
  // === gitleaks (Secret 扫描) ===
  gitleaks: [
    {
      keywords: ["generic-api-key", "generic", "api", "key"],
      result: { name: "通用 API 密钥", description: "检测到可能的 API 密钥或访问令牌。", recommendation: "从代码中移除并改为环境变量存储。" },
    },
    {
      keywords: ["aws", "amazon"],
      result: { name: "AWS 凭据", description: "检测到 AWS 访问密钥或秘密访问密钥。", recommendation: "立即轮换该密钥，使用 IAM 角色或 AWS Secrets Manager。" },
    },
    {
      keywords: ["github", "gitlab", "bitbucket", "pat", "personal access"],
      result: { name: "Git 平台访问令牌", description: "检测到 Git 平台的个人访问令牌。", recommendation: "撤销该令牌并使用环境变量或 CI/CD 密钥管理。" },
    },
    {
      keywords: ["slack", "discord", "telegram", "webhook"],
      result: { name: "Webhook/聊天工具令牌", description: "检测到聊天工具或 Webhook 的密钥。", recommendation: "立即轮换并在外部配置中管理。" },
    },
    {
      keywords: ["private-key", "ssh", "pem", "p pk", "pgp"],
      result: { name: "私钥文件", description: "检测到私钥或证书文件。", recommendation: "移除私钥，使用 SSH 代理或密钥管理服务。" },
    },
    {
      keywords: ["docker", "registry", "npmrc", "npm"],
      result: { name: "包注册表凭据", description: "检测到包管理器的认证凭据。", recommendation: "使用 CI/CD 环境的密钥变量而非明文存储。" },
    },
  ],

  // === bandit (Python SAST) ===
  bandit: [
    {
      keywords: ["B101", "assert"],
      result: { name: "使用了 assert 语句", description: "assert 语句在生产环境中会被 Python 忽略（-O 优化模式下），不能用于安全校验。", recommendation: "使用 if 语句显式检查条件并抛出异常。" },
    },
    {
      keywords: ["B102", "exec"],
      result: { name: "使用了 exec 函数", description: "exec() 可执行任意 Python 代码，存在严重安全风险。", recommendation: "避免使用 exec()，寻找替代方案。" },
    },
    {
      keywords: ["B105", "hardcoded.password", "password"],
      result: { name: "硬编码密码", description: "代码中发现了可能的硬编码密码。", recommendation: "使用环境变量或密钥管理服务。" },
    },
    {
      keywords: ["B106", "hardcoded"],
      result: { name: "硬编码敏感数据", description: "代码中包含可能的硬编码敏感数据。", recommendation: "从外部配置加载敏感数据。" },
    },
    {
      keywords: ["B110", "try", "except", "pass"],
      result: { name: "空的 except 块", description: "try-except 块中捕获异常后未做任何处理（pass）。", recommendation: "记录异常日志或进行适当的错误恢复。" },
    },
    {
      keywords: ["B201", "flask", "debug"],
      result: { name: "Flask 调试模式", description: "Flask 应用以调试模式运行，可能泄露敏感信息。", recommendation: "在生产环境中禁用调试模式（debug=False）。" },
    },
    {
      keywords: ["B301", "pickle", "pickle.loads"],
      result: { name: "不安全的 pickle 反序列化", description: "pickle.loads() 可执行任意代码。", recommendation: "避免反序列化不可信数据，或使用更安全的格式（如 JSON）。" },
    },
    {
      keywords: ["B302", "marshal"],
      result: { name: "不安全的 marshal 反序列化", description: "marshal 模块不支持安全的序列化。", recommendation: "使用 JSON 或其他安全格式替代。" },
    },
    {
      keywords: ["B303", "yaml.load"],
      result: { name: "不安全的 YAML 加载", description: "yaml.load() 可执行任意代码，使用 yaml.safe_load() 替代。", recommendation: "使用 yaml.safe_load() 或 yaml.SafeLoader。" },
    },
    {
      keywords: ["B304", "ciphers", "md5", "sha1"],
      result: { name: "使用弱加密算法", description: "使用了 MD5/SHA1 等已被破解的加密算法。", recommendation: "使用 SHA-256 或更强的加密算法。" },
    },
    {
      keywords: ["B307", "eval"],
      result: { name: "使用了 eval 函数", description: "eval() 可执行任意 Python 代码。", recommendation: "避免使用 eval()，寻找类型安全的替代方案。" },
    },
    {
      keywords: ["B308", "mktemp"],
      result: { name: "不安全的临时文件创建", description: "mktemp() 创建的临时文件可能被预测。", recommendation: "使用 tempfile.TemporaryFile 或 tempfile.mkstemp。" },
    },
    {
      keywords: ["B310", "urllib"],
      result: { name: "不安全的 URL 请求", description: "未经验证的 URL 请求可能导致 SSRF 攻击。", recommendation: "验证请求 URL 并限制请求目标。" },
    },
    {
      keywords: ["B311", "random"],
      result: { name: "使用不安全的随机数生成器", description: "random 模块不适用于安全场景。", recommendation: "使用 secrets 模块或 os.urandom() 生成安全随机数。" },
    },
    {
      keywords: ["B312", "telnet"],
      result: { name: "使用不安全的 Telnet 协议", description: "Telnet 协议通信未加密。", recommendation: "使用 SSH 替代 Telnet。" },
    },
    {
      keywords: ["B320", "xml"],
      result: { name: "不安全的 XML 解析", description: "XML 解析可能受 XXE 攻击。", recommendation: "使用 defusedxml 库替代标准 XML 库。" },
    },
    {
      keywords: ["B324", "ssl", "https"],
      result: { name: "不安全的 SSL/HTTPS 配置", description: "使用了过时或不安全的 SSL/TLS 版本。", recommendation: "使用 TLS 1.2+ 和安全加密套件。" },
    },
    {
      keywords: ["B401", "import", "subprocess"],
      result: { name: "导入了 subprocess 模块", description: "subprocess 模块可能被用于执行系统命令。", recommendation: "使用标准库的高层 API 替代系统命令。" },
    },
    {
      keywords: ["B402", "import", "ftplib"],
      result: { name: "导入不安全的 FTP 模块", description: "FTP 协议通信未加密。", recommendation: "使用 SFTP 或 HTTPS 替代 FTP。" },
    },
    {
      keywords: ["B403", "import", "pickle"],
      result: { name: "导入了 pickle 模块", description: "pickle 模块存在反序列化风险。", recommendation: "仅反序列化可信数据，或使用更安全的格式。" },
    },
    {
      keywords: ["B404", "import", "subprocess", "os.system"],
      result: { name: "导入了命令执行模块", description: "os.system/subprocess 可能被用于执行系统命令。", recommendation: "限制子进程使用并验证所有参数。" },
    },
    {
      keywords: ["B405", "import", "xml"],
      result: { name: "导入了 XML 解析模块", description: "标准 XML 库存在 XXE 风险。", recommendation: "使用 defusedxml 替代标准 XML 库。" },
    },
    {
      keywords: ["B501", "request", "verify", "false"],
      result: { name: "禁用了 SSL 证书验证", description: "requests 库禁用了 SSL 证书验证。", recommendation: "设置 verify=True 启用证书验证。" },
    },
    {
      keywords: ["B502", "ssl", "cert", "verify"],
      result: { name: "SSL 证书验证配置不当", description: "SSL 证书验证配置不完整。", recommendation: "确保正确配置 SSL 证书验证。" },
    },
    {
      keywords: ["B503", "ssl", "match_hostname"],
      result: { name: "缺少主机名验证", description: "SSL 连接缺少主机名验证。", recommendation: "验证 SSL 证书的主机名与目标主机匹配。" },
    },
    {
      keywords: ["B504", "ssl", "weak", "protocol"],
      result: { name: "使用弱 SSL/TLS 协议", description: "使用了过时的 SSL/TLS 协议版本。", recommendation: "配置 TLS 1.2+ 并禁用不安全的加密套件。" },
    },
    {
      keywords: ["B505", "weak", "cipher", "ssl"],
      result: { name: "使用弱加密套件", description: "使用了已知存在安全漏洞的加密套件。", recommendation: "使用强加密套件（如 ECDHE + AES-GCM）。" },
    },
    {
      keywords: ["B506", "yaml.load"],
      result: { name: "不安全的 YAML 加载", description: "yaml.load() 可执行任意代码。", recommendation: "使用 yaml.safe_load() 替代。" },
    },
    {
      keywords: ["B507", "ssh", "host_key"],
      result: { name: "SSH 主机密钥验证缺失", description: "SSH 连接缺少主机密钥验证。", recommendation: "启用 SSH 主机密钥验证以防止中间人攻击。" },
    },
    {
      keywords: ["B601", "paramiko", "exec_command"],
      result: { name: "参数化命令执行", description: "paramiko 的 exec_command 可能被利用。", recommendation: "验证命令参数，避免拼接用户输入。" },
    },
    {
      keywords: ["B602", "shell", "true"],
      result: { name: "启用 shell=True", description: "subprocess 使用 shell=True 存在命令注入风险。", recommendation: "避免使用 shell=True，使用参数列表传递命令。" },
    },
    {
      keywords: ["B603", "shell", "subprocess"],
      result: { name: "子进程命令注入", description: "子进程调用可能受命令注入攻击。", recommendation: "验证所有参数并使用参数列表而非字符串。" },
    },
    {
      keywords: ["B604", "shell", "os.system"],
      result: { name: "Shell 命令注入", description: "os.system 调用存在命令注入风险。", recommendation: "使用 subprocess 并避免 shell=True。" },
    },
    {
      keywords: ["B605", "shell", "injection"],
      result: { name: "Shell 注入", description: "构造系统命令时未正确转义参数。", recommendation: "使用 shlex.quote() 转义参数或使用参数列表。" },
    },
    {
      keywords: ["B606", "start_process_with_shell"],
      result: { name: "启动进程时使用 Shell", description: "启动进程时使用了 shell，存在注入风险。", recommendation: "禁用 shell 并使用直接参数。" },
    },
    {
      keywords: ["B607", "start_process_with_partial_path"],
      result: { name: "使用相对路径调用可执行文件", description: "使用相对路径调用可执行文件可能被路径劫持。", recommendation: "使用绝对路径调用系统命令。" },
    },
    {
      keywords: ["B608", "sql", "injection"],
      result: { name: "Python SQL 注入", description: "字符串拼接 SQL 查询存在注入风险。", recommendation: "使用参数化查询或 ORM。" },
    },
    {
      keywords: ["B609", "linux", "command"],
      result: { name: "Linux 命令注入", description: "使用了可能受注入攻击的 Linux 命令。", recommendation: "避免拼接用户输入到命令中。" },
    },
    {
      keywords: ["B610", "django", "sql"],
      result: { name: "Django SQL 注入", description: "Django 原始 SQL 查询可能受注入攻击。", recommendation: "使用 Django ORM 替代原始 SQL。" },
    },
    {
      keywords: ["B611", "django", "extra"],
      result: { name: "Django extra() 注入", description: "Django extra() 方法存在 SQL 注入风险。", recommendation: "使用 Django ORM 的安全查询方法。" },
    },
    {
      keywords: ["B701", "jinja2", "template"],
      result: { name: "Jinja2 模板注入", description: "用户输入直接用于渲染 Jinja2 模板可能导致模板注入。", recommendation: "使用自动转义并使用 Template 替代 Environment。" },
    },
    {
      keywords: ["B702", "mako", "template"],
      result: { name: "Mako 模板注入", description: "Mako 模板渲染可能存在注入风险。", recommendation: "避免将用户输入直接传入模板。" },
    },
  ],

  // === checkov (IaC 扫描) ===
  checkov: [
    {
      keywords: ["CKV_AWS", "s3", "public", "acl"],
      result: { name: "S3 存储桶公开访问", description: "AWS S3 存储桶配置了公开访问权限。", recommendation: "禁用 S3 存储桶的公开访问权限，使用桶策略限制访问。" },
    },
    {
      keywords: ["CKV_AWS", "s3", "encryption"],
      result: { name: "S3 存储桶未加密", description: "AWS S3 存储桶未启用服务端加密。", recommendation: "启用 S3 默认加密（AES-256 或 AWS KMS）。" },
    },
    {
      keywords: ["CKV_AWS", "sg", "ingress", "0.0.0.0"],
      result: { name: "安全组入站规则过于宽松", description: "安全组允许来自全网的入站流量。", recommendation: "限制入站规则的源 IP 范围，仅允许必要的端口和地址。" },
    },
    {
      keywords: ["CKV_AWS", "ec2", "public"],
      result: { name: "EC2 实例公开暴露", description: "EC2 实例直接关联了公网 IP。", recommendation: "使用负载均衡器或 NAT 网关替代直接公网暴露。" },
    },
    {
      keywords: ["CKV_AWS", "rds", "public"],
      result: { name: "RDS 数据库公开访问", description: "RDS 数据库实例允许公开访问。", recommendation: "将 RDS 部署在私有子网中，禁用公开访问。" },
    },
    {
      keywords: ["CKV_AWS", "rds", "encryption"],
      result: { name: "RDS 未启用加密", description: "RDS 实例未启用存储加密。", recommendation: "启用 RDS 加密以保护静态数据。" },
    },
    {
      keywords: ["CKV_AWS", "iam", "admin", "policy", "wildcard"],
      result: { name: "IAM 策略过于宽松", description: "IAM 策略包含通配符权限（*）。", recommendation: "遵循最小权限原则，仅授予必要的权限。" },
    },
    {
      keywords: ["CKV_AWS", "kms", "key", "rotation"],
      result: { name: "KMS 密钥未启用自动轮换", description: "AWS KMS 密钥未配置自动轮换。", recommendation: "启用 KMS 密钥的自动年度轮换。" },
    },
    {
      keywords: ["CKV_AWS", "lambda", "tracing"],
      result: { name: "Lambda 未启用追踪", description: "Lambda 函数未启用 AWS X-Ray 追踪。", recommendation: "启用 X-Ray 追踪以监控函数性能。" },
    },
    {
      keywords: ["CKV_AWS", "cloudtrail", "enabled"],
      result: { name: "CloudTrail 未启用", description: "AWS 账户未启用 CloudTrail 日志记录。", recommendation: "在所有区域启用 CloudTrail 并配置日志归档。" },
    },
    {
      keywords: ["CKV_GCP"],
      result: { name: "GCP 安全配置问题", description: "GCP 资源配置不符合安全最佳实践。", recommendation: "遵循 GCP 安全基础框架的建议进行配置。" },
    },
    {
      keywords: ["CKV_AZURE"],
      result: { name: "Azure 安全配置问题", description: "Azure 资源配置不符合安全最佳实践。", recommendation: "遵循 Azure 安全基准的建议进行配置。" },
    },
    {
      keywords: ["CKV_DOCKER", "root"],
      result: { name: "Docker 容器以 root 运行", description: "Docker 容器默认以 root 用户运行。", recommendation: "使用 USER 指令指定非 root 用户运行容器。" },
    },
    {
      keywords: ["CKV_DOCKER", "sensitive", "env"],
      result: { name: "Dockerfile 包含敏感环境变量", description: "Dockerfile 中硬编码了敏感环境变量。", recommendation: "使用 Docker Secrets 或运行时环境变量注入。" },
    },
    {
      keywords: ["CKV_K8S", "privilege", "escalation"],
      result: { name: "容器允许权限提升", description: "Kubernetes Pod 配置允许权限提升。", recommendation: "设置 allowPrivilegeEscalation=false。" },
    },
    {
      keywords: ["CKV_K8S", "readOnlyRootFilesystem"],
      result: { name: "容器根文件系统未设为只读", description: "容器的根文件系统未设置为只读。", recommendation: "设置 readOnlyRootFilesystem=true 以增强安全性。" },
    },
    {
      keywords: ["CKV_K8S", "capabilities", "drop"],
      result: { name: "容器未丢弃 Linux 能力", description: "未配置丢弃不必要的 Linux 内核能力。", recommendation: "设置 capabilities.drop=['ALL'] 并仅添加必要的能力。" },
    },
  ],
}

// ─── CVE/依赖漏洞通用描述 ──────────────────────────────────────────────────

// ─── 主翻译函数 ──────────────────────────────────────────────────────────

/**
 * 将漏洞列表中的英文描述翻译为中文
 * 
 * 保留原文不变，将中文翻译追加到 description 和 recommendation 后，
 * 以 【中文】 标记分隔。name 字段保留原始名称不变。
 *
 * @param vulnerabilities 原始漏洞列表
 * @param scannerName 扫描器名称
 * @returns 追加中文注释后的漏洞列表
 */
export function translateVulnerabilities(
  vulnerabilities: Vulnerability[],
  scannerName?: string,
): Vulnerability[] {
  return vulnerabilities.map(vuln => {
    const translated = matchChinese(vuln, scannerName)
    if (translated) {
      return {
        ...vuln,
        name: vuln.name, // 保留原始名称不变
        description: vuln.description
          ? `${vuln.description}\n\n【中文】${translated.description}`
          : translated.description || vuln.description,
        recommendation: vuln.recommendation
          ? `${vuln.recommendation}\n\n【中文】${translated.recommendation}`
          : translated.recommendation || vuln.recommendation,
      }
    }
    return vuln
  })
}

/**
 * 根据漏洞信息匹配中文描述
 * 仅返回中文翻译部分，不包含原文
 */
function matchChinese(
  vuln: Vulnerability,
  scannerName?: string,
): Partial<DescriptionMap> | null {
  const searchText = `${vuln.name} ${vuln.cve} ${vuln.description} ${vuln.recommendation}`.toLowerCase()
  const source = vuln.source || scannerName || ""

  // 1. 优先按扫描器匹配
  if (source && BUILTIN_RULES[source]) {
    for (const rule of BUILTIN_RULES[source]) {
      if (rule.keywords.some(k => searchText.includes(k.toLowerCase()))) {
        return rule.result
      }
    }
  }

  // 2. 按通用关键词匹配
  for (const rule of COMMON_RULES) {
    if (rule.keywords.some(k => searchText.includes(k.toLowerCase()))) {
      return rule.result
    }
  }

  // 3. CVE 格式匹配 — 提供通用的中文说明，不猜测漏洞类型
  const cveMatch = vuln.cve?.match(/CVE-\d{4}-\d{4,}/i)
  if (cveMatch) {
    const cveId = cveMatch[0]
    const pkg = vuln.name || ""
    return {
      description: `检测到 ${cveId} 影响 ${pkg}。详情请查阅国家信息安全漏洞库(CNNVD)或 NVD 官方公告。`,
      recommendation: `升级 ${pkg} 到包含该 CVE 修复的最新版本。`,
    }
  }

  // 4. GHSA (GitHub Advisory) 匹配
  if (vuln.cve?.startsWith("GHSA-")) {
    return {
      description: `检测到 GitHub 安全公告 ${vuln.cve}，影响 ${vuln.name || "依赖包"}。`,
      recommendation: `升级 ${vuln.name || "受影响组件"} 到最新版本。参考 GHSA 公告获取详细信息。`,
    }
  }

  // 5. npm audit / pip audit / dependency check 等扫描器
  if (source === "npm-audit" || source === "pip-audit" || source === "dependency-check") {
    const pkg = vuln.name || ""
    return {
      description: `检测到依赖包 ${pkg} 存在已知安全漏洞。建议升级到修复版本。`,
      recommendation: `运行包管理器的更新命令（如 npm update、pip install --upgrade）修复该漏洞。`,
    }
  }

  return null
}
