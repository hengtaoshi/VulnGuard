---
name: dev-workflow
description: 整合开发全流程：需求沟通→项目同步→Docker部署→审查规则→服务器禁令→设计规范→问题定位→Windows环境
type: user
scope: global
created: 2026-06-03
priority: high
---
# 整合开发全流程规则

---

## 一、需求沟通 → demo 确认 → 动手

### 新需求处理流程

1. **先沟通细节** — 提问澄清：目标用户、交互流程、页面位置、参考样例
2. **总结理解给用户确认**
3. **先做 demo.html** — 纯 HTML+CSS+JS，展示 UI 效果和交互流程
4. **用户确认 demo 后再写真实代码**

**Why：** 避免理解偏差导致返工，确保做出来的东西符合预期。

---

## 二、项目可视化系统协作流程

用户有一个**项目可视化系统**（Web 端项目管理平台），开发任何功能时必须按此流程同步到系统。

### 系统访问信息

| 项目     | 地址                                                                       |
| ------ | ------------------------------------------------------------------------ |
| 前端页面   | `http://localhost:5173`（`cd project-visualizer/frontend && npm run dev`） |
| 后端 API | `http://124.221.92.130:3001`                                             |
| 测试账号   | `admin@test.com` / `123456`                                              |
| 认证方式   | `Authorization: Bearer <token>`                                          |

### 标准工作流程

```
1️⃣ 用户提出新需求
2️⃣ 沟通需求 + 出计划（分解为具体任务）
3️⃣ 同步到项目管理系统（创建项目 → 添加任务，status=todo）
4️⃣ 开发中实时更新进度
5️⃣ 用户随时查看 http://localhost:5173
```

### 进度更新规则

| 时机      | 操作                                   |
| ------- | ------------------------------------ |
| 开始做一个任务 | status → `in_progress`，progress → 10 |
| 任务完成一半  | progress → 50~70                     |
| 任务完成    | status → `done`，progress → 100       |
| 发现新任务   | 添加新任务，status → `todo`                |

**每完成一个子任务立即更新，不允许攒到整个项目完成再更新。**

### API 速查

```
POST /api/auth/login              # 登录，获取 token
POST /api/projects                # 创建项目
POST /api/tasks/project/:projectId # 添加任务
PUT  /api/tasks/:id               # 更新任务（最常用）
```

---

## 三、代码改动前必须告知

在进行任何代码修改、新增或删除之前，必须先用清晰的语言向用户说明具体要改动哪些文件、改什么内容、为什么改。

- 列出：文件路径、改动性质（新增/修改/删除）、改动摘要、预期效果
- 多个文件用列表逐一说明
- 得到用户确认后再执行改动

---

## 四、完成后自动审查

每完成一轮代码改动后，必须自动对改动进行全面审查：

- 语法/类型错误
- 逻辑正确性
- 与现有代码风格一致
- 命名合理性
- 边界情况处理
- 审查结果以 ✅/⚠️/❌ 列表呈现

---

## 五、部署原则：全面容器化

- **禁止**直接将服务进程安装在宿主机系统上
- 宿主机仅保留：Docker Engine、docker-compose、基础运维工具
- 每个服务必须提供 Dockerfile
- 多服务组合必须提供 docker-compose.yml
- 数据持久化使用 Docker volumes
- 环境变量通过 .env 或 Docker secrets 传递
- 日志输出到容器 stdout/stderr

---

## 六、服务器操作禁令

IP: `124.221.92.130` | 密钥: `C:\Users\SHT\.ssh`

### 绝对禁止命令

| 级别  | 命令                                     | 后果        |
| --- | -------------------------------------- | --------- |
| 🔴  | `rm -rf /`、`rm -rf /*`                 | 系统变砖      |
| 🔴  | `rm -rf /var`、`/etc`、`/boot`           | 删除关键目录    |
| 🔴  | `mkfs.*`、`dd if=/dev/zero of=/dev/sda` | 格式化/擦写磁盘  |
| 🔴  | `:(){ :\|:& };:`                       | Fork 炸弹   |
| 🟠  | `chmod -R 777 /`、`chown -R nobody /`   | 权限混乱      |
| 🟠  | `halt`、`poweroff`、`shutdown -h now`    | 关机（需用户确认） |
| 🟠  | `iptables -F`（默认策略 DROP 时）             | 断网        |
| 🟠  | `systemctl stop sshd`                  | 断开 SSH    |
| 🟡  | 非交互 `wget ... \| bash`                 | 安装不明脚本    |

### 保命原则

1. 任何 `rm -rf` 前必须先 `ls` 确认路径
2. 操作前先备份（`cp -r /etc /etc.bak`）
3. 优先用 `mv` 到临时目录代替直接删除
4. 不确定的命令先问用户

---

## 七、问题定位铁律（本轮教训总结）

### 7.1 先确认环境再动手

用户报 bug 后，第一件事不是翻本地代码，而是：

```
1. 问用户：你在哪个域名/端口访问？
2. 看浏览器控制台：报什么错？404/500/JS 错误？
3. 确认服务在哪跑：本地开发 / 服务器 Docker / 服务器裸进程
4. SSH/查日志：确认真实运行状态
```

**Why：** 在错误的环境上花时间是最昂贵的浪费时间。今天"白的"问题在本地修了一轮代码，结果根因在服务器上文件结构错了。

### 7.2 改服务器前先看完整文件结构

`docker exec` 进容器后第一件事：

```bash
docker exec <container> find /app -type f | sort
# 或
docker exec <container> ls -la /app/frontend/
```

**不要凭本地目录结构推断服务器结构**——Docker 镜像可能构建自不同分支、不同时间点的代码。今天 webfonts 移错位置就是没先看完整结构。

### 7.3 改完立即验证

每次修改后立即验证：

```bash
# 静态文件 200？
curl -s -o /dev/null -w '%{http_code}' http://.../js/chart.umd.min.js
# 页面逻辑？ 
curl -s http://.../ | grep -o '关键内容'
# API 正常？
curl -s http://.../api/health
```

### 7.4 安全硬伤优先修

REVIEW.md 列的 🔴 问题（SMTP 凭证明文、Flask debug=True、Alpha/Beta 造假等）优先级高于所有功能需求。每次只修一个，修完即验证。

---

## 八、设计一致性规则

- **色彩**：Terminal Night (`#0D1117`) 暗色底，Terminal Green (`#00D68F`) 主强调，Shade 中性色阶
- **字体**：Display JetBrains Mono，正文系统 Sans-Serif
- **圆角**：卡片 12dp，按钮 50% 药丸形，输入框 12dp
- **间距**：4/8/12/16/24/32/64dp 体系
- **交互**：药丸形 PillButton，列表项深色面 `#161B22`，选中态绿色高亮
- **暗色优先**：始终保持暗色主题

任何新增功能先对照以上规则，确保视觉上无缝融入。

---

## 九、UI/UX 设计参考库

**位置**：`D:\demo\awesome-design-md-main\design-md\`（70+ 品牌设计方案）

**用法**：

1. 设计前先翻参考库，找同类产品设计
2. 引用具体方案（如"参考 stripe/ 数据表格布局"）
3. 跨品牌组合优秀元素，但保持风格统一
4. 搜索：`search_content path:"D:\demo\awesome-design-md-main\design-md" pattern:"关键词"`

---

## 十、Windows 环境开发规范

- 路径用正斜杠 `/`，避免硬编码反斜杠
- 用 `cross-env` 设置环境变量，不用 `VAR=value`
- 用 `chokidar` 做文件监听
- 避免 `cd X && cmd` 链，用 `--prefix` / `-C` 参数
- 避免 `$VAR` 展开、`$(...)` 子 shell、后台 `&`、heredoc `<<`
- 批处理用 `dir` / `copy` / `del`，不用 `ls` / `cp` / `rm`

-
