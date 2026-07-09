# My Agent — 生产级开发路线图

## 当前状态: v0.6

```
已具备: LangGraph 引擎 + 13 个工具 + RAG 知识库 + JS/API/SPA 分析 + Web 前端
能做的: 输入 URL → 自动爬取 + JS/API/SPA 分析 + JWT 审计 + search_knowledge 查知识库 → 输出带分类/CVSS/修复方案的报告
```

---

## v0.5 — RAG 知识库 ✅

> 从"模型自己判断"升级为"有据可查"

### 工程改动

| 模块 | 内容 |
|---|---|
| 文件拆分 | `agent/core.py` → `agent/` `config.py` `prompts.py` `agent.py` `tools/` `rag.py` |
| 知识库 | `agent/knowledge/` — OWASP Top 10、CVE 精选、修复方案 Markdown |
| 向量库 | Chroma 持久化 + Qwen3-Embedding-0.6B（1024 维本地模型） |
| 精排 | Qwen3-Reranker-0.6B CrossEncoder 两阶段检索 |
| 新工具 | `search_knowledge(query)` — 两阶段检索最相关漏洞案例和修复建议 |
| System Prompt | "扫描发现可疑行为时，先调用 search_knowledge 查找已知漏洞模式，再下结论" |

### 实际交付

```
v0.4: 8 个工具，~900 行 core.py
v0.5: 9 个工具，14 个文件，~1500 行
      两阶段 RAG: Embedding 粗排 → Reranker 精排
      知识库: 3 个源文档 → 29 个向量块
      "发现 SQL 注入，匹配 OWASP A03 Injection，CVSS 参考 9.8，
       修复: 参数化查询..."   ← 有风险分类 + CVSS 参考 + 代码级修复方案
```

---

## v0.6 — 扫描基础 + 静态分析 + 浏览器渲染 ✅

> 先把扫描边界、测试和稳定性收紧，再深挖 JS 源码 + SPA 渲染

### 为什么放在这里？

当前 9 个工具全部基于 `requests` 库——静态 HTML 没问题，但遇到 React/Vue SPA 或 JS 中泄露的敏感信息就盲了。扩能力之前先收紧目标范围、限速、超时和回归测试，避免后续主动验证阶段失控。

### 工程改动

| 模块 | 内容 |
|---|---|
| 扫描边界 | 明确只扫同域 / 白名单目标，统一 URL 规范化、去重、最大深度、最大页面数 |
| 请求稳定性 | 统一 requests session、超时、User-Agent、重试、限速、错误分类 |
| 测试回归 | 为 crawl / sitemap / batch_scan / RAG 查询增加靶场集成测试和固定样例 |
| JS 解析 | 提取 `<script>` 和外部 `.js` 文件 → 正则匹配 API Key / Token / 内部端点 / debug 开关 |
| 敏感泄露 | 自动解析 `robots.txt` / `sitemap.xml` / HTML 注释 / sourcemap 残留 |
| JWT 解码 | 发现 JWT Token → 自动解码 header + payload → 检查 `alg:none` 等配置漏洞 |
| Headless 渲染 | Playwright 集成 → 渲染 SPA 页面 → 提取渲染后的 DOM 和网络请求 |
| API 发现 | 从 JS 文件中提取 API 路径模式 (`/api/v1/...`, `/graphql`) + OpenAPI schema 探测 |
| 新工具 | `analyze_js(url)` — 下载 JS 并扫描敏感信息 |
|  | `decode_jwt(token)` — 解码 JWT 并做安全审计 |
|  | `discover_api(url)` — 探测 OpenAPI / GraphQL / Swagger 端点 |
|  | `render_page(url)` — Playwright headless 渲染单页应用 |

### 能力提升

```
v0.5: 只扫 HTML 表面 → 看不到 Vue 渲染内容 → 漏掉 JS 中硬编码的 API Key
v0.6: 渲染 SPA → 提取所有 JS → 发现 `apiKey: "sk-xxx"` → 报告密钥泄露
      从 main.js 中提取 12 个内部 API 端点 → 自动加入扫描队列
```

---

## v0.7 — LFI 专项验证工具

> 先解决真实卡点：发现方向后，能稳定验证本地文件包含并收束报告

### 为什么放在这里？

v0.6 已经能发现 `language` 这类可疑参数，也能判断出白名单、路径约束和响应差异。但目前 Agent 只能靠 `http_get` 自由尝试 payload，遇到 `Illegal path specified!`、目录白名单、后缀限制时容易循环，最后触发 LangGraph 步数上限。先补一个专项工具，比直接进入 UI 更能提升实战产出。

### 工程改动

| 模块 | 内容 |
|---|---|
| LFI 参数验证 | 新增 `test_lfi_param(url, param)`，对指定参数自动建立 baseline 并验证文件包含迹象 |
| Payload 模板 | 内置 LFI payload 集: 正常值、非法值、目录穿越、URL 编码、双重编码、白名单目录绕过 |
| 响应差分 | 对正常值 / 非法值 / payload 响应做长度、状态码、关键词和正文差分 |
| Flag 提取 | 自动匹配 `flag{...}` / `ctf{...}` / `BUGKU{...}` / `key{...}` 等 CTF 常见格式 |
| 尝试预算 | 每个参数最多尝试固定数量 payload，连续失败后停止，避免 Agent 无限循环 |
| 证据摘要 | 输出命中的 payload、响应摘要、路径约束、置信度和下一步建议 |

### 能力提升

```
v0.6: 发现 ?language=en 有差异 → 推测 LFI → 反复 http_get 尝试 → 可能超步数
v0.7: test_lfi_param(url, "language") → 自动测试白名单/编码/穿越变体
      → 若命中 flag 直接提取；若未命中，也输出明确约束和失败样本
```

---

## v0.8 — Agent UI 2.0 (Hermes 风格)

> 不是聊天框，是 AI Agent 工作站

### 为什么放在这里？

v0.5-v0.7 给了 Agent 更多工具，但前端仍然是纯文本框——用户完全看不到 Agent 在做什么、调了哪些工具、走到了哪一步。**工具越多，交互盲区越大**。v0.8 不涉及后端新能力，专注把已有能力可视化。

### 当前 vs 目标

| 能力 | v0.5 的 index.html | v0.8 Hermes 风格 |
|---|---|---|
| 流式对话 | ✅ 基础流式 | ✅ 细腻动画 + markdown 真渲染 |
| **工具调用展示** | ❌ 完全隐藏 | ✅ 实时卡片（启动→执行→完成→结果摘要） |
| **分析轨迹** | ❌ 无 | ✅ 可折叠工具轨迹和阶段摘要 |
| **代码高亮** | ❌ 正则简易替换 | ✅ Prism.js 真语法高亮 |
| **扫描进度** | ❌ 无 | ✅ 步骤指示器（爬取 → 测绘 → 扫描 → 报告） |
| **漏洞卡片** | ❌ 纯文本 | ✅ 结构化风险卡片（等级 + CVE + CVSS + 复现步骤） |
| **会话管理** | ❌ 关页面即丢失 | ✅ 侧边栏历史会话（localStorage 持久化） |
| 主题系统 | 1 个暗色 | glassmorphism 暗色主题 + css variables 可扩展 |

### 工程改动

| 模块 | 内容 |
|---|---|
| **后端改造** | WebSocket 协议升级 — 透传 LangGraph 事件类型 |
|  | `on_tool_start` → 推工具名 + 参数到前端 |
|  | `on_tool_end` → 推工具输出摘要到前端 |
|  | `on_chat_model_stream` → 保持现有 token 流 |
| **工具调用卡片** | 橙色加载态（工具名 + 参数） → 绿色完成态（结果摘要，展开看详情） → 红色失败态 |
| **分析摘要展示** | 将扫描阶段、工具轨迹、关键发现整理成折叠式摘要（默认收起） |
| **扫描进度条** | 步骤指示器: 🔍爬取 → 📊测绘 → ⚔️扫描 → 🧠知识库验证 → 📝报告 |
| **漏洞卡片** | 从 Agent 输出解析 → 渲染为结构化卡片: `[🔴高危] SQL注入 — CVSS 9.8 — CVE-2023-XXXXX` |
| **会话侧边栏** | 左侧可收起面板 → 历史对话列表 → 点击切换/删除 → localStorage 持久化 |
| **Markdown 引擎** | 引入 marked.js + Prism.js → 代码块语法高亮 + 表格 + 链接 |
| **视觉系统** | Glassmorphism 暗色主题 + Inter/JetBrains Mono 字体 + 统一图标系统 |

### 技术选型

```
不引入 React / Vue 框架 ← 留给 v1.3
v0.8 用: vanilla JS + marked.js + Prism.js + CSS variables
保持: 单文件 HTML 或拆分为 web/ 目录下的 index.html + style.css + app.js
后端改动: <80 行
前端重写: ~600 行（从当前 290 行重构）
```

### 前端架构草图

```
┌──────────────────────────────────────────────────┐
│  Header: 🔍 Web Scanner v0.8    会话:3  已连接 🟢 │
├────────────┬─────────────────────────────────────┤
│ 侧边栏     │  主对话区                            │
│ (可收起)   │                                     │
│            │  ┌─────────────────────────────┐    │
│ 📋 会话1    │  │ 🔍 爬取中…  crawl(testphp)  │    │ ← 工具卡片
│ 📋 会话2    │  │ ████████░░ 12/20 页       │    │
│ 📋 会话3 ◀  │  └─────────────────────────────┘    │
│            │                                     │
│ + 新扫描   │  ┌─────────────────────────────┐    │
│            │  │ 分析摘要… (点击展开)          │    │ ← 工具轨迹
│            │  └─────────────────────────────┘    │
│            │                                     │
│            │  🤖 Agent:                          │
│            │  ## 攻击面概览                       │
│            │  发现 15 个页面，3 个安全风险         │
│            │                                     │
│            │  ┌──────────────────────────────┐   │
│            │  │ 🔴 高危  SQL 注入             │   │ ← 漏洞卡片
│            │  │ /login.php?user=admin         │   │
│            │  │ CVSS 9.8 | CVE-2021-44228    │   │
│            │  │ 修复: 参数化查询 →            │   │
│            │  └──────────────────────────────┘   │
│            │                                     │
├────────────┴─────────────────────────────────────┤
│  Footer: [输入 URL 或问题…              ] [发送]  │
└──────────────────────────────────────────────────┘
```

---

## v0.9 — 主动验证引擎 + 证据模型 (DAST Core)

> 不只"看起来像漏洞"，而是"确认这就是漏洞"

### 为什么放在这里？

v0.5-v0.8 的大部分工具仍偏**观测型**——看到异常就报告，无法确认是不是误报。真正的 DAST 需要"注入 → 观察行为差异 → 确认利用"的闭环。UI 做完后可以完整展示这个闭环过程。

### 工程改动

| 模块 | 内容 |
|---|---|
| 响应差分引擎 | 同一端点发两次请求（正常 vs payload）→ 自动 diff 响应差异 |
| Payload 模板引擎 | YAML 定义的 payload 描述语言 → 支持条件注入、编码链、WAF 绕过 |
| 时间盲注检测 | 注入 `SLEEP(3)` / `waitfor delay` → 测量实际响应时间 → 自动标记 |
| OOB 回连检测 | 注入带 callback URL 的 payload → 监听回连确认 RCE/SSRF |
| 渐进式验证 | 发现可疑注入点 → 自动升级 payload 强度 → 尝试提取数据作为确凿证据 |
| 证据模型 | 定义统一 JSON 结构: 目标、请求、响应摘要、payload、diff、置信度、复现步骤 |
| 误报抑制流水线 | 阶段1: 重放验证 (同 payload ×2 不一致=可疑) → 阶段2: 差分对比 → 阶段3: 知识库交叉验证 |
| 外部引擎对接 | 将 sqlmap / nuclei 作为子进程调用，解析结果融入 Agent 报告 |
| 新工具 | `verify_injection(url, param, vuln_type)` — 自动选择验证策略 |
|  | `fuzz_params(url, method)` — 对页面所有参数遍历注入 |
|  | `detect_tech_stack(url)` — 识别框架/语言/版本 → 精准 exploit 选择 |

### 能力提升

```
v0.8: POST ' OR 1=1 → 看到返回全量数据 → "可能是 SQL 注入"
v0.9: POST ' UNION SELECT @@version,user(),database() --
      → 确认提取 MySQL 8.0.36 + root@localhost + 库名 'shop'
      → 时间盲注 SLEEP(3) 实测响应 3127ms
      → 确认为 SQL 注入 | CVSS 9.8 | 误报概率 <1%
```

---

## v1.0 — 认证扫描 + 会话管理

> 登录后的攻击面才是真正的战场

### 为什么放在 v1.0？

有了 v0.9 的深度验证引擎，带认证态去扫描才有实际产出。否则带 Cookie 扫管理后台也用同一套浅层检查，纯浪费时间。

### 工程改动

| 模块 | 内容 |
|---|---|
| 会话管理 | Agent 自动处理登录表单 → 维持 Cookie/Token → 带认证状态继续扫描 |
| 多角色切换 | 先以 user 角色扫描 → 再以 admin 角色重扫 → 对比两个角色的页面差异 (IDOR 检测) |
| 凭证安全 | 凭证仅存内存，不回显，不记录日志，不序列化 |
| Token 刷新 | 检测 JWT / Session 过期 → 自动重新登录 |
| 新工具 | `login(url, username, password)` — 自动识别表单字段并发起登录 |
|  | `set_auth_header(key, value)` — 手动设置 Bearer Token / API Key |
|  | `current_auth_state()` — 查看当前认证状态和角色 |
|  | `compare_roles(url)` — 以不同角色访问同一资源 → IDOR 检测 |

### 能力提升

```
v0.9: 扫公开页面 → 漏掉 90% 的后台漏洞
v1.0: 自动登录 → 带着 Cookie 扫管理面板
      user 角色看 /api/orders/123 → 自己的订单
      admin 角色看 /api/orders/123 → 所有人的订单
      发现越权漏洞 → IDOR 确认
```

---

## v1.1 — 持久化 + 报告 + 对比

> 扫描结果入库，随时回看，能出 PDF

### 工程改动

| 模块 | 内容 |
|---|---|
| 数据库 | SQLite（零配置）→ SQLAlchemy ORM → 3 张表: scans / vulnerabilities / pages |
| 存储 | 每次扫描结果、漏洞列表、页面快照落库 |
| 历史 | `/api/scans` — 历史扫描列表、同站多次扫描对比 |
| 报告 | Markdown → PDF 导出（`weasyprint`） + OWASP ASVS 4.0 合规映射 |
| 新工具 | `compare_scan(id1, id2)` — 对比两次扫描，看漏洞是否修复 |

### 能力提升

```
v1.0: 扫完就没了，关浏览器 = 结果丢失
v1.1: 扫描落库 → 随时回看 → PDF 周报/月报导出
      "上次那 3 个高危修了吗？" → 重新扫对比 → 自动标记 [已修复] [新增] [仍存在]
```

---

## v1.2 — 生产化部署

> 从"单用户玩具"变成"能给人用的服务"

### 工程改动

| 模块 | 内容 |
|---|---|
| 任务队列 | Redis → 多用户提交扫描排队，Worker 进程独立执行 |
| 速率控制 | 对同一目标限速（如每秒 3 请求），避免打挂靶场或被 WAF 封 |
| 鉴权 | API Key 鉴权（`X-API-Key` header） |
| 沙箱隔离 | 扫描在独立子进程中执行，超时自动 kill |
| 日志 | 结构化日志（JSON 格式）+ 审计日志（谁什么时候扫了谁） |
| 部署 | `Dockerfile` + `docker-compose.yml` — 一键部署 |
| 监控 | Prometheus metrics 端点（扫描次数、漏洞数、响应时间） |

---

## v1.3 — 前端框架化 + 多租户

> React 重写前端，完整产品形态

### 工程改动

| 模块 | 内容 |
|---|---|
| 数据库升级 | SQLite → PostgreSQL（生产环境） |
| 多租户 | 每个用户独立的数据视图，权限隔离 |
| 前端重构 | React 19 + Tailwind CSS 4 + shadcn/ui 重写前端 |
| 多 Agent 支持 | 同时管理多个扫描 Agent，组队协作 |
| CI/CD | GitHub Actions — 提交自动测试 + 构建镜像 |
| 文档 | 部署文档 + API 文档 + 用户手册 |

---

## v1.4 — 新赛道

> 2026 年安全新趋势

| 方向 | 内容 |
|---|---|
| **AI 应用安全** | Prompt Injection / Model Inversion / 越狱检测 |
| **SBOM 依赖分析** | `npm audit` / `pip audit` 级别的依赖漏洞自动检测 |
| **API Security 专项** | OWASP API Security Top 10 (2023) / GraphQL 内省 + 递归扫描 |
| **Nuclei 生态对接** | 6000+ 社区模板一键接入，按 CVE 精确匹配 |
| **Agent 自适应渗透** | LLM 根据每次试探结果动态调整下一步策略，而非固定脚本 |

---

## 版本总览

```
v0.4  爬虫 + 前端                  ~1000 行代码
v0.5  ★ 当前  RAG + 文件拆分        ~1500 行
v0.6  扫描基础   边界/测试 + JS/API/SPA   ~2200 行
v0.7  LFI 专项   test_lfi_param + Flag 提取 ~2600 行
v0.8  Agent UI   工具事件流 + 可观测工作台 ~3300 行
v0.9  DAST Core  主动验证 + 证据模型       ~4500 行
v1.0  认证扫描   登录态 + 越权检测         ~5500 行
v1.1  持久化     SQLite + PDF报告          ~6500 行
v1.2  生产化     Redis + Docker            ~8000 行
v1.3  产品化     React + 多租户            ~9500 行
```

## 不变的部分

| 层 | 说明 |
|---|---|
| FastAPI 控制面 | 从一开始就对了，后续版本不会大改 |
| LangGraph 引擎 | v0.3 选型正确，后续只加工具不加引擎复杂度 |
| 分层解耦 | Agent 不 import FastAPI，永远如此 |
| LLM 无关 | LLM 是可替换的接口，不被任何单一厂商绑定 |

## 跨版本持续事项

| 事项 | 说明 |
|---|---|
| 知识库更新 | OWASP / CVE / 修复方案定期同步，随版本扩展 |
| 测试覆盖 | 新工具必须有集成测试 + 靶场回归 |
| 安全审计 | 自身的依赖和代码安全——扫描器自身不能被攻破 |
