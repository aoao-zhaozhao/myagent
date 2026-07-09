"""
Agent 核心模块 —— Web 漏洞审查引擎。

v0.3: 基于 LangGraph 重构
  - LangGraph create_react_agent 替代手写 ReAct 循环
  - ChatOpenAI 指向 DeepSeek
  - 5 个扫描工具: http_get / http_post / analyze_headers / extract_forms / extract_links

v0.4: 深度爬取 + 攻击面测绘
  - 新增 crawl: BFS 爬虫，自动发现所有同域页面
  - 新增 sitemap: 对爬取结果分类（表单页/API/静态页/管理后台）
  - 新增 batch_scan: 批量扫描所有发现页面的安全头
  - System Prompt 更新: 两步工作流（先爬再扫）
"""

import os
from dataclasses import dataclass, field
from typing import AsyncIterator

# ── LangChain imports ──────────────────────────────
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool

# ── HTTP 工具所需 ──────────────────────────────────
import requests
from bs4 import BeautifulSoup

# 靶场多为自签证书，禁用 SSL 警告
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════
# 配置
# ═══════════════════════════════════════════════════════

@dataclass
class AgentConfig:
    api_key: str = field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    base_url: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    model: str = field(default_factory=lambda: os.getenv("DEEPSEEK_MODEL", "deepseek-chat"))
    max_turns: int = 20


# ═══════════════════════════════════════════════════════
# System Prompt — Web 安全专家
# ═══════════════════════════════════════════════════════

SYSTEM_PROMPT = """\
你是一个Web应用安全审计专家。你的任务是扫描目标Web应用并发现漏洞。

## 工作流程 (v0.4 — 先爬取再扫描)
### 第一步: 攻击面测绘
1. 用 crawl 工具从根 URL 出发，自动发现所有同域页面和端点
2. 用 sitemap 工具对发现的页面进行分类
3. 根据分类结果，识别出最值得深入测试的页面（登录页、表单页、API端点）

### 第二步: 深度扫描
4. 用 batch_scan 对所有关键页面做批量安全头检查
5. 对每个表单/输入点用 http_post 发送测试 payload（XSS、SQLi）
6. 用 http_get 探测敏感路径（/.env、/admin、/backup等）

## 输出格式
扫描完成后，输出一份 **完整的安全审计报告**:

### 攻击面概览
- 发现的页面总数、分类统计
- 攻击面评估（大/中/小）

### 漏洞列表
每个发现按以下格式:
- **漏洞类型**: (XSS / SQL注入 / CSRF / 安全头缺失 / 信息泄露 / ...)
- **风险等级**: 🔴高危 / 🟡中危 / 🟢低危
- **位置**: URL + 参数名/Header名
- **证据**: 响应中观察到的具体内容
- **复现步骤**: 如何重现
- **修复建议**: 具体的代码/配置修改方案

## 扫描原则
- 仅分析 target URL 对应的主机，不要扫描外部链接
- XSS payload: <script>alert(1)</script>、<img src=x onerror=alert(1)>
- SQLi payload: ' OR '1'='1、' OR 1=1--、admin'--
- 注意响应中是否反射了 payload（XSS）或出现了数据库错误（SQLi）
- 响应体可能很长，重点关注前 3000 字符中的关键信息

请用中文回复。"""


# ═══════════════════════════════════════════════════════
# 工具定义
# ═══════════════════════════════════════════════════════

@tool
def http_get(url: str) -> str:
    """
    发送 HTTP GET 请求到目标 URL，返回状态码、响应头、页面内容（前 3000 字符）。

    用途: 获取页面内容、探测端点是否存在、触发反射型漏洞。

    参数:
        url: 目标 URL（如 http://example.com/page?id=1）
    """
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers_str = "\n".join(f"  {k}: {v}" for k, v in r.headers.items())
        return (
            f"[GET] {url}\n"
            f"Status: {r.status_code} {r.reason}\n"
            f"Response Headers:\n{headers_str}\n\n"
            f"Body (first 3000 chars):\n{r.text[:3000]}"
        )
    except requests.exceptions.Timeout:
        return f"[GET] {url}\nError: 请求超时"
    except requests.exceptions.ConnectionError:
        return f"[GET] {url}\nError: 无法连接到目标服务器"
    except Exception as e:
        return f"[GET] {url}\nError: {str(e)}"


@tool
def http_post(url: str, data: str = "", content_type: str = "application/x-www-form-urlencoded") -> str:
    """
    发送 HTTP POST 请求，用于向表单/API 提交测试 payload。

    用途: 测试 XSS 反射、SQL 注入、命令注入、XXE 等。

    参数:
        url: 目标 URL
        data: POST body 数据（如 username=admin&password=' OR '1'='1）
        content_type: Content-Type（默认 application/x-www-form-urlencoded）
    """
    try:
        headers = {"Content-Type": content_type}
        r = requests.post(url, data=data, headers=headers, timeout=10, allow_redirects=True, verify=False)
        return (
            f"[POST] {url}\n"
            f"Payload: {data[:500]}\n"
            f"Status: {r.status_code}\n"
            f"Body (first 3000 chars):\n{r.text[:3000]}"
        )
    except Exception as e:
        return f"[POST] {url}\nError: {str(e)}"


@tool
def analyze_headers(url: str) -> str:
    """
    分析目标 URL 的 HTTP 安全响应头。

    检查项:
        - Content-Security-Policy (CSP)
        - Strict-Transport-Security (HSTS)
        - X-Frame-Options
        - X-Content-Type-Options
        - Referrer-Policy
        - Permissions-Policy
        - Set-Cookie (HttpOnly / Secure / SameSite)

    参数:
        url: 目标 URL
    """
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = r.headers

        checks = {
            "Content-Security-Policy": "防止XSS和数据注入攻击",
            "Strict-Transport-Security": "强制HTTPS连接",
            "X-Frame-Options": "防止点击劫持",
            "X-Content-Type-Options": "防止MIME类型嗅探",
            "Referrer-Policy": "控制Referer信息泄露",
            "Permissions-Policy": "限制浏览器API使用",
        }

        result = [f"安全头分析 - {url}", f"HTTP Status: {r.status_code}", ""]
        issues = 0

        for header, desc in checks.items():
            if header in headers:
                result.append(f"  ✅ {header}: {headers[header]}")
            else:
                result.append(f"  ❌ {header} — 缺失 ({desc})")
                issues += 1

        # Cookie 安全
        cookies = headers.get("Set-Cookie", "")
        if cookies:
            cookie_flags = []
            if "HttpOnly" not in cookies:
                cookie_flags.append("HttpOnly 未设置")
            if "Secure" not in cookies:
                cookie_flags.append("Secure 未设置")
            if "SameSite" not in cookies:
                cookie_flags.append("SameSite 未设置")
            if cookie_flags:
                result.append(f"  ⚠️ Cookie 安全问题: {', '.join(cookie_flags)}")
                issues += len(cookie_flags)
        else:
            result.append("  ℹ️ 未设置 Cookie")

        result.append(f"\n共发现 {issues} 个安全问题")
        return "\n".join(result)
    except Exception as e:
        return f"analyze_headers Error: {str(e)}"


@tool
def extract_forms(url: str) -> str:
    """
    从页面 HTML 中提取所有 <form> 标签及其输入参数。

    返回: 每个表单的 action、method、以及所有 input/textarea/select 的 name/type。

    用途: 发现可测试的注入点。

    参数:
        url: 目标页面 URL
    """
    try:
        r = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return f"[extract_forms] {url}\n未发现任何表单。"

        result = [f"[extract_forms] {url} — 发现 {len(forms)} 个表单", ""]
        for i, form in enumerate(forms, 1):
            action = form.get("action", "(当前页面)")
            method = form.get("method", "GET").upper()
            result.append(f"表单 #{i}: {method} {action}")

            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                tag = inp.name
                name = inp.get("name", "(无名称)")
                itype = inp.get("type", "text") if tag == "input" else tag
                result.append(f"  [{itype}] {name}")
            result.append("")

        return "\n".join(result)
    except Exception as e:
        return f"extract_forms Error: {str(e)}"


@tool
def extract_links(url: str) -> str:
    """
    从页面 HTML 中提取所有 <a href> 链接。

    用途: 发现更多攻击面（API 端点、隐藏页面、管理后台等）。

    参数:
        url: 目标页面 URL
    """
    try:
        from urllib.parse import urljoin, urlparse

        r = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a", href=True)

        base_domain = urlparse(url).netloc
        internal, external = [], []

        for link in links:
            href = urljoin(url, link["href"])
            parsed = urlparse(href)
            label = link.get_text(strip=True) or "(无文本)"
            entry = f"  {href}  — {label}"
            if parsed.netloc == base_domain or parsed.netloc == "":
                internal.append(entry)
            else:
                external.append(entry)

        result = [
            f"[extract_links] {url}",
            f"内部链接 ({len(internal)}):",
        ]
        result.extend(internal[:30])  # 最多 30 条
        result.append(f"\n外部链接 ({len(external)}) — 不扫描:")
        result.extend(external[:10])
        result.append(f"\n总计: {len(internal) + len(external)} 个链接")
        return "\n".join(result)
    except Exception as e:
        return f"extract_links Error: {str(e)}"


@tool
def crawl(root_url: str, max_depth: int = 2, max_pages: int = 30) -> str:
    """
    从根 URL 出发，BFS 爬取同域下所有可达页面。

    自动发现:
        - 页面中所有 <a href> 内部链接
        - 常见敏感路径: /admin, /api, /.env, /backup, /robots.txt, /sitemap.xml, /.git/HEAD
        - <script src> 和 <link href> 中的 JS/CSS 资源路径（可能泄露 API 端点）

    参数:
        root_url: 根 URL（如 http://example.com）
        max_depth: 最大爬取深度（默认 2，建议 2-3）
        max_pages: 最多爬取页数（默认 30）
    """
    from urllib.parse import urljoin, urlparse, urldefrag

    base_domain = urlparse(root_url).netloc
    visited: set[str] = set()
    # BFS 队列: (url, depth)
    queue: list[tuple[str, int]] = [(root_url.rstrip("/"), 0)]
    discovered: list[dict] = []

    # 常见的敏感探测路径
    sensitive_paths = [
        "/admin", "/admin/login", "/backup", "/bak",
        "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
        "/api", "/api/v1", "/swagger", "/docs",
        "/phpinfo.php", "/info.php", "/test.php",
        "/wp-admin", "/wp-login.php",
        "/console", "/actuator", "/debug",
    ]

    while queue and len(discovered) < max_pages:
        url, depth = queue.pop(0)
        norm = url.rstrip("/")

        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = requests.get(url, timeout=8, allow_redirects=True, verify=False)
            status = r.status_code
            content_type = r.headers.get("Content-Type", "")

            discovered.append({
                "url": url,
                "status": status,
                "content_type": content_type.split(";")[0] if content_type else "unknown",
                "size": len(r.text),
            })

            # 只对 HTML 页面提取链接
            if "text/html" not in content_type:
                continue

            if depth >= max_depth:
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            # 提取 <a href>
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                href, _ = urldefrag(href)  # 去 fragment
                parsed = urlparse(href)
                if parsed.netloc == base_domain or parsed.netloc == "":
                    if parsed.scheme in ("http", "https") or parsed.scheme == "":
                        target = urljoin(url, href).rstrip("/")
                        if target not in visited:
                            queue.append((target, depth + 1))

        except Exception:
            continue

    # 探测敏感路径
    sensitive_found: list[str] = []
    for path in sensitive_paths:
        probe_url = urljoin(root_url, path)
        try:
            r = requests.get(probe_url, timeout=5, allow_redirects=False, verify=False)
            if r.status_code not in (404, 500, 502, 503):
                sensitive_found.append(f"  {probe_url} → {r.status_code}")
        except Exception:
            pass

    lines = [
        f"[crawl] 根 URL: {root_url}",
        f"域名: {base_domain}",
        f"爬取深度: {max_depth} | 最多页数: {max_pages}",
        f"发现页面: {len(discovered)}",
        "",
        "── 发现的页面 ──",
    ]
    for d in discovered:
        lines.append(f"  [{d['status']}] {d['content_type']:20s} {d['url']}")

    if sensitive_found:
        lines.append("")
        lines.append("── 敏感路径探测 ──")
        lines.extend(sensitive_found)

    lines.append("")
    lines.append(f"总计: {len(discovered)} 个页面, {len(sensitive_found)} 个敏感路径")
    return "\n".join(lines)


@tool
def sitemap(root_url: str) -> str:
    """
    对 crawl 发现的页面进行智能分类。

    分类维度:
        - 登录/认证页（含 login/signin/auth 关键词）
        - 表单页（含 <form> 标签）
        - API 端点（JSON 响应 / 路径含 api）
        - 管理后台（路径含 admin/management/dashboard）
        - 静态资源（CSS/JS/图片）
        - 其他页面
        - 敏感暴露（.env/.git/phpinfo 等返回了内容）

    参数:
        root_url: 根 URL（会先自动 crawl）
    """
    from urllib.parse import urljoin, urlparse, urldefrag

    base_domain = urlparse(root_url).netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(root_url.rstrip("/"), 0)]
    pages: list[dict] = []

    while queue and len(pages) < 25:
        url, depth = queue.pop(0)
        norm = url.rstrip("/")

        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = requests.get(url, timeout=8, allow_redirects=True, verify=False)
            status = r.status_code
            ct = r.headers.get("Content-Type", "")
            is_html = "text/html" in ct
            is_json = "application/json" in ct

            has_forms = False
            if is_html:
                soup = BeautifulSoup(r.text, "html.parser")
                has_forms = len(soup.find_all("form")) > 0

            pages.append({
                "url": url,
                "status": status,
                "is_html": is_html,
                "is_json": is_json,
                "has_forms": has_forms,
            })

            if is_html and depth < 2:
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = urljoin(url, a["href"])
                    href, _ = urldefrag(href)
                    p = urlparse(href)
                    if (p.netloc == base_domain or p.netloc == "") and p.scheme in ("http", "https", ""):
                        target = href.rstrip("/")
                        if target not in visited:
                            queue.append((target, depth + 1))
        except Exception:
            continue

    # 分类
    categories = {
        "登录/认证页": [],
        "表单页": [],
        "API 端点": [],
        "管理后台": [],
        "静态资源": [],
        "其他页面": [],
    }

    for p in pages:
        url_lower = p["url"].lower()
        path = urlparse(p["url"]).path.lower()

        if any(kw in url_lower for kw in ["login", "signin", "auth", "signup", "register", "sign_on"]):
            categories["登录/认证页"].append(p)
        elif any(kw in path for kw in ["admin", "manage", "dashboard", "backend", "cms"]):
            categories["管理后台"].append(p)
        elif p["is_json"] or "/api" in path or "/v1/" in path or "/v2/" in path:
            categories["API 端点"].append(p)
        elif p["has_forms"]:
            categories["表单页"].append(p)
        elif any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf"]):
            categories["静态资源"].append(p)
        else:
            categories["其他页面"].append(p)

    # 汇总
    total = len(pages)
    lines = [
        f"[sitemap] 攻击面测绘 — {root_url}",
        f"域名: {base_domain}",
        f"发现页面总数: {total}",
        "",
    ]
    for cat, items in categories.items():
        if items:
            lines.append(f"## {cat} ({len(items)}):")
            for it in items[:8]:
                forms_mark = " [含表单]" if it.get("has_forms") else ""
                lines.append(f"  [{it['status']}] {it['url']}{forms_mark}")
            if len(items) > 8:
                lines.append(f"  ... 还有 {len(items) - 8} 个")
            lines.append("")

    lines.append(f"攻击面评级: {'🔴 大' if total > 20 else '🟡 中' if total > 8 else '🟢 小'} ({total} 个页面)")
    return "\n".join(lines)


@tool
def batch_scan(root_url: str) -> str:
    """
    批量扫描目标站点的安全配置。

    自动执行:
        1. crawl 发现所有页面
        2. 对每个页面做安全头检查（CSP/HSTS/X-Frame-Options 等）
        3. 汇总缺失安全头的页面列表
        4. 统计整体安全态势

    参数:
        root_url: 目标根 URL
    """
    from urllib.parse import urljoin, urlparse, urldefrag

    base_domain = urlparse(root_url).netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(root_url.rstrip("/"), 0)]
    results: list[dict] = []

    # 第一步: crawl
    while queue and len(results) < 20:
        url, depth = queue.pop(0)
        norm = url.rstrip("/")
        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = requests.get(url, timeout=8, allow_redirects=True, verify=False)
            headers = dict(r.headers)
            results.append({
                "url": url,
                "status": r.status_code,
                "missing_headers": [
                    h for h in [
                        "Content-Security-Policy",
                        "Strict-Transport-Security",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                    ] if h not in headers
                ],
            })

            if depth < 2 and "text/html" in headers.get("Content-Type", ""):
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = urljoin(url, a["href"])
                    href, _ = urldefrag(href)
                    p = urlparse(href)
                    if (p.netloc == base_domain or p.netloc == "") and p.scheme in ("http", "https", ""):
                        target = href.rstrip("/")
                        if target not in visited:
                            queue.append((target, depth + 1))
        except Exception:
            continue

    # 第二步: 汇总
    lines = [
        f"[batch_scan] 批量安全扫描 — {root_url}",
        f"扫描页面数: {len(results)}",
        "",
        "── 安全头缺失汇总 ──",
    ]

    # 每个安全头缺失的页面数
    header_stats: dict[str, list[str]] = {}
    for r in results:
        for h in r["missing_headers"]:
            header_stats.setdefault(h, []).append(r["url"])

    for header, urls in header_stats.items():
        lines.append(f"  ❌ {header}: {len(urls)}/{len(results)} 页缺失")

    lines.append("")
    lines.append("── 逐页详情 ──")
    for r in results:
        if r["missing_headers"]:
            missing = ", ".join(r["missing_headers"])
            lines.append(f"  [{r['status']}] {r['url']}")
            lines.append(f"         缺失: {missing}")
        else:
            lines.append(f"  [{r['status']}] {r['url']} ✅ 安全头完整")

    # 评分
    total_missing = sum(len(r["missing_headers"]) for r in results)
    if total_missing == 0:
        grade = "🟢 A — 安全配置完善"
    elif total_missing <= len(results) * 2:
        grade = "🟡 B — 存在一定缺失"
    else:
        grade = "🔴 C — 安全配置严重不足"

    lines.append(f"\n整体安全评级: {grade}")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════
# Agent 类 — 基于 LangGraph
# ═══════════════════════════════════════════════════════

TOOLS = [http_get, http_post, analyze_headers, extract_forms, extract_links,
        crawl, sitemap, batch_scan]


class Agent:
    """
    Web 漏洞审查 Agent (v0.4 — 深度爬取引擎)。

    v0.4 新增:
        - crawl: BFS 爬虫，自动发现所有同域页面 + 敏感路径探测
        - sitemap: 攻击面分类（登录页/表单页/API/管理后台）
        - batch_scan: 批量安全头检查所有发现页面
        - 两步工作流: 先爬取测绘攻击面 → 再深度扫描漏洞

    用法:
        agent = Agent(AgentConfig())
        async for token in agent.run("扫描 http://testphp.vulnweb.com"):
            print(token, end="")
    """

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.llm = ChatOpenAI(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            model=self.config.model,
            temperature=0.3,  # 低温度，安全分析需要精确
        )
        self.agent = create_react_agent(self.llm, TOOLS)
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    def clear(self) -> None:
        """清空对话历史，只保留 system prompt"""
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """
        执行扫描，逐 token yield 模型输出。

        LangGraph 的 astream_events(version="v2") 在 on_chat_model_stream
        事件中产出每个 token。工具调用过程由 agent 内部处理，不会
        yield 给调用者（避免了工具参数碎片出现在输出中）。
        """
        self.messages.append(HumanMessage(content=user_input))

        # 收集完整回复（用于写入历史）
        full_response: list[str] = []

        async for event in self.agent.astream_events(
            {"messages": list(self.messages)},  # copy to avoid mutation during iteration
            version="v2",
        ):
            kind = event["event"]

            # 只有 LLM 产出的文本 token 才 yield（工具调用内部细节不暴露）
            if kind == "on_chat_model_stream":
                chunk = event["data"]["chunk"]
                if chunk.content:
                    full_response.append(chunk.content)
                    yield chunk.content

        # 将本轮回复写入历史
        response_text = "".join(full_response).strip()
        if response_text:
            self.messages.append(AIMessage(content=response_text))

        # 如果本轮没有文本输出（全是工具调用且最终无总结），兜底
        if not response_text:
            self.messages.append(AIMessage(content="扫描完成，请查看上方工具调用结果。"))
