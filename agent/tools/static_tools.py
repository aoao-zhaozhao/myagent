"""
v0.6 static analysis and browser rendering tools.

Tools:
  - analyze_js: scan HTML/JS for secrets, API paths, JWTs, comments, sourcemaps
  - decode_jwt: decode JWT header/payload and audit risky settings
  - discover_api: probe common API docs/endpoints and extract API paths from JS
  - render_page: render SPA pages with Playwright when available
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin, urlparse

import urllib3
from bs4 import BeautifulSoup
from langchain_core.tools import tool

from .http_client import get, in_scope_url, normalize_url, same_origin, truncate_text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


MAX_JS_FILES = 20
MAX_FINDINGS = 40

SECRET_PATTERNS = [
    ("OpenAI/DeepSeek style key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Generic API key", re.compile(r"(?i)\b(api[_-]?key|secret|token|access[_-]?token)\b\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
    ("Private key marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("Basic auth URL", re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s'\"]+")),
]

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?=[\s'\";,)<}\]]|$)")
API_PATH_RE = re.compile(
    r"['\"]((?:/api(?:/v\d+)?|/v\d+|/graphql|/swagger|/docs|/redoc|/openapi|/actuator)[^'\"\s<>(){}]*)['\"]",
    re.IGNORECASE,
)
ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

COMMON_API_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger",
    "/swagger-ui",
    "/docs",
    "/redoc",
    "/graphql",
    "/api",
    "/api/v1",
    "/actuator",
]


def _dedupe(items: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _mask(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "***"
    return value[:6] + "***" + value[-4:]


def _safe_json_b64(segment: str) -> dict | str:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return f"decode error: {exc}"


def _decode_jwt_parts(token: str) -> tuple[dict | str, dict | str, list[str]]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return "invalid token", "invalid token", ["JWT 必须包含 header.payload.signature 三段"]

    header = _safe_json_b64(parts[0])
    payload = _safe_json_b64(parts[1])
    issues: list[str] = []

    if isinstance(header, dict):
        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            issues.append("高危: alg 为 none 或缺失，可能允许签名绕过")
        if alg.startswith("hs"):
            issues.append("注意: HMAC 算法依赖共享密钥强度，需确认密钥足够随机")
    if isinstance(payload, dict):
        if "exp" not in payload:
            issues.append("中危: payload 缺少 exp，Token 可能长期有效")
        if payload.get("admin") is True or payload.get("role") in ("admin", "root"):
            issues.append("注意: payload 包含高权限角色声明，需确认服务端强制鉴权")

    if not parts[2]:
        issues.append("高危: signature 为空")
    return header, payload, issues


def _extract_api_paths(root_url: str, text: str) -> list[str]:
    paths = [m.group(1) for m in API_PATH_RE.finditer(text)]
    absolute = [m.group(0) for m in ABS_URL_RE.finditer(text)]
    scoped_absolute = [u for u in absolute if same_origin(root_url, u)]

    normalized: list[str] = []
    for path in paths:
        normalized.append(normalize_url(path, root_url))
    normalized.extend(normalize_url(u) for u in scoped_absolute)
    return _dedupe(normalized)


def _scan_text_for_secrets(text: str, source: str) -> list[str]:
    findings: list[str] = []
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(2) if match.lastindex and match.lastindex >= 2 else match.group(0)
            findings.append(f"{label}: {_mask(value)} @ {source}")
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


def _collect_js(root_url: str) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    root_url = normalize_url(root_url)
    response = get(root_url)
    content_type = response.headers.get("Content-Type", "")

    js_sources: list[tuple[str, str]] = []
    html_comments: list[str] = []
    errors: list[str] = []

    if "javascript" in content_type or urlparse(root_url).path.endswith(".js"):
        js_sources.append((root_url, response.text))
        return js_sources, html_comments, errors

    soup = BeautifulSoup(response.text, "html.parser")
    html_comments = [
        truncate_text(comment.strip(), 200)
        for comment in HTML_COMMENT_RE.findall(response.text)
        if comment.strip()
    ][:10]

    inline_index = 0
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_url = in_scope_url(root_url, src)
            if not js_url:
                continue
            if len(js_sources) >= MAX_JS_FILES:
                break
            try:
                js_response = get(js_url, timeout=8)
                js_sources.append((js_url, js_response.text))
            except Exception as exc:
                errors.append(f"{js_url}: {exc}")
        else:
            content = script.string or script.get_text()
            if content.strip():
                inline_index += 1
                js_sources.append((f"{root_url}#inline-script-{inline_index}", content))

    return js_sources, html_comments, errors


@tool
def decode_jwt(token: str) -> str:
    """
    解码 JWT header/payload，并检查常见安全问题。

    检查项:
        - alg:none / 空签名
        - 缺少 exp
        - 高权限角色声明
        - HMAC 算法密钥强度提醒

    参数:
        token: JWT 字符串
    """
    header, payload, issues = _decode_jwt_parts(token)
    return "\n".join(
        [
            "[decode_jwt] JWT 安全审计",
            "",
            "Header:",
            json.dumps(header, ensure_ascii=False, indent=2) if isinstance(header, dict) else str(header),
            "",
            "Payload:",
            json.dumps(payload, ensure_ascii=False, indent=2) if isinstance(payload, dict) else str(payload),
            "",
            "风险:",
            *(f"  - {issue}" for issue in issues),
            *([] if issues else ["  - 未发现明显 JWT 配置问题"]),
        ]
    )


@tool
def analyze_js(url: str) -> str:
    """
    下载页面中的同域 JS，并扫描敏感信息、JWT、API 路径、HTML 注释和 sourcemap 残留。

    参数:
        url: 页面 URL 或 JS 文件 URL
    """
    try:
        root_url = normalize_url(url)
        js_sources, html_comments, errors = _collect_js(root_url)

        secret_findings: list[str] = []
        jwt_tokens: list[str] = []
        api_paths: list[str] = []
        sourcemaps: list[str] = []
        debug_flags: list[str] = []

        for source, text in js_sources:
            secret_findings.extend(_scan_text_for_secrets(text, source))
            jwt_tokens.extend(JWT_RE.findall(text))
            api_paths.extend(_extract_api_paths(root_url, text))
            for match in SOURCE_MAP_RE.finditer(text):
                sourcemaps.append(normalize_url(match.group(1), source))
            if re.search(r"(?i)\b(debug|devMode|isDev)\b\s*[:=]\s*true\b", text):
                debug_flags.append(source)

        jwt_tokens = _dedupe(jwt_tokens)
        api_paths = _dedupe(api_paths)
        sourcemaps = _dedupe(sourcemaps)
        secret_findings = _dedupe(secret_findings)[:MAX_FINDINGS]

        lines = [
            f"[analyze_js] {root_url}",
            f"扫描 JS 数量: {len(js_sources)}",
            "",
            f"敏感信息: {len(secret_findings)}",
        ]
        lines.extend(f"  - {finding}" for finding in secret_findings[:20])
        if not secret_findings:
            lines.append("  - 未发现明显硬编码密钥")

        lines.append("")
        lines.append(f"JWT Token: {len(jwt_tokens)}")
        for token in jwt_tokens[:5]:
            header, payload, issues = _decode_jwt_parts(token)
            alg = header.get("alg") if isinstance(header, dict) else "?"
            sub = payload.get("sub") if isinstance(payload, dict) else "?"
            lines.append(f"  - {_mask(token)} | alg={alg} | sub={sub} | issues={len(issues)}")

        lines.append("")
        lines.append(f"API 路径: {len(api_paths)}")
        lines.extend(f"  - {path}" for path in api_paths[:30])

        lines.append("")
        lines.append(f"Sourcemap 残留: {len(sourcemaps)}")
        lines.extend(f"  - {item}" for item in sourcemaps[:10])

        lines.append("")
        lines.append(f"HTML 注释: {len(html_comments)}")
        lines.extend(f"  - {comment}" for comment in html_comments[:5])

        if debug_flags:
            lines.append("")
            lines.append("Debug 标记:")
            lines.extend(f"  - {item}" for item in debug_flags[:10])

        if errors:
            lines.append("")
            lines.append("下载失败:")
            lines.extend(f"  - {err}" for err in errors[:10])

        return "\n".join(lines)
    except Exception as exc:
        return f"analyze_js Error: {exc}"


@tool
def discover_api(url: str) -> str:
    """
    探测 OpenAPI / Swagger / GraphQL / 常见 API 入口，并从同域 JS 提取 API 路径。

    参数:
        url: 目标根 URL
    """
    try:
        root_url = normalize_url(url)
        found: list[str] = []
        for path in COMMON_API_PATHS:
            probe_url = urljoin(root_url + "/", path.lstrip("/"))
            try:
                response = get(probe_url, timeout=6, allow_redirects=False)
                if response.status_code not in (404, 500, 502, 503):
                    content_type = response.headers.get("Content-Type", "").split(";")[0]
                    found.append(f"[{response.status_code}] {content_type or 'unknown':20s} {probe_url}")
            except Exception:
                continue

        js_sources, _comments, errors = _collect_js(root_url)
        extracted: list[str] = []
        for _source, text in js_sources:
            extracted.extend(_extract_api_paths(root_url, text))
        extracted = _dedupe(extracted)

        lines = [
            f"[discover_api] {root_url}",
            "",
            f"常见 API / 文档端点: {len(found)}",
        ]
        lines.extend(f"  - {item}" for item in found[:30])
        if not found:
            lines.append("  - 未发现常见 API 文档端点")

        lines.append("")
        lines.append(f"JS 中提取的 API 路径: {len(extracted)}")
        lines.extend(f"  - {item}" for item in extracted[:40])
        if not extracted:
            lines.append("  - 未从 JS 中提取到 API 路径")

        if errors:
            lines.append("")
            lines.append("JS 下载失败:")
            lines.extend(f"  - {err}" for err in errors[:10])

        return "\n".join(lines)
    except Exception as exc:
        return f"discover_api Error: {exc}"


@tool
def render_page(url: str, wait_ms: int = 2000) -> str:
    """
    使用 Playwright headless 渲染 SPA 页面，提取渲染后 DOM、标题和同域网络请求。

    如果 Playwright 或浏览器驱动未安装，会返回安装提示并不中断扫描。

    参数:
        url: 页面 URL
        wait_ms: 页面加载后额外等待毫秒数，默认 2000
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return (
            "[render_page] Playwright 未安装。\n"
            "安装依赖: pip install playwright\n"
            "安装浏览器: python -m playwright install chromium"
        )

    root_url = normalize_url(url)
    requests_seen: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(user_agent="MyAgent-WebSecurityScanner/0.6")

            def on_request(req):
                req_url = req.url
                if same_origin(root_url, req_url):
                    requests_seen.append(f"{req.method} {req_url}")

            page.on("request", on_request)
            response = page.goto(root_url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(max(0, min(wait_ms, 10000)))
            title = page.title()
            content = page.content()
            browser.close()

        soup = BeautifulSoup(content, "html.parser")
        text = " ".join(soup.get_text(" ", strip=True).split())
        forms = len(soup.find_all("form"))
        links = [
            in_scope_url(root_url, a.get("href", ""))
            for a in soup.find_all("a", href=True)
        ]
        links = [link for link in _dedupe([l for l in links if l])]

        lines = [
            f"[render_page] {root_url}",
            f"HTTP Status: {response.status if response else 'unknown'}",
            f"Title: {title or '(无标题)'}",
            f"渲染后 DOM 长度: {len(content)}",
            f"表单数量: {forms}",
            f"同域链接: {len(links)}",
            f"同域网络请求: {len(_dedupe(requests_seen))}",
            "",
            "同域网络请求 Top 20:",
        ]
        lines.extend(f"  - {item}" for item in _dedupe(requests_seen)[:20])
        lines.append("")
        lines.append("同域链接 Top 20:")
        lines.extend(f"  - {item}" for item in links[:20])
        lines.append("")
        lines.append("页面文本摘要:")
        lines.append(truncate_text(text, 1200))
        return "\n".join(lines)
    except Exception as exc:
        return f"render_page Error: {exc}"
