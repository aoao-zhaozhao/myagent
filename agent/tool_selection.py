"""Deterministic, bounded tool selection for a single agent turn."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


DEFAULT_TOOLS = (
    "http_get",
    "http_request",
    "analyze_headers",
    "extract_forms",
    "extract_links",
    "crawl",
    "sitemap",
)

DOMAIN_TOOLS: dict[str, tuple[str, ...]] = {
    "scan": (
        "render_page",
        "verify_injection",
        "test_ssrf",
        "test_idor",
        "analyze_js",
    ),
    "authentication": (
        "auth_login",
        "session_jwt_review",
        "session_jwt_hmac_check",
        "session_jwt_privilege_check",
        "session_response_search",
    ),
    "jwt": (
        "decode_jwt",
        "jwt_alg_none_attack",
        "jwt_hmac_brute",
        "jwt_key_confusion",
    ),
    "injection": (
        "verify_injection",
        "test_lfi_param",
        "test_command_injection",
        "test_ssti",
    ),
    "browser": (
        "render_page",
        "search_rendered_dom",
        "analyze_js",
        "discover_api",
    ),
    "ssrf": ("test_ssrf", "probe_internal_port"),
    "authorization": (
        "test_idor",
        "test_privilege_escalation",
        "test_role_manipulation",
    ),
    "oob": ("generate_oob_payload", "check_oob_callbacks"),
    "traffic": ("traffic_list", "traffic_view", "traffic_repeat", "traffic_sitemap"),
    "skills": (
        "skill_list",
        "skill_view",
        "skill_load",
        "skill_create",
        "skill_patch",
        "skill_pin",
        "skill_archive",
        "skill_restore",
        "case_create",
        "scan_reflect",
    ),
    "knowledge": ("search_knowledge",),
}

DOMAIN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "scan": ("scan", "audit", "pentest", "vulnerability", "安全扫描", "漏洞扫描", "渗透测试", "审计"),
    "authentication": ("auth", "login", "session", "cookie", "credential", "认证", "登录", "会话", "权限令牌"),
    "jwt": ("jwt", "bearer", "token", "alg:none", "hmac", "令牌", "签名"),
    "injection": ("injection", "sqli", "sql injection", "xss", "lfi", "ssti", "rce", "命令注入", "注入", "文件包含"),
    "browser": ("javascript", "js", "dom", "render", "browser", "前端", "浏览器", "渲染"),
    "ssrf": ("ssrf", "internal port", "metadata service", "内网", "端口探测"),
    "authorization": ("idor", "authorization", "privilege", "role", "越权", "权限", "水平越权", "垂直越权"),
    "oob": ("oob", "callback", "webhook", "out-of-band", "外带", "回连"),
    "traffic": ("traffic", "request history", "proxy", "burp", "流量", "请求历史", "代理"),
    "skills": ("skill", "case memory", "知识库", "技能", "案例记忆"),
    "knowledge": ("knowledge", "owasp", "cve", "remediation", "知识库", "修复建议"),
}


@dataclass(frozen=True)
class ToolSelection:
    tools: list[Any]
    domains: tuple[str, ...]


def tools_for_domain(tools: Iterable[Any], domain: str, *, limit: int = 12) -> list[Any]:
    """Find a bounded, domain-specific catalogue, including matching MCP tools."""
    if domain not in DOMAIN_TOOLS or limit < 1:
        return []

    available = list(tools)
    by_name = {str(getattr(tool, "name", "")): tool for tool in available}
    selected: list[Any] = []
    selected_names: set[str] = set()

    def add(tool: Any) -> None:
        name = str(getattr(tool, "name", ""))
        if name and name not in selected_names and len(selected) < limit:
            selected.append(tool)
            selected_names.add(name)

    for name in DOMAIN_TOOLS[domain]:
        if tool := by_name.get(name):
            add(tool)

    terms = DOMAIN_KEYWORDS[domain]
    for tool in available:
        name = str(getattr(tool, "name", "")).lower()
        description = str(getattr(tool, "description", "")).lower()
        if name not in selected_names and any(term in f"{name} {description}" for term in terms):
            add(tool)
    return selected


def select_tools(
    tools: Iterable[Any],
    user_input: str,
    *,
    max_tools: int = 12,
) -> ToolSelection:
    """Return the smallest ordered subset likely to serve the current request.

    Tool names are the primary routing signal. Descriptions are considered only
    for MCP tools, whose names are not controlled by this project.
    """
    if max_tools < 1:
        raise ValueError("max_tools must be at least 1")

    available = list(tools)
    by_name = {str(getattr(tool, "name", "")): tool for tool in available}
    request = user_input.lower()
    domains = tuple(
        domain
        for domain, keywords in DOMAIN_KEYWORDS.items()
        if any(keyword in request for keyword in keywords)
    )

    desired_names = list(DEFAULT_TOOLS)
    for domain in domains:
        desired_names.extend(DOMAIN_TOOLS[domain])

    selected: list[Any] = []
    selected_names: set[str] = set()

    def add(tool: Any) -> None:
        name = str(getattr(tool, "name", ""))
        if name and name not in selected_names and len(selected) < max_tools:
            selected.append(tool)
            selected_names.add(name)

    for name in desired_names:
        tool = by_name.get(name)
        if tool is not None:
            add(tool)

    # MCP tools often use server-specific names. Match only the active domains
    # so an enabled browser MCP cannot add its whole tool catalogue by default.
    if domains and len(selected) < max_tools:
        for domain in domains:
            for tool in tools_for_domain(available, domain, limit=max_tools):
                add(tool)

    # A renamed or unavailable baseline tool must not yield an empty tool list.
    if not selected:
        for tool in available[:max_tools]:
            add(tool)

    return ToolSelection(tools=selected, domains=domains)
