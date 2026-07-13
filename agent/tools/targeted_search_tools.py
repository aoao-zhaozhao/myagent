"""Bounded, evidence-oriented search for large authorized HTTP and DOM responses."""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any

from langchain_core.tools import tool

from .http_client import in_scope_url, normalize_url, request, same_origin
from .results import RequestRecord, ResponseRecord, ToolResult, error_result


MAX_RESPONSE_BYTES = int(os.getenv("SCAN_TARGETED_SEARCH_MAX_BYTES", "2097152"))
MAX_CONTEXT_CHARS = int(os.getenv("SCAN_TARGETED_SEARCH_CONTEXT_CHARS", "240"))
MAX_MATCHES = int(os.getenv("SCAN_TARGETED_SEARCH_MAX_MATCHES", "20"))
TEXT_CONTENT_TYPES = ("text/", "application/json", "application/javascript", "application/xml")


def _is_text_content_type(value: str) -> bool:
    content_type = value.split(";", 1)[0].strip().lower()
    return (
        content_type.startswith(TEXT_CONTENT_TYPES)
        or content_type.endswith("+json")
        or content_type.endswith("+xml")
    )


def _compile_query(keyword_or_regex: str) -> tuple[re.Pattern[str], str]:
    query = keyword_or_regex.strip()
    if not query:
        raise ValueError("keyword_or_regex must not be empty")
    if query.startswith("regex:"):
        return re.compile(query[6:]), "regex"
    if len(query) >= 2 and query.startswith("/") and query.endswith("/"):
        return re.compile(query[1:-1]), "regex"
    return re.compile(re.escape(query)), "literal"


def _search_text(text: str, keyword_or_regex: str) -> tuple[dict[str, Any], str]:
    pattern, query_kind = _compile_query(keyword_or_regex)
    matches = list(pattern.finditer(text))
    contexts = []
    for match in matches[:MAX_MATCHES]:
        start = max(0, match.start() - MAX_CONTEXT_CHARS // 2)
        end = min(len(text), match.end() + MAX_CONTEXT_CHARS // 2)
        contexts.append({
            "offset": match.start(),
            "length": match.end() - match.start(),
            "context": text[start:end],
        })
    return {
        "outcome": "matches" if matches else "no_matches",
        "query_kind": query_kind,
        "match_count": len(matches),
        "matches": contexts,
        "matches_limited": len(matches) > MAX_MATCHES,
    }, query_kind


def _search_result(
    *,
    tool_name: str,
    url: str,
    text: str,
    keyword_or_regex: str,
    response: ResponseRecord | None = None,
    source: str,
) -> str:
    try:
        search, query_kind = _search_text(text, keyword_or_regex)
    except re.error as exc:
        return ToolResult(
            tool=tool_name,
            target=url,
            status="error",
            summary="Invalid regular expression.",
            errors=[{"kind": "regex_error", "message": str(exc)[:500]}],
            raw_excerpt=f"[{tool_name}] {url}\n正则错误: {exc}",
            request=RequestRecord("GET", url),
            response=response,
            data={"outcome": "regex_error", "source": source},
        ).to_text()

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    lines = [
        f"[{tool_name}] {url}",
        f"来源: {source}",
        f"响应长度: {len(text.encode('utf-8'))} bytes",
        f"内容 SHA-256: {digest}",
        f"检索类型: {query_kind}",
        f"命中次数: {search['match_count']}",
    ]
    for item in search["matches"]:
        lines.append(f"\n偏移量 {item['offset']}（长度 {item['length']}）:")
        lines.append(item["context"])
    if search["matches_limited"]:
        lines.append(f"\n仅展示前 {MAX_MATCHES} 个命中的受限上下文。")
    return ToolResult(
        tool=tool_name,
        target=url,
        status="ok",
        summary=f"{source} search: {search['outcome']} ({search['match_count']} matches)",
        raw_excerpt="\n".join(lines),
        request=RequestRecord("GET", url),
        response=response,
        data={
            **search,
            "source": source,
            "content_length": len(text.encode("utf-8")),
            "content_sha256": digest,
        },
    ).to_text()


def _limit_result(tool_name: str, url: str, outcome: str, message: str, data: dict[str, Any]) -> str:
    return ToolResult(
        tool=tool_name,
        target=url,
        status="error",
        summary=message,
        errors=[{"kind": outcome, "message": message}],
        raw_excerpt=f"[{tool_name}] {url}\n{message}",
        request=RequestRecord("GET", url),
        data={"outcome": outcome, **data},
    ).to_text()


def _read_bounded_response(url: str) -> tuple[Any, str | None, str | None]:
    response = request("GET", url, stream=True, allow_redirects=False)
    content_type = str(response.headers.get("Content-Type", ""))
    if not _is_text_content_type(content_type):
        return response, None, "unsupported_content_type"
    content_length = response.headers.get("Content-Length")
    try:
        if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
            return response, None, "response_limit_exceeded"
    except ValueError:
        pass

    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
        if not chunk:
            continue
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            return response, None, "response_limit_exceeded"
        chunks.append(chunk)
    if response.status_code == 206 or response.headers.get("Content-Range"):
        return response, None, "response_truncated"
    raw = b"".join(chunks)
    return response, raw.decode(response.encoding or "utf-8", errors="replace"), None


@tool
def search_http_body(url: str, keyword_or_regex: str) -> str:
    """在已授权同源文本 HTTP 响应中定向检索关键词或正则，不返回完整响应正文。

    当 http_get 的摘要过短、但已知关键词或 flag 模式可能位于大响应深处时使用。
    默认按字面量检索；以 `regex:` 或 `/.../` 包裹时按正则检索。仅返回内容长度、
    SHA-256、命中次数、偏移量及受限上下文。响应超过上限、非文本类型或正则错误会
    返回分类结果。
    """
    tool_name = "search_http_body"
    normalized = normalize_url(url)
    if not in_scope_url(normalized, normalized):
        return _limit_result(tool_name, url, "out_of_scope", "Only HTTP(S) URLs are supported.", {})
    try:
        response, text, outcome = _read_bounded_response(normalized)
        response_record = ResponseRecord(
            status_code=response.status_code,
            content_type=str(response.headers.get("Content-Type", "")).split(";", 1)[0] or None,
            body_length=int(response.headers.get("Content-Length", 0) or 0) or None,
        )
        if outcome:
            return _limit_result(
                tool_name,
                normalized,
                outcome,
                f"HTTP response cannot be searched: {outcome}.",
                {"content_type": response_record.content_type, "response_limit_bytes": MAX_RESPONSE_BYTES},
            )
        return _search_result(
            tool_name=tool_name, url=normalized, text=text or "", keyword_or_regex=keyword_or_regex,
            response=response_record, source="http_body",
        )
    except Exception as exc:
        return error_result(tool_name, normalized, exc).to_text()


@tool
def search_rendered_dom(url: str, keyword_or_regex: str, wait_ms: int = 2000) -> str:
    """在 Playwright 渲染后的同源页面文本中定向检索关键词或正则。

    适用于 SPA 或动态内容。检索规则与 search_http_body 相同，且只返回受限证据，
    不返回完整 DOM 或页面文本。
    """
    tool_name = "search_rendered_dom"
    normalized = normalize_url(url)
    if not in_scope_url(normalized, normalized):
        return _limit_result(tool_name, url, "out_of_scope", "Only HTTP(S) URLs are supported.", {})
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return _limit_result(tool_name, normalized, "playwright_unavailable", "Playwright is not installed.", {})

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(user_agent="MyAgent-WebSecurityScanner/1.7.2")

            def restrict_request(route):
                if same_origin(normalized, route.request.url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", restrict_request)
            response = page.goto(normalized, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(max(0, min(wait_ms, 10000)))
            if not same_origin(normalized, page.url):
                browser.close()
                return _limit_result(tool_name, normalized, "out_of_scope", "Rendered page redirected out of scope.", {})
            text = page.locator("body").inner_text()
            browser.close()
        text_bytes = text.encode("utf-8")
        if len(text_bytes) > MAX_RESPONSE_BYTES:
            return _limit_result(
                tool_name, normalized, "response_limit_exceeded", "Rendered DOM exceeds the response limit.",
                {"response_limit_bytes": MAX_RESPONSE_BYTES},
            )
        return _search_result(
            tool_name=tool_name,
            url=normalized,
            text=text,
            keyword_or_regex=keyword_or_regex,
            response=ResponseRecord(status_code=response.status if response else None, body_length=len(text_bytes)),
            source="rendered_dom",
        )
    except Exception as exc:
        return error_result(tool_name, normalized, exc).to_text()
