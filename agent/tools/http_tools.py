"""
HTTP 基础工具: GET / POST / 受约束的通用请求。

v0.5: 从 agent/core.py 拆分，无功能变更。
"""

import json

import urllib3
from langchain_core.tools import tool

from .http_client import get, post, request, truncate_text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALLOWED_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"})


@tool
def http_get(url: str) -> str:
    """
    发送 HTTP GET 请求到目标 URL，返回状态码、响应头、页面内容（前 3000 字符）。

    用途: 获取页面内容、探测端点是否存在、触发反射型漏洞。

    参数:
        url: 目标 URL（如 http://example.com/page?id=1）
    """
    try:
        r = get(url)
        headers_str = "\n".join(f"  {k}: {v}" for k, v in r.headers.items())
        return (
            f"[GET] {url}\n"
            f"Status: {r.status_code} {r.reason}\n"
            f"Response Headers:\n{headers_str}\n\n"
            f"Body (first 3000 chars):\n{truncate_text(r.text)}"
        )
    except Exception as e:
        if e.__class__.__name__ == "Timeout":
            return f"[GET] {url}\nError: 请求超时"
        if e.__class__.__name__ == "ConnectionError":
            return f"[GET] {url}\nError: 无法连接到目标服务器"
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
        r = post(url, data=data, headers=headers)
        return (
            f"[POST] {url}\n"
            f"Payload: {data[:500]}\n"
            f"Status: {r.status_code}\n"
            f"Body (first 3000 chars):\n{truncate_text(r.text)}"
        )
    except Exception as e:
        return f"[POST] {url}\nError: {str(e)}"


@tool
def http_request(
    method: str,
    url: str,
    data: str = "",
    headers_json: str = "",
) -> str:
    """发送受约束的 HTTP 请求，用于验证目标明确要求的非 GET/POST 方法。

    支持 GET、POST、PUT、PATCH、HEAD、OPTIONS；拒绝 DELETE、TRACE、CONNECT。
    仅当页面、源码或 Allow 响应头明确要求某个方法时才使用 PUT/PATCH，且应
    使用最小、非破坏性的请求体。headers_json 必须是 HTTP 请求头 JSON 对象。

    参数:
        method: HTTP 方法，例如 PUT
        url: 同源目标 URL
        data: 可选请求体
        headers_json: 可选 JSON 对象，例如 {"Content-Type":"application/json"}
    """
    normalized_method = method.strip().upper()
    if normalized_method not in ALLOWED_HTTP_METHODS:
        allowed = ", ".join(sorted(ALLOWED_HTTP_METHODS))
        return f"[http_request] {method} {url}\nError: method not allowed; supported methods: {allowed}"

    try:
        headers: dict[str, str] = {}
        if headers_json.strip():
            parsed_headers = json.loads(headers_json)
            if not isinstance(parsed_headers, dict):
                raise ValueError("headers_json parse error: expected a JSON object")
            for key, value in parsed_headers.items():
                if not isinstance(key, str) or "\r" in key or "\n" in key:
                    raise ValueError("headers_json parse error: invalid header name")
                value_text = str(value)
                if "\r" in value_text or "\n" in value_text:
                    raise ValueError("headers_json parse error: invalid header value")
                headers[key] = value_text

        response = request(
            normalized_method,
            url,
            data=data or None,
            headers=headers or None,
        )
        headers_str = "\n".join(f"  {key}: {value}" for key, value in response.headers.items())
        return (
            f"[{normalized_method}] {url}\n"
            f"Status: {response.status_code} {response.reason}\n"
            f"Response Headers:\n{headers_str}\n\n"
            f"Body (first 3000 chars):\n{truncate_text(response.text)}"
        )
    except Exception as exc:
        return f"[http_request] {normalized_method} {url}\nError: {exc}"
