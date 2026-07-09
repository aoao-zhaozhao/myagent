"""
HTTP 基础工具: GET / POST 请求。

v0.5: 从 agent/core.py 拆分，无功能变更。
"""

import urllib3
from langchain_core.tools import tool

from .http_client import get, post, truncate_text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
