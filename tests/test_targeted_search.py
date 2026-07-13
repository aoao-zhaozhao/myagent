from __future__ import annotations

import unittest
from unittest.mock import patch

from agent.tools import BASE_TOOLS
from agent.tools.results import parse_tool_result


class FakeStreamingResponse:
    def __init__(self, body: bytes, content_type: str = "text/html", status_code: int = 200):
        self.body = body
        self.status_code = status_code
        self.headers = {"Content-Type": content_type, "Content-Length": str(len(body))}
        self.encoding = "utf-8"

    def iter_content(self, chunk_size: int, decode_unicode: bool = False):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset:offset + chunk_size]


def invoke(arguments: dict) -> tuple[str, dict | None]:
    tool = next(item for item in BASE_TOOLS if item.name == "search_http_body")
    return parse_tool_result(tool.invoke(arguments))


class TargetedSearchTests(unittest.TestCase):
    def test_large_fixture_finds_deep_match_without_returning_full_body(self):
        fixture = ("A" * 61_000) + "FLAG{deep-evidence}" + ("B" * 15_000)
        response = FakeStreamingResponse(fixture.encode())
        with patch("agent.tools.targeted_search_tools.request", return_value=response):
            text, result = invoke({"url": "http://scanner.test/large", "keyword_or_regex": "FLAG{deep-evidence}"})

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["match_count"], 1)
        self.assertEqual(result["data"]["matches"][0]["offset"], 61_000)
        self.assertLess(len(text), 2_000)
        self.assertNotIn("A" * 1000, text)
        self.assertNotIn("A" * 1000, str(result))

    def test_unsupported_content_type_is_classified(self):
        response = FakeStreamingResponse(b"%PDF-1.7", content_type="application/pdf")
        with patch("agent.tools.targeted_search_tools.request", return_value=response):
            _text, result = invoke({"url": "http://scanner.test/report", "keyword_or_regex": "secret"})

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["data"]["outcome"], "unsupported_content_type")

    def test_response_limit_and_regex_errors_are_classified(self):
        response = FakeStreamingResponse(b"content")
        response.headers["Content-Length"] = str(2_097_153)
        with patch("agent.tools.targeted_search_tools.request", return_value=response):
            _text, result = invoke({"url": "http://scanner.test/large", "keyword_or_regex": "needle"})
        self.assertEqual(result["data"]["outcome"], "response_limit_exceeded")

        response = FakeStreamingResponse(b"content")
        with patch("agent.tools.targeted_search_tools.request", return_value=response):
            _text, result = invoke({"url": "http://scanner.test/regex", "keyword_or_regex": "regex:("})
        self.assertEqual(result["data"]["outcome"], "regex_error")


if __name__ == "__main__":
    unittest.main()
