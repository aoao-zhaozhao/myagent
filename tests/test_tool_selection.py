from types import SimpleNamespace

from agent.tool_selection import DEFAULT_TOOLS, select_tools, tools_for_domain


def _tools(*names: str):
    return [SimpleNamespace(name=name, description="") for name in names]


def test_default_request_only_loads_reconnaissance_tools():
    tools = _tools(*DEFAULT_TOOLS, "test_ssrf", "jwt_hmac_brute", "traffic_list")

    result = select_tools(tools, "Inspect https://example.test and summarize its attack surface")

    assert [tool.name for tool in result.tools] == list(DEFAULT_TOOLS)
    assert result.domains == ()


def test_generic_security_scan_has_a_bounded_first_round_of_verification_tools():
    tools = _tools(*DEFAULT_TOOLS, "render_page", "verify_injection", "test_ssrf", "test_idor", "analyze_js")

    result = select_tools(tools, "Scan https://example.test for common vulnerabilities")

    assert result.domains == ("scan",)
    assert len(result.tools) == 12
    assert [tool.name for tool in result.tools][-5:] == [
        "render_page", "verify_injection", "test_ssrf", "test_idor", "analyze_js"
    ]


def test_jwt_request_adds_only_the_jwt_domain_before_the_limit():
    tools = _tools(*DEFAULT_TOOLS, "decode_jwt", "jwt_alg_none_attack", "jwt_hmac_brute", "jwt_key_confusion", "test_ssrf")

    result = select_tools(tools, "Review this JWT token and test for weak HMAC signing")

    assert result.domains == ("jwt",)
    assert [tool.name for tool in result.tools][-4:] == [
        "decode_jwt",
        "jwt_alg_none_attack",
        "jwt_hmac_brute",
        "jwt_key_confusion",
    ]
    assert "test_ssrf" not in [tool.name for tool in result.tools]


def test_injection_request_is_bounded_by_the_configured_tool_limit():
    tools = _tools(*DEFAULT_TOOLS, "verify_injection", "test_lfi_param", "test_command_injection", "test_ssti")

    result = select_tools(tools, "Test this endpoint for SQL injection", max_tools=9)

    assert len(result.tools) == 9
    assert result.domains == ("injection",)
    assert [tool.name for tool in result.tools][-2:] == ["verify_injection", "test_lfi_param"]


def test_mcp_tool_is_selected_only_when_its_domain_matches():
    tools = _tools(*DEFAULT_TOOLS, "test_ssrf")
    tools.append(SimpleNamespace(name="browser_network", description="MCP browser network request tool"))

    result = select_tools(tools, "Use the browser DOM to inspect the rendered page")

    assert "browser_network" in [tool.name for tool in result.tools]


def test_domain_catalogue_can_expose_a_long_tail_tool_later():
    tools = _tools(*DEFAULT_TOOLS, "test_ssrf", "probe_internal_port")

    result = tools_for_domain(tools, "ssrf")

    assert [tool.name for tool in result] == ["test_ssrf", "probe_internal_port"]
