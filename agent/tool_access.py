"""On-demand access to tools omitted from the initial model tool list."""

from __future__ import annotations

from typing import Any, Literal

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from .tool_selection import DOMAIN_TOOLS, tools_for_domain
from .tools.results import ToolResult, error_result


class LoadToolDomainArgs(BaseModel):
    domain: Literal[
        "scan", "authentication", "jwt", "injection", "browser", "ssrf",
        "authorization", "oob", "traffic", "skills", "knowledge",
    ] = Field(description="Capability domain to make available for this turn")


class CallLoadedToolArgs(BaseModel):
    tool_name: str = Field(description="Name returned by load_tool_domain")
    arguments: dict[str, Any] = Field(default_factory=dict, description="Arguments for that tool")


class ToolAccessBroker:
    """Keeps long-tail tools server-side until the model explicitly requests them."""

    def __init__(self, tools: list[Any], initially_loaded: list[Any], *, domain_limit: int = 12) -> None:
        self._tools_by_name = {
            str(getattr(tool, "name", "")): tool
            for tool in tools
            if getattr(tool, "name", "")
        }
        self._all_tools = list(self._tools_by_name.values())
        self._loaded_names = {str(getattr(tool, "name", "")) for tool in initially_loaded}
        self._domain_limit = domain_limit

    def control_tools(self) -> list[StructuredTool]:
        return [
            StructuredTool.from_function(
                func=self.load_tool_domain,
                name="load_tool_domain",
                description=(
                    "Load a bounded catalogue of tools for one capability domain. "
                    "Then call call_loaded_tool with a returned name and arguments."
                ),
                args_schema=LoadToolDomainArgs,
                infer_schema=False,
            ),
            StructuredTool.from_function(
                func=self.call_loaded_tool,
                name="call_loaded_tool",
                description="Execute only a tool previously returned by load_tool_domain.",
                args_schema=CallLoadedToolArgs,
                infer_schema=False,
            ),
        ]

    def load_tool_domain(self, domain: str) -> str:
        domain_tools = tools_for_domain(self._all_tools, domain, limit=self._domain_limit)
        self._loaded_names.update(str(getattr(tool, "name", "")) for tool in domain_tools)
        catalogue = [
            {
                "name": str(getattr(tool, "name", "")),
                "description": str(getattr(tool, "description", ""))[:240],
                "parameters": self._parameters_for(tool),
            }
            for tool in domain_tools
        ]
        return ToolResult(
            tool="load_tool_domain",
            target="",
            status="ok",
            summary=f"Loaded {len(catalogue)} {domain} tools for this turn.",
            raw_excerpt=(
                f"Loaded {domain} tools. Use call_loaded_tool with one of these names and its arguments:\n"
                f"{catalogue}"
            ),
            data={"domain": domain, "loaded_tools": catalogue},
        ).to_text()

    def call_loaded_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        if tool_name not in self._loaded_names:
            return error_result(
                "call_loaded_tool", "", f"{tool_name!r} is not loaded; call load_tool_domain first."
            ).to_text()
        tool = self._tools_by_name.get(tool_name)
        if tool is None:
            return error_result("call_loaded_tool", "", f"Unknown tool {tool_name!r}.").to_text()
        try:
            return str(tool.invoke(arguments, config={"callbacks": []}))
        except Exception as exc:
            return error_result(tool_name, "", exc).to_text()

    @staticmethod
    def _parameters_for(tool: Any) -> dict[str, Any]:
        schema = getattr(tool, "args_schema", None)
        if schema is None:
            return {}
        try:
            json_schema = schema.model_json_schema()
        except AttributeError:
            return {}
        return {
            "required": json_schema.get("required", []),
            "properties": json_schema.get("properties", {}),
        }
