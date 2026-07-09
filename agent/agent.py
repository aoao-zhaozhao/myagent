"""
LangGraph-based Web security scanning agent.

v0.7 bundles:
  - LFI verification tool: test_lfi_param
  - Structured streaming events for the browser UI
  - Existing v0.6 JS/API/JWT/SPA/RAG scanning flow
"""

from __future__ import annotations

from typing import Any, AsyncIterator

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .config import AgentConfig
from .prompts import SYSTEM_PROMPT
from .rag import create_search_knowledge_tool
from .tools import BASE_TOOLS


class Agent:
    """Web application security scanning agent."""

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.llm = ChatOpenAI(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            model=self.config.model,
            temperature=self.config.temperature,
        )

        self._search_knowledge_tool = None
        self._rag_manager = None
        self._init_rag()

        self.agent = create_react_agent(self.llm, self._tools())
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    def _tools(self):
        tools = list(BASE_TOOLS)
        if self._search_knowledge_tool:
            tools.append(self._search_knowledge_tool)
        return tools

    def _init_rag(self) -> None:
        """Initialize the RAG tool; continue without it if local models fail."""
        try:
            search_tool, rag_mgr = create_search_knowledge_tool(self.config)
            self._search_knowledge_tool = search_tool
            self._rag_manager = rag_mgr
        except Exception as exc:
            print(f"[Agent] RAG init failed ({exc}); continuing without knowledge search")
            self._search_knowledge_tool = None
            self._rag_manager = None

    @property
    def has_rag(self) -> bool:
        return self._rag_manager is not None and self._search_knowledge_tool is not None

    def clear(self) -> None:
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    def _summarize_tool_output(self, output: Any, limit: int = 900) -> str:
        if hasattr(output, "content"):
            text = str(output.content)
        else:
            text = str(output)
        text = text.strip()
        if len(text) > limit:
            return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
        return text

    async def run_events(self, user_input: str) -> AsyncIterator[dict[str, Any]]:
        """
        Execute one turn and yield structured events.

        Event types:
          - token: model text stream
          - tool_start: tool name and arguments
          - tool_end: compact tool result summary
        """
        self.messages.append(HumanMessage(content=user_input))
        self.agent = create_react_agent(self.llm, self._tools())

        full_response: list[str] = []

        async for event in self.agent.astream_events(
            {"messages": list(self.messages)},
            config={"recursion_limit": self.config.max_turns},
            version="v2",
        ):
            kind = event["event"]

            if kind == "on_chat_model_stream":
                chunk = event["data"]["chunk"]
                if chunk.content:
                    full_response.append(chunk.content)
                    yield {"type": "token", "content": chunk.content}
            elif kind == "on_tool_start":
                yield {
                    "type": "tool_start",
                    "id": event.get("run_id"),
                    "name": event.get("name", "tool"),
                    "input": event.get("data", {}).get("input"),
                }
            elif kind == "on_tool_end":
                yield {
                    "type": "tool_end",
                    "id": event.get("run_id"),
                    "name": event.get("name", "tool"),
                    "output": self._summarize_tool_output(event.get("data", {}).get("output")),
                }

        response_text = "".join(full_response).strip()
        if response_text:
            self.messages.append(AIMessage(content=response_text))
        else:
            self.messages.append(AIMessage(content="扫描完成，请查看工具调用结果。"))

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """Backward-compatible token-only stream."""
        async for event in self.run_events(user_input):
            if event.get("type") == "token":
                yield str(event.get("content", ""))
