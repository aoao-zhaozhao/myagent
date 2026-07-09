"""
FastAPI server for My Agent Web Security Scanner v0.7.

v0.7 ships the LFI verifier and the v0.8-style structured browser UI while
publishing the product version as 0.7.0, per release plan.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from agent import Agent, AgentConfig

load_dotenv(PROJECT_ROOT / ".env")

APP_VERSION = "0.7.0"

app = FastAPI(title="Web Security Scanner", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

agent_config = AgentConfig()
active_sessions: int = 0


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return str(value)


@app.get("/api/config")
async def get_config():
    return {
        "model": agent_config.model,
        "base_url": agent_config.base_url,
        "max_turns": agent_config.max_turns,
        "has_api_key": bool(agent_config.api_key),
        "version": APP_VERSION,
    }


@app.put("/api/config")
async def update_config(data: dict):
    allowed = ["model", "base_url", "api_key", "max_turns"]
    for key in allowed:
        if key in data:
            setattr(agent_config, key, data[key])
    return {"status": "ok"}


@app.get("/api/sessions")
async def get_sessions():
    return {"active_sessions": active_sessions}


@app.websocket("/api/chat")
async def chat(ws: WebSocket):
    global active_sessions

    await ws.accept()
    agent = Agent(agent_config)
    active_sessions += 1
    print(f"[WS] session opened (active: {active_sessions})")

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                msg = {"content": raw}

            if msg.get("command") == "clear":
                agent.clear()
                await ws.send_json({"type": "info", "content": "对话记忆已清空"})
                continue

            user_input = str(msg.get("content", "")).strip()
            if not user_input:
                continue

            try:
                async for event in agent.run_events(user_input):
                    if event.get("type") in {"tool_start", "tool_end"}:
                        event["input"] = _json_safe(event.get("input"))
                        event["output"] = _json_safe(event.get("output"))
                    await ws.send_json(event)
                await ws.send_json({"type": "done"})
            except Exception as exc:
                import traceback

                print(f"[ERROR] Agent exception:\n{traceback.format_exc()}")
                await ws.send_json({"type": "error", "content": f"扫描出错: {exc}"})

    except WebSocketDisconnect:
        print(f"[WS] session closed (active: {active_sessions - 1})")
    finally:
        active_sessions -= 1


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = PROJECT_ROOT / "web" / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model": agent_config.model,
        "engine": "LangGraph",
        "version": APP_VERSION,
        "active_sessions": active_sessions,
    }


if __name__ == "__main__":
    import io

    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9120"))

    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    print(f"[*] Web Security Scanner v{APP_VERSION}: http://{host}:{port}")
    print("    API: /api/health | /api/config | /api/sessions")

    uvicorn.run(app, host=host, port=port, log_level="info")
