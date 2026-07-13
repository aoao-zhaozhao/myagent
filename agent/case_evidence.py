"""Per-run evidence gate for durable RAG case creation."""

from __future__ import annotations

import contextvars
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class CaseEvidenceGate:
    run_id: str
    target: str
    evidence: list[dict[str, str]] = field(default_factory=list)

    def record(self, tool_name: str, result: dict[str, Any] | None) -> None:
        if not result or result.get("status") != "ok" or tool_name in {"case_create", "scan_reflect"}:
            return
        verified: list[dict[str, str]] = []
        for finding in result.get("findings") or []:
            if not isinstance(finding, dict) or finding.get("confidence") != "confirmed":
                continue
            title = str(finding.get("title", "verified finding")).strip()
            category = str(finding.get("category", "general")).strip()
            verified.append({"title": title, "category": category})
        data = result.get("data") or {}
        if tool_name == "session_jwt_privilege_check" and data.get("validated") is True:
            verified.append({"title": "JWT privilege validation", "category": "jwt_attack"})
        for item in verified:
            raw = json.dumps(
                {"run": self.run_id, "tool": tool_name, "target": self.target, **item},
                ensure_ascii=False, sort_keys=True,
            )
            reference = hashlib.sha256(raw.encode()).hexdigest()[:16]
            if not any(existing["reference"] == reference for existing in self.evidence):
                self.evidence.append({"reference": reference, "tool": tool_name, **item})

    def authorize(self, target: str) -> dict[str, str] | None:
        if not self.evidence or not _same_origin(self.target, target):
            return None
        return self.evidence[-1]


_gate: contextvars.ContextVar[CaseEvidenceGate | None] = contextvars.ContextVar("case_evidence_gate", default=None)


def begin_case_evidence_gate(run_id: str, target: str) -> contextvars.Token[CaseEvidenceGate | None]:
    return _gate.set(CaseEvidenceGate(run_id=run_id, target=target))


def end_case_evidence_gate(token: contextvars.Token[CaseEvidenceGate | None]) -> None:
    _gate.reset(token)


def record_verified_evidence(tool_name: str, result: dict[str, Any] | None) -> None:
    gate = _gate.get()
    if gate is not None:
        gate.record(tool_name, result)


def authorize_case(target: str) -> dict[str, str] | None:
    gate = _gate.get()
    return gate.authorize(target) if gate is not None else None


def _same_origin(first: str, second: str) -> bool:
    left, right = urlparse(first), urlparse(second)
    return bool(left.netloc) and left.scheme == right.scheme and left.netloc == right.netloc
