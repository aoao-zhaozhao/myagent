"""Filesystem-backed case memory for solved scans and CTFs."""

from __future__ import annotations

import os
import re
import uuid
import hashlib
from pathlib import Path

import yaml

from .evolution.store import now_iso


_CASE_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:[a-z0-9_-]*(?:ctf|flag)|flag)\{[^}\r\n]{1,512}\}"),
    re.compile(r"(?i)(bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|passwd|secret)\s*[=:]\s*)[^\s&;,]+"),
)


def redact_case_text(value: str) -> str:
    """Keep reusable technique details while removing secrets from case memory."""
    text = str(value)
    for pattern in _CASE_SECRET_PATTERNS:
        text = pattern.sub(lambda match: match.group(1) + "[REDACTED]" if match.lastindex else "[REDACTED]", text)
    return text


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug[:56] or "case"


class CaseManager:
    """Store structured, searchable lessons without promoting them to skills."""

    def __init__(self, root: Path | None = None):
        self.root = root or Path(
            os.getenv("AGENT_CASES_DIR", str(Path(__file__).parent / "knowledge" / "cases"))
        )
        self.root.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        *,
        title: str,
        target: str,
        summary: str,
        evidence: str,
        solution: str,
        failed_attempts: str = "",
        category: str = "general",
        tags: list[str] | None = None,
        source: str = "agent",
        verified_evidence: dict[str, str] | None = None,
    ) -> dict[str, str | list[str]]:
        if not verified_evidence:
            raise ValueError("verified evidence is required for a RAG case")
        safe_title = redact_case_text(title).strip()[:200]
        safe_target = redact_case_text(target).strip()[:500]
        safe_tags = [redact_case_text(tag).strip()[:64] for tag in (tags or []) if tag.strip()]
        fingerprint_input = "|".join((safe_target, category.strip().lower(), verified_evidence["reference"]))
        evidence_fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:24]
        for existing in self.root.glob("*.md"):
            metadata = self._metadata(existing)
            if metadata.get("evidence_fingerprint") == evidence_fingerprint:
                return {"id": str(metadata.get("id", existing.stem)), "path": str(existing), "tags": metadata.get("tags", []), "created": False}
        case_id = f"{_slugify(safe_title)}-{uuid.uuid4().hex[:8]}"
        path = self.root / f"{case_id}.md"
        metadata = {
            "id": case_id,
            "title": safe_title,
            "target": safe_target,
            "category": category.strip().lower()[:64] or "general",
            "tags": sorted(set(safe_tags)),
            "source": source,
            "created_at": now_iso(),
            "verified": True,
            "evidence_reference": verified_evidence["reference"],
            "evidence_tool": verified_evidence["tool"],
            "evidence_fingerprint": evidence_fingerprint,
        }
        sections = [
            f"# {metadata['title']}",
            "## Summary",
            redact_case_text(summary).strip(),
            "## Evidence",
            redact_case_text(evidence).strip(),
            "## Resolution",
            redact_case_text(solution).strip(),
        ]
        if failed_attempts.strip():
            sections.extend(["## Failed Attempts", redact_case_text(failed_attempts).strip()])
        content = f"---\n{yaml.safe_dump(metadata, allow_unicode=True, sort_keys=False).strip()}\n---\n\n" + "\n\n".join(sections) + "\n"
        path.write_text(content, encoding="utf-8")
        return {"id": case_id, "path": str(path), "tags": metadata["tags"], "created": True}

    @staticmethod
    def _metadata(path: Path) -> dict:
        text = path.read_text(encoding="utf-8")
        if not text.startswith("---\n"):
            return {}
        closing = text.find("\n---\n", 4)
        if closing < 0:
            return {}
        try:
            return yaml.safe_load(text[4:closing]) or {}
        except yaml.YAMLError:
            return {}

    def count_similar(self, category: str, tags: list[str]) -> int:
        """Count independent case records that can justify a skill promotion."""
        wanted_tags = {tag.strip().lower() for tag in tags if tag.strip()}
        count = 0
        for path in self.root.glob("*.md"):
            metadata = self._metadata(path)
            if str(metadata.get("category", "")).lower() != category.lower():
                continue
            case_tags = {str(tag).lower() for tag in metadata.get("tags", [])}
            if wanted_tags and not wanted_tags.intersection(case_tags):
                continue
            count += 1
        return count


_manager: CaseManager | None = None


def get_case_manager() -> CaseManager:
    global _manager
    if _manager is None:
        _manager = CaseManager()
    return _manager
