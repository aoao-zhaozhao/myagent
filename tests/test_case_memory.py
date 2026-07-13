from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent.case_evidence import begin_case_evidence_gate, end_case_evidence_gate, record_verified_evidence
from agent.case_manager import CaseManager
from agent.evolution.store import EvolutionStore
from agent.rag import RAGManager
from agent.skill_manager import SkillManager
from agent.tools.case_tools import case_create
from agent.tools.results import parse_tool_result


class CaseMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_case_manager_writes_structured_rag_document(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        record = manager.create(
            title="Trailing newline validation bypass",
            target="authorized CTF",
            summary="A validation bypass was confirmed.",
            evidence="The source exposed an unquoted shell command.",
            solution="Use a harmless proof before any further CTF step.",
            category="general",
            tags=["php", "ctf"],
            verified_evidence={"reference": "evidence-1", "tool": "verify_injection", "title": "Confirmed validation bypass", "category": "general"},
        )

        document = Path(str(record["path"])).read_text(encoding="utf-8")
        self.assertIn("category: general", document)
        self.assertIn("## Evidence", document)
        self.assertIn("## Resolution", document)

    def test_rag_discovers_nested_case_documents(self):
        knowledge = self.root / "knowledge"
        case_path = knowledge / "cases" / "example.md"
        case_path.parent.mkdir(parents=True)
        case_path.write_text("---\nverified: true\n---\n\n# Case\n\n## Summary\n\nExample", encoding="utf-8")
        config = SimpleNamespace(
            knowledge_dir=str(knowledge),
            chroma_persist_dir=str(self.root / "chroma"),
            embedding_model_dir=str(self.root / "embedding"),
            reranker_model_dir=str(self.root / "reranker"),
            rag_top_k=4,
            rag_candidate_multiplier=3,
        )

        rag = RAGManager(config)
        self.assertEqual(rag._source_name(case_path), "cases/example.md")
        self.assertEqual(rag._knowledge_files(), [case_path])
        (knowledge / "cases" / "unverified.md").write_text("---\nverified: false\n---\n\n# Old", encoding="utf-8")
        self.assertEqual(rag._knowledge_files(), [case_path])
        initial_hash = rag._source_hash(case_path)
        case_path.write_text("# Case\n\n## Summary\n\nUpdated", encoding="utf-8")
        self.assertNotEqual(initial_hash, rag._source_hash(case_path))

    def test_case_similarity_requires_matching_category_and_tags(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        for title in ("First PHP case", "Second PHP case"):
            manager.create(
                title=title,
                target="authorized CTF",
                summary="summary",
                evidence="evidence",
                solution="solution",
                category="general",
                tags=["php", "command-injection"],
                verified_evidence={"reference": f"evidence-{title}", "tool": "verify_injection", "title": "Confirmed command injection", "category": "general"},
            )

        self.assertEqual(manager.count_similar("general", ["php"]), 2)
        self.assertEqual(manager.count_similar("auth", ["php"]), 0)

    def test_case_manager_redacts_flags_and_credentials_before_writing(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        record = manager.create(
            title="CTF flag wctf{should-not-persist}",
            target="http://authorized.test/?api_key=private-value",
            summary="The flag is wctf{should-not-persist}.",
            evidence="Authorization: Bearer private-token",
            solution="password=private-value must not be retained.",
            category="general",
            verified_evidence={"reference": "evidence-redaction", "tool": "verify_injection", "title": "Confirmed finding", "category": "general"},
        )

        document = Path(str(record["path"])).read_text(encoding="utf-8")
        self.assertNotIn("should-not-persist", document)
        self.assertNotIn("private-token", document)
        self.assertNotIn("private-value", document)
        self.assertIn("[REDACTED]", document)

    def test_case_manager_deduplicates_a_verified_evidence_fingerprint(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        evidence = {"reference": "same-evidence", "tool": "verify_injection", "title": "Confirmed finding", "category": "general"}
        first = manager.create(title="First", target="http://authorized.test", summary="s", evidence="e", solution="r", verified_evidence=evidence)
        second = manager.create(title="Second", target="http://authorized.test", summary="s", evidence="e", solution="r", verified_evidence=evidence)
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["id"], second["id"])

    def test_case_tool_requires_verified_run_evidence(self):
        manager = CaseManager(self.root / "knowledge" / "cases")
        arguments = {
            "target": "http://authorized.test", "title": "Verified login bypass", "summary": "summary",
            "evidence": "evidence", "solution": "solution", "category": "auth",
        }
        with patch("agent.tools.case_tools.get_case_manager", return_value=manager):
            rejected = parse_tool_result(case_create.func(**arguments))[1]
            self.assertEqual(rejected["errors"][0]["kind"], "case_not_verified")

            token = begin_case_evidence_gate("run-1", "http://authorized.test")
            try:
                record_verified_evidence("verify_injection", {
                    "status": "ok",
                    "findings": [{"title": "Confirmed auth bypass", "confidence": "confirmed", "category": "auth"}],
                })
                accepted = parse_tool_result(case_create.func(**arguments))[1]
            finally:
                end_case_evidence_gate(token)
        self.assertEqual(accepted["status"], "ok")
        self.assertTrue(accepted["data"]["created"])

    def test_archive_handles_missing_agent_skill_document(self):
        store = EvolutionStore(self.root / "evolution.db")
        manager = SkillManager(self.root / "skills", store=store)
        manager.create("temporary-skill", "test", "body", "general")
        skill_path = self.root / "skills" / "general" / "temporary-skill"
        for child in skill_path.iterdir():
            child.unlink()
        skill_path.rmdir()

        self.assertTrue(manager.archive("temporary-skill"))
        self.assertEqual(store.get_skill("temporary-skill")["state"], "archived")
        store.close()


if __name__ == "__main__":
    unittest.main()
