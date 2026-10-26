"""Core behavioural tests: the happy path, and the withholding rules."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from support import CATALOG, approval, build_control, evidence, proposal

from whyward.evidence import KnowledgeStore
from whyward.models import ActionRequest, Claim, Proposal, RiskTier, TaskState, VerdictStatus


class KnowledgeStoreTests(unittest.TestCase):
    ACCEPTED = frozenset({"verified", "demo_verified"})

    @classmethod
    def setUpClass(cls) -> None:
        cls.store = KnowledgeStore.load(CATALOG)

    def answer(self, question: str):
        return self.store.answer_query(question, accepted_review_statuses=self.ACCEPTED)

    def test_valdivia_question_does_not_require_answer_token(self) -> None:
        result = self.answer("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
        self.assertEqual(result.status, "FOUND")
        self.assertEqual(result.value, 9.5)
        self.assertEqual(result.candidates, ("geology.earthquake:valdivia-1960",))

    def test_year_2004_at_another_place_does_not_match_sumatra(self) -> None:
        result = self.answer("Động đất năm 2004 tại California có độ lớn bao nhiêu?")
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(result.record)

    def test_sumatra_by_name_and_year(self) -> None:
        result = self.answer("Magnitude of the Sumatra earthquake in 2004?")
        self.assertEqual(result.status, "FOUND")
        self.assertEqual(result.value, 9.1)

    def test_superlative_is_scoped_to_incomplete_catalog(self) -> None:
        result = self.answer("Động đất mạnh nhất là gì?")
        self.assertEqual(result.status, "FOUND_SCOPED")
        self.assertEqual(result.value, 9.5)
        self.assertIn("not declared globally complete", " ".join(result.reasons))

    def test_lookup_result_serializes_the_full_record(self) -> None:
        result = self.answer("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
        payload = result.to_dict()
        self.assertEqual(payload["record"]["entity"]["year"], 1960)
        self.assertEqual(payload["record"]["facts"]["magnitude"]["value"], 9.5)
        self.assertTrue(payload["dataset_digest"])

    def test_snapshot_is_immutable(self) -> None:
        record = self.store.get_by_id("geology.earthquake:valdivia-1960")
        assert record is not None
        with self.assertRaises(TypeError):
            record["entity"]["year"] = 2000  # type: ignore[index]

    def test_domain_filter(self) -> None:
        result = self.store.answer_query(
            "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
            domain="geology.volcano",
            accepted_review_statuses=self.ACCEPTED,
        )
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")


class ControlPlaneHappyPathTests(unittest.TestCase):
    def test_low_risk_proposal_executes_through_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            task = control.create_task("t1", "tester", "write a governed file")
            decision = control.submit_proposal(task, proposal())
            self.assertTrue(decision.allowed, decision.reasons)
            self.assertEqual(decision.status, VerdictStatus.PASS_WITHIN_SCOPE)
            self.assertEqual(task.state, TaskState.COMPLETED)
            self.assertEqual((Path(tmp) / "workspace" / "result.txt").read_text(), "governed")
            self.assertTrue(control.ledger.verify()[0])
            self.assertTrue(decision.decision_digest)

    def test_ledger_records_lineage_of_the_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            task = control.create_task("t1", "tester", "goal", trace_id="a" * 32)
            target = proposal()
            decision = control.submit_proposal(task, target)
            events = list(control.ledger.iter_events())
            types = [event["event_type"] for event in events]
            self.assertEqual(
                types,
                [
                    "TASK_RECEIVED",
                    "PROPOSAL_RECEIVED",
                    "PROPOSAL_REVIEWED",
                    "ACTION_EXECUTED",
                    "TASK_COMPLETED_WITHIN_SCOPE",
                ],
            )
            received = events[1]["payload"]
            self.assertEqual(received["proposal_digest"], target.digest())
            self.assertEqual(received["policy_digest"], control.policy.digest())
            self.assertEqual(received["dataset_digest"], control.knowledge_store.dataset_digest)
            self.assertEqual(events[0]["trace_id"], "a" * 32)
            self.assertEqual(events[3]["payload"]["readback_sha256"], decision.execution_results[0]["readback_sha256"])
            self.assertTrue(events[0]["event_id"])
            self.assertEqual(len(events[0]["event_id"]), 26)

    def test_lookup_requires_registered_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, register_catalog_evidence=False)
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["verdict"], VerdictStatus.INSUFFICIENT_EVIDENCE.value)
            self.assertEqual(result["code"], "UNKNOWN_EVIDENCE")

    def test_lookup_is_answered_with_registered_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["verdict"], VerdictStatus.PASS_WITHIN_SCOPE.value)
            self.assertIn("9.5", result["answer"])
            self.assertEqual(result["evidence"]["source_id"], "usgs")
            self.assertTrue(result["evidence"]["registry_signature"])
            self.assertTrue(result["dataset_digest"])


class WithholdingTests(unittest.TestCase):
    def test_claim_without_evidence_is_withheld(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            task = control.create_task("t2", "tester", "unsupported action")
            decision = control.submit_proposal(
                task,
                Proposal(
                    proposal_id="no-evidence",
                    title="Unsupported write",
                    summary="Try to write without evidence.",
                    rationale="The model says so.",
                    claims=(Claim("c1", "This is safe"),),
                    actions=(ActionRequest("w", "write_text", "x.txt", {"content": "bad"}),),
                ),
            )
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.INSUFFICIENT_EVIDENCE)
            self.assertFalse((Path(tmp) / "workspace" / "x.txt").exists())

    def test_protected_path_is_blocked_by_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            task = control.create_task("t3", "tester", "protected path")
            decision = control.submit_proposal(
                task, proposal(proposal_id="protected", resources=("policy/core.json",), risk=RiskTier.MEDIUM)
            )
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.BLOCKED_BY_POLICY)
            self.assertFalse((Path(tmp) / "workspace" / "policy" / "core.json").exists())

    def test_unknown_evidence_is_withheld(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            task = control.create_task("t4", "tester", "unknown evidence")
            decision = control.submit_proposal(task, proposal(evidence_ids=("ev-does-not-exist",)))
            self.assertEqual(decision.status, VerdictStatus.INSUFFICIENT_EVIDENCE)
            self.assertIn("UNKNOWN_EVIDENCE", [finding.code for finding in decision.findings])

    def test_tool_outside_allowlist_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            task = control.create_task("t5", "tester", "shell")
            decision = control.submit_proposal(
                task, proposal(proposal_id="shell", tool="run_shell", resources=("x.sh",), risk=RiskTier.MEDIUM)
            )
            self.assertEqual(decision.status, VerdictStatus.BLOCKED_BY_POLICY)

    def test_duplicate_action_ids_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            target = proposal()
            duplicate = Proposal(
                **{
                    **target.__dict__,
                    "actions": (
                        ActionRequest("same", "write_text", "a.txt", {"content": "1"}),
                        ActionRequest("same", "write_text", "b.txt", {"content": "2"}),
                    ),
                }
            )
            task = control.create_task("t6", "tester", "duplicate action ids")
            decision = control.submit_proposal(task, duplicate)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.BLOCKED_BY_POLICY)

    def test_kill_switch_blocks_lookup_and_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kill_file = Path(tmp) / "STOP"
            kill_file.write_text("stop", encoding="utf-8")
            control = build_control(tmp, kill_switch_file=kill_file)
            lookup = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(lookup["verdict"], VerdictStatus.BLOCKED_BY_POLICY.value)
            evidence(control, "ev-1", "lineage-a")
            task = control.create_task("t7", "tester", "blocked")
            decision = control.submit_proposal(task, proposal())
            self.assertEqual(decision.status, VerdictStatus.BLOCKED_BY_POLICY)
            self.assertEqual(decision.code, "KILL_SWITCH_ENGAGED")


class HighRiskHumanGateTests(unittest.TestCase):
    def build_high_risk(self):
        return proposal(
            proposal_id="high-write",
            risk=RiskTier.HIGH,
            autonomy=4,
            evidence_ids=("ev-1", "ev-2"),
        )

    def test_high_risk_without_decision_awaits_human(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            task = control.create_task("t8", "tester", "high risk")
            decision = control.submit_proposal(task, self.build_high_risk())
            self.assertEqual(decision.status, VerdictStatus.AWAITING_HUMAN)
            self.assertTrue(decision.required_human)
            self.assertIsNotNone(decision.approval_package)
            self.assertEqual(decision.approval_package["proposal_digest"], self.build_high_risk().digest())
            self.assertFalse((Path(tmp) / "workspace" / "result.txt").exists())

    def test_signed_bound_decision_executes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            target = self.build_high_risk()
            task = control.create_task("t9", "tester", "high risk approved")
            decision = control.submit_proposal(task, target, human_decision=approval(control, task.task_id, target))
            self.assertTrue(decision.allowed, decision.reasons)
            self.assertEqual((Path(tmp) / "workspace" / "result.txt").read_text(), "governed")


if __name__ == "__main__":
    unittest.main()
