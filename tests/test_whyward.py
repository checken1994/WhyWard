from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from whyward.capability import CapabilityBroker
from whyward.control import ControlPlane
from whyward.evidence import KnowledgeStore
from whyward.execution import SandboxExecutor
from whyward.ledger import Ledger
from whyward.models import (
    ActionRequest,
    Claim,
    EvidenceRef,
    HumanDecision,
    Proposal,
    RiskTier,
    TaskState,
    VerdictStatus,
)
from whyward.policy import Policy
from whyward.workers import ScriptedWorker

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "examples" / "catalog"
SECRET = b"whyward-test-secret-32-bytes-long"


def make_evidence(evidence_id: str = "ev-1", lineage: str = "lineage-a") -> EvidenceRef:
    return EvidenceRef(
        evidence_id=evidence_id,
        source_id="internal-test",
        lineage_id=lineage,
        title="Deterministic test evidence",
        observed_fields=("requested action", "sandbox resource"),
        blind_spots=("does not measure end-user value",),
        retrieved_at="2026-10-26T00:00:00Z",
        review_status="verified",
        observation_method="unit-test fixture",
    )


class KnowledgeStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.store = KnowledgeStore.load(CATALOG)

    def test_valdivia_question_does_not_require_answer_token(self) -> None:
        result = self.store.answer_query("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
        self.assertEqual(result.status, "FOUND")
        self.assertEqual(result.value, 9.5)
        self.assertEqual(result.candidates, ("geology.earthquake:valdivia-1960",))

    def test_year_2004_at_another_place_does_not_match_sumatra(self) -> None:
        result = self.store.answer_query("Động đất năm 2004 tại California có độ lớn bao nhiêu?")
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(result.record)

    def test_sumatra_by_name_and_year(self) -> None:
        result = self.store.answer_query("Magnitude of the Sumatra earthquake in 2004?")
        self.assertEqual(result.status, "FOUND")
        self.assertEqual(result.value, 9.1)

    def test_superlative_is_scoped_to_incomplete_catalog(self) -> None:
        result = self.store.answer_query("Động đất mạnh nhất là gì?")
        self.assertEqual(result.status, "FOUND_SCOPED")
        self.assertEqual(result.value, 9.5)
        self.assertIn("not declared globally complete", " ".join(result.reasons))

    def test_lookup_result_serializes_the_full_record(self) -> None:
        result = self.store.answer_query("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
        payload = result.to_dict()
        self.assertEqual(payload["record"]["entity"]["year"], 1960)
        self.assertEqual(payload["record"]["facts"]["magnitude"]["value"], 9.5)

    def test_snapshot_is_immutable(self) -> None:
        record = self.store.get_by_id("geology.earthquake:valdivia-1960")
        assert record is not None
        with self.assertRaises(TypeError):
            record["entity"]["year"] = 2000  # type: ignore[index]


class LedgerTests(unittest.TestCase):
    def test_hash_chain_and_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = Ledger(path)
            ledger.append("A", "tester", {"value": 1})
            ledger.append("B", "tester", {"value": 2})
            valid, message = ledger.verify()
            self.assertTrue(valid, message)
            checkpoint = ledger.checkpoint(signing_key=SECRET)
            self.assertEqual(checkpoint["event_count"], 2)
            self.assertIn("signature", checkpoint)

    def test_tampered_ledger_is_rejected_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = Ledger(path)
            ledger.append("A", "tester", {"value": 1})
            text = path.read_text(encoding="utf-8").replace('"value":1', '"value":999')
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                Ledger(path)


class CapabilityAndSandboxTests(unittest.TestCase):
    def test_capability_is_scoped_and_one_use(self) -> None:
        broker = CapabilityBroker(SECRET)
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p1", actions=[action])
        broker.consume(token, action)
        with self.assertRaises(PermissionError):
            broker.consume(token, action)

    def test_write_and_readback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broker = CapabilityBroker(SECRET)
            executor = SandboxExecutor(Path(tmp) / "workspace", broker)
            content = "hello WhyWard"
            action = ActionRequest(
                "write-a",
                "write_text",
                "notes/a.txt",
                {"content": content, "expected_sha256": hashlib.sha256(content.encode()).hexdigest()},
            )
            token = broker.issue(proposal_id="p1", actions=[action])
            result = executor.execute(action, token)
            self.assertTrue(result["ok"])
            self.assertEqual((Path(tmp) / "workspace" / "notes" / "a.txt").read_text(), content)

    def test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broker = CapabilityBroker(SECRET)
            executor = SandboxExecutor(Path(tmp) / "workspace", broker)
            action = ActionRequest("evil", "write_text", "../evil.txt", {"content": "x"})
            token = broker.issue(proposal_id="p1", actions=[action])
            with self.assertRaises(PermissionError):
                executor.execute(action, token)

    def test_run_python_uses_no_shell_and_returns_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            workspace.mkdir(parents=True)
            (workspace / "hello.py").write_text("print('ok-from-sandbox')\n", encoding="utf-8")
            broker = CapabilityBroker(SECRET)
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("run-hello", "run_python", "hello.py", {"timeout_seconds": 5})
            token = broker.issue(proposal_id="p1", actions=[action])
            result = executor.execute(action, token)
            self.assertTrue(result["ok"])
            self.assertIn("ok-from-sandbox", result["stdout"])


class ControlPlaneTests(unittest.TestCase):
    def build_control(self, tmp: str, *, kill_switch_file: Path | None = None) -> tuple[ControlPlane, Path]:
        root = Path(tmp)
        workspace = root / "workspace"
        broker = CapabilityBroker(SECRET)
        control = ControlPlane(
            policy=Policy.default(),
            ledger=Ledger(root / "ledger.jsonl"),
            capability_broker=broker,
            executor=SandboxExecutor(workspace, broker),
            knowledge_store=KnowledgeStore.load(CATALOG),
            kill_switch_file=kill_switch_file,
        )
        return control, workspace

    @staticmethod
    def low_risk_proposal() -> Proposal:
        return Proposal(
            proposal_id="low-write",
            title="Write a sandbox file",
            summary="Write result.txt in the sandbox.",
            rationale="A deterministic low-risk action for boundary testing.",
            claims=(
                Claim(
                    claim_id="claim-1",
                    statement="The action is limited to result.txt.",
                    evidence_ids=("ev-1",),
                ),
            ),
            actions=(
                ActionRequest(
                    action_id="write-result",
                    tool="write_text",
                    resource="result.txt",
                    parameters={"content": "governed"},
                    reversible=True,
                ),
            ),
            rollback_plan="Delete result.txt.",
            requested_autonomy=2,
            risk_tier=RiskTier.LOW,
        )

    def test_low_risk_worker_proposal_executes_through_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control, workspace = self.build_control(tmp)
            control.register_evidence(make_evidence())
            task = control.create_task("t1", "tester", "write a governed file")
            decision = control.run_worker(task, ScriptedWorker(self.low_risk_proposal()))
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.PASS_WITHIN_SCOPE)
            self.assertEqual(task.state, TaskState.COMPLETED)
            self.assertEqual((workspace / "result.txt").read_text(), "governed")
            self.assertTrue(control.ledger.verify()[0])

    def test_claim_without_evidence_is_withheld(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control, workspace = self.build_control(tmp)
            proposal = Proposal(
                proposal_id="no-evidence",
                title="Unsupported write",
                summary="Try to write without evidence.",
                rationale="The model says so.",
                claims=(Claim("c1", "This is safe"),),
                actions=(ActionRequest("w", "write_text", "x.txt", {"content": "bad"}),),
            )
            task = control.create_task("t2", "tester", "unsupported action")
            decision = control.submit_proposal(task, proposal)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.INSUFFICIENT_EVIDENCE)
            self.assertFalse((workspace / "x.txt").exists())

    def test_protected_path_is_blocked_by_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control, workspace = self.build_control(tmp)
            control.register_evidence(make_evidence())
            proposal = Proposal(
                proposal_id="protected",
                title="Write policy",
                summary="Try to alter a protected resource.",
                rationale="Adversarial fixture.",
                claims=(Claim("c1", "Target is named explicitly.", ("ev-1",)),),
                actions=(ActionRequest("w", "write_text", "policy/core.json", {"content": "bad"}),),
                rollback_plan="Restore the prior policy from an external signed copy.",
            )
            task = control.create_task("t3", "tester", "protected path")
            decision = control.submit_proposal(task, proposal)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.BLOCKED_BY_POLICY)
            self.assertFalse((workspace / "policy" / "core.json").exists())

    def test_high_risk_requires_human_comprehension(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control, workspace = self.build_control(tmp)
            control.register_evidence(make_evidence("ev-1", "lineage-a"))
            control.register_evidence(make_evidence("ev-2", "lineage-b"))
            proposal = Proposal(
                proposal_id="high-write",
                title="High-risk governed write",
                summary="Write an important sandbox artifact.",
                rationale="Exercise the comprehension gate.",
                claims=(Claim("c1", "The action and target are explicitly scoped.", ("ev-1", "ev-2")),),
                actions=(ActionRequest("w", "write_text", "important.txt", {"content": "approved"}),),
                alternatives=("Do nothing", "Use a manual process"),
                consequences_if_done=("The artifact will exist and can be audited.",),
                consequences_if_not_done=("The workflow remains manual.",),
                unknowns=("Whether downstream consumers accept the format.",),
                rollback_plan="Delete important.txt and restore the previous artifact from backup.",
                requested_autonomy=4,
                risk_tier=RiskTier.HIGH,
            )
            waiting_task = control.create_task("t4a", "tester", "high risk without approval")
            waiting = control.submit_proposal(waiting_task, proposal)
            self.assertEqual(waiting.status, VerdictStatus.AWAITING_HUMAN)
            self.assertIsNotNone(waiting.approval_package)
            self.assertFalse((workspace / "important.txt").exists())

            approved_task = control.create_task("t4b", "tester", "high risk with approval")
            human = HumanDecision(
                decision_id="decision-1",
                approver="owner@example.invalid",
                approved=True,
                restatement="Tôi duyệt ghi artifact trong sandbox và hiểu có thể xóa để rollback.",
                reason="Phạm vi hẹp, có bằng chứng và rollback rõ.",
                comprehension={"action": True, "consequence": True, "rollback": True},
            )
            decision = control.submit_proposal(approved_task, proposal, human_decision=human)
            self.assertTrue(decision.allowed, decision.reasons)
            self.assertEqual((workspace / "important.txt").read_text(), "approved")

    def test_kill_switch_blocks_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kill_file = Path(tmp) / "STOP"
            kill_file.write_text("stop", encoding="utf-8")
            control, _ = self.build_control(tmp, kill_switch_file=kill_file)
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["verdict"], VerdictStatus.BLOCKED_BY_POLICY.value)

    def test_answer_question_uses_reviewed_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control, _ = self.build_control(tmp)
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["verdict"], VerdictStatus.PASS_WITHIN_SCOPE.value)
            self.assertIn("9.5", result["answer"])
            self.assertEqual(result["evidence"]["source_id"], "usgs")


if __name__ == "__main__":
    unittest.main()
