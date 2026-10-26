"""Edge cases and failure paths.

These tests exist because robustness is defined by what happens when things go
wrong: unreadable files, disabled features, stale evidence, unknown keys, bad
input. They also keep the coverage gate honest.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC
from pathlib import Path

from support import CATALOG, Clock, approval, build_control, evidence, keyring, proposal

from whyward.capability import CapabilityBroker
from whyward.errors import (
    CapabilityError,
    ConfigurationError,
    EvidenceError,
    ExecutionError,
    IntegrityError,
    PolicyError,
)
from whyward.evidence import KnowledgeStore
from whyward.execution import SandboxExecutor
from whyward.identity import (
    ApiTokenStore,
    Keyring,
    generate_api_token,
    hash_token,
    sign_document,
    verify_envelope,
)
from whyward.isolation import DockerSandboxBackend, isolation_report
from whyward.ledger import Ledger
from whyward.models import ActionRequest, EvidenceRef, RiskTier, TaskState, VerdictStatus
from whyward.policy import Policy, PolicyLimits
from whyward.registry import EvidenceRecord, EvidenceRegistry
from whyward.review import has_blockers, review_proposal, verdict_for_findings
from whyward.workers import CallableWorker, ScriptedWorker


class ExecutionEdgeTests(unittest.TestCase):
    def broker(self) -> CapabilityBroker:
        return CapabilityBroker(keyring(), key_id="capability")

    def test_run_python_success_and_output_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "ok.py").write_text("print('hello from sandbox')", encoding="utf-8")
            broker = self.broker()
            executor = SandboxExecutor(workspace, broker, allow_python=True)
            action = ActionRequest("a", "run_python", "ok.py", {"timeout_seconds": 10})
            result = executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertTrue(result["ok"])
            self.assertIn("hello from sandbox", result["stdout"])
            self.assertEqual(result["backend"], "subprocess-rlimit")
            self.assertTrue(result["output_sha256"])

    def test_run_python_output_is_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "loud.py").write_text("print('x' * 5000)", encoding="utf-8")
            broker = self.broker()
            executor = SandboxExecutor(
                workspace,
                broker,
                allow_python=True,
                limits=replace(PolicyLimits(), max_python_output_bytes=100),
            )
            action = ActionRequest("a", "run_python", "loud.py", {"timeout_seconds": 10})
            result = executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertTrue(result["output_truncated"])
            self.assertLessEqual(len(result["stdout"]), 100)

    def test_run_python_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "slow.py").write_text("import time\ntime.sleep(5)", encoding="utf-8")
            broker = self.broker()
            executor = SandboxExecutor(
                workspace,
                broker,
                allow_python=True,
                limits=replace(PolicyLimits(), max_python_timeout_seconds=1),
            )
            action = ActionRequest("a", "run_python", "slow.py", {"timeout_seconds": 1})
            with self.assertRaises(ExecutionError) as ctx:
                executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertEqual(ctx.exception.code, "PYTHON_TIMEOUT")

    def test_run_python_requires_py_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "script.sh").write_text("echo hi", encoding="utf-8")
            broker = self.broker()
            executor = SandboxExecutor(workspace, broker, allow_python=True)
            action = ActionRequest("a", "run_python", "script.sh", {})
            with self.assertRaises(ExecutionError) as ctx:
                executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertEqual(ctx.exception.code, "PYTHON_PROGRAM_INVALID")

    def test_run_python_rejects_nul_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "prog.py").write_text("print(1)", encoding="utf-8")
            broker = self.broker()
            executor = SandboxExecutor(workspace, broker, allow_python=True)
            action = ActionRequest("a", "run_python", "prog.py", {"args": ["bad\x00arg"]})
            with self.assertRaises(ExecutionError) as ctx:
                executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertEqual(ctx.exception.code, "PYTHON_ARGS_INVALID")

    def test_read_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broker = self.broker()
            executor = SandboxExecutor(Path(tmp), broker)
            action = ActionRequest("a", "read_text", "missing.txt", {})
            with self.assertRaises(ExecutionError) as ctx:
                executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertEqual(ctx.exception.code, "READ_REFUSED")

    def test_unsupported_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broker = self.broker()
            executor = SandboxExecutor(Path(tmp), broker)
            action = ActionRequest("a", "format_disk", "x", {})
            with self.assertRaises(ExecutionError):
                executor.execute(action, broker.issue(proposal_id="p", actions=[action]))

    def test_absolute_and_nul_resources_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broker = self.broker()
            executor = SandboxExecutor(Path(tmp), broker)
            for resource in ("/etc/passwd", "a\x00b", ""):
                action = ActionRequest("a", "read_text", resource, {})
                with self.assertRaises((ExecutionError, CapabilityError)):
                    executor.execute(action, broker.issue(proposal_id="p", actions=[action]))

    def test_read_binary_content_is_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "bin.dat").write_bytes(b"\xff\xfe\x00abc")
            broker = self.broker()
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("a", "read_text", "bin.dat", {})
            result = executor.execute(action, broker.issue(proposal_id="p", actions=[action]))
            self.assertTrue(result["ok"])
            self.assertIn("abc", result["content"])


class IdentityEdgeTests(unittest.TestCase):
    def test_keyring_generate_and_from_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            ring = Keyring.generate("demo-key")
            self.assertEqual(ring.ids(), ("demo-key",))
            path.write_text(json.dumps({"demo-key": "a" * 40}), encoding="utf-8")
            loaded = Keyring.from_file(path)
            self.assertEqual(loaded.ids(), ("demo-key",))

    def test_keyring_file_must_be_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                Keyring.from_file(path)

    def test_hex_and_b64_keys(self) -> None:
        ring = Keyring({"hex-key": "hex:" + "ab" * 32, "b64-key": "b64:" + "A" * 44})
        self.assertTrue(ring.has("hex-key"))
        self.assertTrue(ring.has("b64-key"))

    def test_demo_keyring_is_stable(self) -> None:
        self.assertEqual(Keyring.demo().ids(), keyring().ids())

    def test_env_keyring(self) -> None:
        os.environ["WHYWARD_KEY_CI__DEPLOY"] = "q" * 40
        try:
            self.assertIn("ci-deploy", Keyring.from_env().ids())
        finally:
            del os.environ["WHYWARD_KEY_CI__DEPLOY"]

    def test_generate_token_and_hash(self) -> None:
        token = generate_api_token()
        self.assertTrue(token.startswith("ww_"))
        self.assertEqual(len(hash_token(token)), 64)

    def test_token_store_from_file_and_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tokens.json"
            path.write_text(
                json.dumps(
                    [
                        {"token": "ww_" + "b" * 30, "subject": "svc", "scopes": ["ask"]},
                        {"token_sha256": "c" * 64, "subject": "hashed", "scopes": ["read"]},
                    ]
                ),
                encoding="utf-8",
            )
            store = ApiTokenStore.from_file(path)
            self.assertEqual(store.authenticate("Bearer ww_" + "b" * 30).subject, "svc")
            os.environ["WHYWARD_API_TOKENS"] = json.dumps([{"token": "ww_" + "d" * 30, "subject": "env"}])
            try:
                env_store = ApiTokenStore.from_env()
                self.assertEqual(env_store.authenticate("Bearer ww_" + "d" * 30).subject, "env")
            finally:
                del os.environ["WHYWARD_API_TOKENS"]

    def test_token_store_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tokens.json"
            path.write_text(json.dumps([{"subject": "no-token"}]), encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                ApiTokenStore.from_file(path)
            path.write_text(json.dumps({"tokens": "nope"}), encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                ApiTokenStore.from_file(path)

    def test_env_tokens_required(self) -> None:
        os.environ.pop("WHYWARD_API_TOKENS", None)
        with self.assertRaises(ConfigurationError):
            ApiTokenStore.from_env()

    def test_envelope_without_require_returns_false(self) -> None:
        self.assertFalse(verify_envelope({}, keyring(), require=False))

    def test_unsupported_algorithm_is_rejected(self) -> None:
        document = sign_document({"x": 1}, "evidence-ingest", keyring().get("evidence-ingest"))
        document["signature"]["algorithm"] = "none"
        with self.assertRaises(IntegrityError) as ctx:
            verify_envelope(document, keyring())
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_SIGNATURE")

    def test_keyring_allows_untrusted_ids_restriction(self) -> None:
        document = sign_document({"x": 1}, "evidence-ingest", keyring().get("evidence-ingest"))
        with self.assertRaises(IntegrityError) as ctx:
            verify_envelope(document, keyring(), allowed_key_ids={"other"})
        self.assertEqual(ctx.exception.code, "UNTRUSTED_SIGNING_KEY")


class RegistryEdgeTests(unittest.TestCase):
    def base_record(self, **overrides):
        payload = {
            "evidence_id": "ev-1",
            "source_id": "usgs",
            "lineage_id": "lineage-a",
            "retrieved_at": "2026-10-26T00:00:00Z",
            "observed_fields": ["magnitude"],
            "blind_spots": ["no independent refetch"],
            "review_status": "verified",
        }
        payload.update(overrides)
        return payload

    def test_persistence_across_instances(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.jsonl"
            keys = keyring()
            first = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest", path=path)
            first.register(self.base_record())
            second = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest", path=path)
            self.assertTrue(second.has("ev-1"))
            self.assertEqual(second.get("ev-1").lineage_id, "lineage-a")

    def test_incomplete_record_is_rejected(self) -> None:
        registry = EvidenceRegistry(keyring=keyring(), signing_key_id="evidence-ingest")
        with self.assertRaises(EvidenceError) as ctx:
            registry.register({"evidence_id": "ev-2"})
        self.assertEqual(ctx.exception.code, "EVIDENCE_INCOMPLETE")
        self.assertIn("source_id", ctx.exception.details["missing"])

    def test_unknown_evidence_is_typed(self) -> None:
        registry = EvidenceRegistry(keyring=keyring(), signing_key_id="evidence-ingest")
        with self.assertRaises(EvidenceError) as ctx:
            registry.get("nope")
        self.assertEqual(ctx.exception.code, "UNKNOWN_EVIDENCE")

    def test_unknown_signing_key_fails_closed(self) -> None:
        registry = EvidenceRegistry(keyring=keyring(), signing_key_id="not-a-key")
        with self.assertRaises(IntegrityError) as ctx:
            registry.register(self.base_record())
        self.assertEqual(ctx.exception.code, "UNKNOWN_KEY_ID")

    def test_freshness_states(self) -> None:
        from datetime import datetime

        now = datetime(2026, 10, 26, tzinfo=UTC)
        expired = EvidenceRecord.from_mapping(self.base_record(freshness={"valid_until": "2020-01-01"}))
        overdue = EvidenceRecord.from_mapping(self.base_record(freshness={"review_after": "2020-01-01"}))
        current = EvidenceRecord.from_mapping(
            self.base_record(freshness={"class": "volatile"}, retrieved_at="2026-10-25T00:00:00Z")
        )
        stale_by_class = EvidenceRecord.from_mapping(
            self.base_record(freshness={"class": "volatile"}, retrieved_at="2020-01-01T00:00:00Z")
        )
        unknown = EvidenceRecord.from_mapping(self.base_record(freshness={}))
        bad = EvidenceRecord.from_mapping(self.base_record(freshness={"valid_until": "not-a-date"}))
        classes = {"volatile": 86400}
        self.assertEqual(expired.freshness_state(now=now, max_age_seconds_by_class=classes).value, "expired")
        self.assertEqual(overdue.freshness_state(now=now, max_age_seconds_by_class=classes).value, "review_overdue")
        self.assertEqual(current.freshness_state(now=now, max_age_seconds_by_class=classes).value, "current")
        self.assertEqual(
            stale_by_class.freshness_state(now=now, max_age_seconds_by_class=classes).value, "review_overdue"
        )
        self.assertEqual(unknown.freshness_state(now=now).value, "unknown")
        self.assertEqual(bad.freshness_state(now=now).value, "unknown")

    def test_register_from_catalog(self) -> None:
        registry = EvidenceRegistry(keyring=keyring(), signing_key_id="evidence-ingest")
        store = KnowledgeStore.load(CATALOG)
        record = registry.register_from_catalog(catalog_record=store.records[0], review_status="demo_verified")
        self.assertTrue(record.registry_signature)
        self.assertEqual(record.review_status, "demo_verified")
        self.assertTrue(registry.digest())
        self.assertEqual(len(registry.all_records()), 1)

    def test_corrupt_registry_file_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.jsonl"
            path.write_text("{not json}\n", encoding="utf-8")
            with self.assertRaises(EvidenceError):
                EvidenceRegistry(keyring=keyring(), signing_key_id="evidence-ingest", path=path)

    def test_evidence_ref_roundtrip(self) -> None:
        record = EvidenceRecord.from_mapping(self.base_record())
        ref = record.to_ref()
        self.assertEqual(ref.evidence_id, "ev-1")
        self.assertFalse(ref.signed)


class ReviewEdgeTests(unittest.TestCase):
    def test_mapping_evidence_path_requires_signatures(self) -> None:
        unsigned = EvidenceRef(evidence_id="ev-1", source_id="usgs", lineage_id="l1")
        findings = review_proposal(proposal(), {"ev-1": unsigned}, Policy.dev())
        self.assertIn("UNSIGNED_EVIDENCE", [finding.code for finding in findings])
        self.assertTrue(has_blockers(findings))

    def test_verdict_mapping(self) -> None:
        self.assertEqual(verdict_for_findings(()), "PASS_WITHIN_SCOPE")
        self.assertEqual(
            verdict_for_findings((__import__("whyward.models", fromlist=["ReviewFinding"]).ReviewFinding(
                role="security", code="POLICY_VIOLATION", message="x"
            ),)),
            "BLOCKED_BY_POLICY",
        )
        self.assertEqual(
            verdict_for_findings((__import__("whyward.models", fromlist=["ReviewFinding"]).ReviewFinding(
                role="missing_piece", code="CLAIM_WITHOUT_EVIDENCE", message="x"
            ),)),
            "INSUFFICIENT_EVIDENCE",
        )

    def test_irreversible_action_without_rollback(self) -> None:
        target = replace(proposal(risk=RiskTier.HIGH), rollback_plan="")
        target = replace(
            target,
            actions=(ActionRequest("a", "write_text", "x.txt", {"content": "x"}, reversible=False),),
        )
        findings = review_proposal(target, keyring_registry(), Policy.dev())
        codes = [finding.code for finding in findings]
        self.assertIn("ROLLBACK_MISSING", codes)
        self.assertIn("HIGH_RISK_ROLLBACK_MISSING", codes)

    def test_too_many_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            target = proposal(resources=[f"f{index}.txt" for index in range(40)])
            decision = control.submit_proposal(control.create_task("t", "w", "g"), target)
            self.assertFalse(decision.allowed)
            self.assertIn("TOO_MANY_ACTIONS", [finding.code for finding in decision.findings])


def keyring_registry():
    registry = EvidenceRegistry(keyring=keyring(), signing_key_id="evidence-ingest")
    registry.register(
        {
            "evidence_id": "ev-1",
            "source_id": "usgs",
            "lineage_id": "lineage-a",
            "retrieved_at": "2026-10-26T00:00:00Z",
            "observed_fields": ["x"],
            "blind_spots": ["y"],
            "review_status": "verified",
        }
    )
    return registry


class PolicyEdgeTests(unittest.TestCase):
    def test_from_env_reads_policy_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(Policy.dev().to_dict()), encoding="utf-8")
            os.environ["WHYWARD_POLICY"] = str(path)
            try:
                policy = Policy.from_env()
                self.assertEqual(policy.profile, "dev")
            finally:
                del os.environ["WHYWARD_POLICY"]

    def test_from_env_defaults_to_production(self) -> None:
        os.environ.pop("WHYWARD_POLICY", None)
        self.assertEqual(Policy.from_env().profile, "production")

    def test_bad_json_is_a_policy_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text("{oops", encoding="utf-8")
            with self.assertRaises(PolicyError) as ctx:
                Policy.load(path)
            self.assertEqual(ctx.exception.code, "POLICY_INVALID_JSON")

    def test_missing_file_is_a_policy_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyError) as ctx:
                Policy.load(Path(tmp) / "nope.json")
            self.assertEqual(ctx.exception.code, "POLICY_UNREADABLE")

    def test_resource_validation(self) -> None:
        policy = Policy.default()
        for resource in ("/etc/shadow", "a/../../b", "x\x00y", "keys/private.pem", ".git/config"):
            self.assertTrue(policy.evaluate_action(ActionRequest("a", "write_text", resource, {})))

    def test_limits_and_autonomy(self) -> None:
        policy = Policy.dev()
        self.assertIn("limit is", policy.evaluate_proposal_limits(100)[0])
        self.assertEqual(policy.evaluate_proposal_limits(1), ())
        self.assertTrue(policy.human_required(RiskTier.LOW, ["run_python"], 0, True))
        self.assertFalse(Policy.default().human_required(RiskTier.LOW, ["write_text"], 0, True))
        self.assertTrue(Policy.default().human_required(RiskTier.LOW, ["write_text"], 0, False))
        self.assertTrue(policy.human_required(RiskTier.LOW, ["write_text"], 99, True))
        self.assertFalse(policy.human_required(RiskTier.LOW, ["write_text"], 0, True))

    def test_to_text_is_stable(self) -> None:
        self.assertEqual(Policy.default().to_text(), Policy.default().to_text())

    def test_policy_profiles_differ_in_expected_ways(self) -> None:
        dev, prod = Policy.dev(), Policy.default()
        self.assertNotEqual(dev.digest(), prod.digest())
        self.assertIn("run_python", dev.allowed_tools)
        self.assertNotIn("run_python", prod.allowed_tools)


class ControlEdgeTests(unittest.TestCase):
    def test_no_knowledge_store_withholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, with_catalog=False, register_catalog_evidence=False)
            result = control.answer_question("anything")
            self.assertEqual(result["code"], "NO_KNOWLEDGE_STORE")

    def test_no_registry_withholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            control.evidence_registry = None
            self.assertEqual(control.answer_question("anything")["code"], "NO_EVIDENCE_REGISTRY")
            decision = control.submit_proposal(control.create_task("t", "w", "g"), proposal())
            self.assertEqual(decision.code, "NO_EVIDENCE_REGISTRY")

    def test_source_not_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, register_catalog_evidence=False)
            control.evidence_registry.register_from_catalog(
                catalog_record=control.knowledge_store.records[0], review_status="demo_verified"
            )
            control.policy = replace(control.policy, allowed_source_ids=frozenset({"internal-test"}))
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["code"], "SOURCE_NOT_ALLOWLISTED")

    def test_evidence_not_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, register_catalog_evidence=False)
            control.evidence_registry.register_from_catalog(
                catalog_record=control.knowledge_store.records[0], review_status="unverified"
            )
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["code"], "EVIDENCE_NOT_REVIEWED")

    def test_no_executor_blocks_actions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, with_executor=False)
            evidence(control, "ev-1", "lineage-a")
            decision = control.submit_proposal(control.create_task("t", "w", "g"), proposal())
            self.assertEqual(decision.status, VerdictStatus.INSUFFICIENT_OBSERVABILITY)

    def test_execution_failure_marks_rollback_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            target = proposal(resources=("ok.txt", "blocked.txt"))
            (Path(tmp) / "workspace").mkdir(parents=True, exist_ok=True)
            (Path(tmp) / "workspace" / "blocked.txt").write_text("exists", encoding="utf-8")
            decision = control.submit_proposal(control.create_task("t", "w", "g"), target)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.FAIL)
            self.assertEqual(decision.task_state, TaskState.FAILED_ROLLBACK_REQUIRED)
            self.assertEqual(decision.execution_results[0]["ok"], True)

    def test_run_worker_scripted_and_callable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            task = control.create_task("t", "w", "g")
            decision = control.run_worker(
                task, ScriptedWorker(proposal(proposal_id="scripted", resources=("one.txt",)))
            )
            self.assertTrue(decision.allowed)

            class Producer:
                def propose(self, task, context):
                    return proposal(proposal_id="callable", resources=("two.txt",))

            task2 = control.create_task("t2", "w", "g")
            self.assertTrue(control.run_worker(task2, Producer()).allowed)
            task3 = control.create_task("t3", "w", "g")
            worker = CallableWorker(lambda task, context: proposal(proposal_id="fn", resources=("three.txt",)))
            self.assertTrue(control.run_worker(task3, worker).allowed)

    def test_decision_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            target = proposal(risk=RiskTier.HIGH, autonomy=4, evidence_ids=("ev-1", "ev-2"))
            task = control.create_task("t", "w", "g")
            decision = approval(control, task.task_id, target)
            self.assertTrue(control.submit_proposal(task, target, human_decision=decision).allowed)
            task2 = control.create_task("t2", "w", "g")
            replay = control.submit_proposal(task2, target, human_decision=decision)
            self.assertFalse(replay.allowed)
            self.assertTrue(any("DECISION_REPLAYED" in reason for reason in replay.reasons))

    def test_clock_controls_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clock = Clock()
            control = build_control(tmp, clock=clock)
            evidence(
                control,
                "ev-1",
                "lineage-a",
                freshness={"class": "volatile", "valid_until": clock.iso()},
                retrieved_at=clock.iso(),
            )
            clock.advance(days=1)
            decision = control.submit_proposal(control.create_task("t", "w", "g"), proposal())
            self.assertFalse(decision.allowed)
            self.assertIn("EVIDENCE_STALE", [finding.code for finding in decision.findings])

    def test_kill_switch_is_held_in_memory_without_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            self.assertFalse(control.kill_switch_engaged())
            control.engage_kill_switch("probe")
            self.assertTrue(control.kill_switch_engaged())
            control.release_kill_switch()
            self.assertFalse(control.kill_switch_engaged())

    def test_kill_switch_env_variable(self) -> None:
        os.environ["WHYWARD_KILL_SWITCH"] = "1"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                control = build_control(tmp)
                self.assertTrue(control.kill_switch_engaged())
        finally:
            del os.environ["WHYWARD_KILL_SWITCH"]

    def test_approval_package_lists_actions_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            target = proposal(risk=RiskTier.HIGH, autonomy=4)
            package = control.approval_package(target, findings=(), task_id="t")
            self.assertEqual(package.body["actions"][0]["resource"], "result.txt")
            self.assertEqual(package.body["human_must_understand"], ["action", "consequence", "rollback"])
            self.assertTrue(package.package_digest)


class BoundaryHardeningTests(unittest.TestCase):
    def test_kill_switch_blocks_capability_issuance(self) -> None:
        broker = CapabilityBroker(keyring(), key_id="capability")
        broker.set_blocked_hook(lambda: True)
        with self.assertRaises(CapabilityError) as ctx:
            broker.issue(proposal_id="p", actions=[ActionRequest("a", "write_text", "x.txt", {})])
        self.assertEqual(ctx.exception.code, "KILL_SWITCH_ENGAGED")

    def test_kill_switch_revokes_live_capabilities(self) -> None:
        broker = CapabilityBroker(keyring(), key_id="capability")
        action = ActionRequest("a", "write_text", "x.txt", {})
        token = broker.issue(proposal_id="p", actions=[action])
        self.assertEqual(broker.revoke_all(), 1)
        with self.assertRaises(CapabilityError):
            broker.consume(token, action)

    def test_submit_proposal_rejects_non_proposal_objects(self) -> None:
        from whyward.errors import WhyWardError

        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            task = control.create_task("t", "w", "g")
            with self.assertRaises(WhyWardError) as ctx:
                control.submit_proposal(task, {"proposal_id": "x"})  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "PROPOSAL_INVALID")

    def test_submit_proposal_rejects_non_task_objects(self) -> None:
        from whyward.errors import WhyWardError

        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            with self.assertRaises(WhyWardError) as ctx:
                control.submit_proposal("t", proposal())  # type: ignore[arg-type]
            self.assertEqual(ctx.exception.code, "TASK_INVALID")

    def test_submit_ignores_caller_supplied_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, register_catalog_evidence=False)
            forged = EvidenceRef(evidence_id="ev-1", source_id="usgs", lineage_id="l", review_status="verified")
            task = control.create_task("t", "w", "g")
            decision = control.submit_proposal(task, proposal(), evidence={"ev-1": forged})
            self.assertFalse(decision.allowed)
            self.assertIn("UNKNOWN_EVIDENCE", [finding.code for finding in decision.findings])

    def test_cli_policy_loading_uses_configured_keyring(self) -> None:
        from whyward import cli

        args = cli.build_parser().parse_args(
            [
                "ask",
                "q",
                "--catalog",
                str(CATALOG),
                "--policy",
                str(Path(__file__).resolve().parents[1] / "examples" / "policy.dev.json"),
                "--keyring",
                str(Path(__file__).resolve().parents[1] / "examples" / "keys" / "demo.keyring.json"),
            ]
        )
        policy = cli._load_policy(args)
        self.assertEqual(policy.profile, "dev")


class StoreLifetimeTests(unittest.TestCase):
    def test_sqlite_store_releases_its_handle(self) -> None:
        """A leaked SQLite handle locks the file on Windows and blocks cleanup."""
        from whyward.capability import SqliteUsedTokenStore

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "used.sqlite3"
            store = SqliteUsedTokenStore(path)
            self.assertTrue(store.claim("use-1", 4_000_000_000))
            self.assertFalse(store.claim("use-1", 4_000_000_000))
            store.revoke("cap-1", 4_000_000_000)
            self.assertTrue(store.is_revoked("cap-1"))
            self.assertEqual(store.purge(0), 0)
            # Renaming/removing the file must work: no connection may still be open.
            path.unlink()
            self.assertFalse(path.exists())


class IsolationEdgeTests(unittest.TestCase):
    def test_isolation_report_shape(self) -> None:
        report = isolation_report()
        self.assertIn("recommended_backend", report)
        self.assertIn("container_runtime", report)

    def test_try_create_returns_none_without_runtime(self) -> None:
        backend = DockerSandboxBackend.try_create()
        if backend is not None:
            self.assertTrue(backend.available)

    def test_missing_runtime_is_configuration_error(self) -> None:
        with self.assertRaises(ConfigurationError):
            DockerSandboxBackend(runtime="definitely-not-a-runtime")


class LedgerEdgeTests(unittest.TestCase):
    def test_empty_checkpoint_is_genesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "l.jsonl")
            checkpoint = ledger.checkpoint()
            self.assertEqual(checkpoint["head_hash"], Ledger.GENESIS)
            self.assertEqual(checkpoint["event_count"], 0)

    def test_require_signed_ledger_rejects_unsigned_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.jsonl"
            Ledger(path).append("E", "a", {"x": 1})
            with self.assertRaises(IntegrityError) as ctx:
                Ledger(path, require_signature=True)
            self.assertEqual(ctx.exception.code, "LEDGER_INVALID")
            self.assertIn("Unsigned", str(ctx.exception))

    def test_lock_timeout_is_a_typed_error(self) -> None:
        from whyward.ledger import _FileLock

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.jsonl"
            held = _FileLock(path, timeout=1.0, stale_after=600.0)
            def take(lock):
                with lock:
                    return True

            with held, self.assertRaises(IntegrityError) as ctx:
                take(_FileLock(path, timeout=0.2, stale_after=600.0))
            self.assertEqual(ctx.exception.code, "LEDGER_LOCKED")

    def test_stale_lock_is_broken(self) -> None:
        from whyward.ledger import _FileLock

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.jsonl"
            stale = Path(f"{path}.lock")
            stale.write_text("999999\n", encoding="utf-8")
            os.utime(stale, (0, 0))
            with _FileLock(path, timeout=2.0, stale_after=1.0):
                pass
            self.assertFalse(stale.exists())

    def test_missing_anchor_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "l.jsonl")
            valid, message = ledger.verify_against_anchor(Path(tmp) / "nope.json")
            self.assertFalse(valid)
            self.assertIn("missing", message)

    def test_anchor_with_tampered_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            path = Path(tmp) / "l.jsonl"
            anchor = Path(tmp) / "a.json"
            ledger = Ledger(path, keyring=keys, signing_key_id="audit-ledger")
            ledger.append("E", "a", {"x": 1})
            ledger.anchor(anchor, signing_key_id="audit-ledger")
            payload = json.loads(anchor.read_text(encoding="utf-8"))
            payload["checkpoint"]["signature"]["value"] = "0" * 64
            anchor.write_text(json.dumps(payload), encoding="utf-8")
            valid, message = ledger.verify_against_anchor(anchor)
            self.assertFalse(valid)
            self.assertIn("signature is invalid", message)

    def test_corrupt_json_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.jsonl"
            path.write_text("not json\n", encoding="utf-8")
            with self.assertRaises(IntegrityError):
                Ledger(path)

    def test_ledger_signed_by_unknown_key_is_rejected_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.jsonl"
            Ledger(path, keyring=keyring(), signing_key_id="audit-ledger").append("E", "a", {"x": 1})
            with self.assertRaises(IntegrityError) as ctx:
                Ledger(path, keyring=Keyring({"other": "r" * 40}))
            self.assertEqual(ctx.exception.code, "LEDGER_INVALID")
            self.assertIn("Unverifiable", str(ctx.exception))


class KnowledgeStoreEdgeTests(unittest.TestCase):
    def test_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(tmp)
            self.assertEqual(ctx.exception.code, "CATALOG_MISSING")

    def test_unsupported_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog"
            catalog.mkdir()
            (catalog / "manifest.json").write_text(json.dumps({"schema_version": 99, "shards": []}), encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(catalog)
            self.assertEqual(ctx.exception.code, "CATALOG_SCHEMA_UNSUPPORTED")

    def test_duplicate_record_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import shutil

            catalog = Path(tmp) / "catalog"
            shutil.copytree(CATALOG, catalog)
            shard = catalog / "facts" / "geology.earthquakes.jsonl"
            lines = shard.read_text(encoding="utf-8").splitlines()
            shard.write_text("\n".join([lines[0], lines[0]]) + "\n", encoding="utf-8")
            manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
            import hashlib as _hashlib

            manifest["shards"][0]["sha256"] = _hashlib.sha256(shard.read_bytes()).hexdigest()
            (catalog / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(catalog)
            self.assertEqual(ctx.exception.code, "CATALOG_DUPLICATE_RECORD")

    def test_completeness_and_superlative(self) -> None:
        store = KnowledgeStore.load(CATALOG)
        self.assertFalse(store.is_complete_for("geology.earthquake"))
        self.assertTrue(store.dataset_digest)
        self.assertIsNotNone(store.manifest)


class ExecutionErrorPathTests(unittest.TestCase):
    def test_write_to_read_only_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broker = CapabilityBroker(keyring(), key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir()
            (workspace / "sub").write_text("i am a file", encoding="utf-8")
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("a", "write_text", "sub/file.txt", {"content": "x"})
            with self.assertRaises(ExecutionError):
                executor.execute(action, broker.issue(proposal_id="p", actions=[action]))


class WorkerProtocolTests(unittest.TestCase):
    def test_scripted_worker_prefixes_task(self) -> None:
        from whyward.models import TaskRecord

        worker = ScriptedWorker(proposal(proposal_id="base"))
        task = TaskRecord(task_id="t1", requester="w", goal="g")
        produced = worker.propose(task, {})
        self.assertEqual(produced.proposal_id, "t1:base")

    def test_callable_worker(self) -> None:
        from whyward.models import TaskRecord

        worker = CallableWorker(lambda task, context: proposal(proposal_id=f"{task.task_id}-x"))
        produced = worker.propose(TaskRecord(task_id="t2", requester="w", goal="g"), {})
        self.assertEqual(produced.proposal_id, "t2-x")


if __name__ == "__main__":
    unittest.main()
