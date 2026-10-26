"""Negative tests for every finding in the 2026-10-26 audit.

Each class maps to an audit ID (W-xx). These are the tests that used to fail;
they now encode the security contract. Do not delete a test to make a change
pass — that is exactly the failure mode this repo is trying to prevent.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from support import CATALOG, Clock, approval, build_control, evidence, keyring, proposal, sha256

from whyward.capability import CapabilityBroker, InMemoryUsedTokenStore
from whyward.errors import CapabilityError, ConfigurationError, IntegrityError, PolicyError
from whyward.evidence import KnowledgeStore
from whyward.execution import SandboxExecutor
from whyward.identity import Keyring
from whyward.ledger import Ledger
from whyward.models import ActionRequest, RiskTier, TaskState, VerdictStatus
from whyward.policy import Policy
from whyward.registry import EvidenceRegistry


class W01ApprovalBindingTests(unittest.TestCase):
    """Approval must be bound to one proposal, one task, one signed decision."""

    def high_risk(self):
        return proposal(proposal_id="high", risk=RiskTier.HIGH, autonomy=4, evidence_ids=("ev-1", "ev-2"))

    def setup(self, tmp):
        control = build_control(tmp)
        evidence(control, "ev-1", "lineage-a")
        evidence(control, "ev-2", "lineage-b")
        return control

    def test_approval_replayed_on_another_proposal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self.setup(tmp)
            first = self.high_risk()
            task_a = control.create_task("t-a", "worker", "write hello")
            decision = approval(control, task_a.task_id, first)
            self.assertTrue(control.submit_proposal(task_a, first, human_decision=decision).allowed)

            other = replace(
                self.high_risk(),
                proposal_id="other",
                actions=(ActionRequest("a-0", "write_text", "prod/secret.txt", {"content": "pwned " * 5}),),
            )
            task_b = control.create_task("t-b", "worker", "something else")
            replay = control.submit_proposal(task_b, other, human_decision=decision)
            self.assertFalse(replay.allowed)
            self.assertEqual(replay.status, VerdictStatus.AWAITING_HUMAN)
            self.assertTrue(any("DECISION_NOT_BOUND" in reason for reason in replay.reasons), replay.reasons)
            self.assertFalse((Path(tmp) / "workspace" / "prod" / "secret.txt").exists())

    def test_approval_for_another_task_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self.setup(tmp)
            target = self.high_risk()
            task_a = control.create_task("t-a", "worker", "goal")
            decision = approval(control, task_a.task_id, target)
            task_b = control.create_task("t-b", "worker", "goal")
            result = control.submit_proposal(task_b, target, human_decision=decision)
            self.assertFalse(result.allowed)
            self.assertTrue(any("DECISION_WRONG_TASK" in reason for reason in result.reasons))

    def test_expired_approval_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            clock = Clock()
            control = build_control(tmp, clock=clock)
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            target = self.high_risk()
            task = control.create_task("t", "worker", "goal")
            decision = approval(control, task.task_id, target, expires_in_seconds=60)
            clock.advance(minutes=5)
            result = control.submit_proposal(task, target, human_decision=decision)
            self.assertFalse(result.allowed)
            self.assertTrue(any("DECISION_EXPIRED" in reason for reason in result.reasons), result.reasons)

    def test_unsigned_approval_is_rejected_in_production(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, profile="production")
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            target = self.high_risk()
            task = control.create_task("t", "worker", "goal")
            unsigned = approval(control, task.task_id, target, sign=False)
            result = control.submit_proposal(task, target, human_decision=unsigned)
            self.assertFalse(result.allowed)
            self.assertTrue(any("DECISION_UNSIGNED" in reason for reason in result.reasons))

    def test_tampered_signature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, profile="production")
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            target = self.high_risk()
            task = control.create_task("t", "worker", "goal")
            signed = approval(control, task.task_id, target)
            tampered = replace(signed, signature=signed.signature[:-2] + "00")
            result = control.submit_proposal(task, target, human_decision=tampered)
            self.assertFalse(result.allowed)
            self.assertTrue(any("DECISION_BAD_SIGNATURE" in reason for reason in result.reasons))

    def test_missing_comprehension_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self.setup(tmp)
            target = self.high_risk()
            task = control.create_task("t", "worker", "goal")
            decision = replace(approval(control, task.task_id, target), comprehension={"action": True})
            result = control.submit_proposal(task, target, human_decision=decision)
            self.assertFalse(result.allowed)
            self.assertTrue(any("DECISION_NO_COMPREHENSION" in reason for reason in result.reasons))

    def test_rejection_by_human_withholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = self.setup(tmp)
            target = self.high_risk()
            task = control.create_task("t", "worker", "goal")
            decision = approval(control, task.task_id, target, approved=False)
            result = control.submit_proposal(task, target, human_decision=decision)
            self.assertFalse(result.allowed)
            self.assertEqual(result.status, VerdictStatus.BLOCKED_BY_POLICY)
            self.assertEqual(result.code, "HUMAN_REJECTED")


class W02EvidenceTrustTests(unittest.TestCase):
    """Evidence review status must come from the registry, never from the caller."""

    def test_caller_cannot_assert_verified_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            # Legacy path: a caller tries to inject a "verified" ref.
            control.register_evidence(
                {
                    "evidence_id": "forged",
                    "source_id": "usgs",
                    "lineage_id": "attacker-lineage",
                    "retrieved_at": "2026-10-26T00:00:00Z",
                    "observed_fields": ["x"],
                    "blind_spots": [],
                    "review_status": "verified",
                }
            )
            record = control.evidence_registry.get("forged")
            # The registry re-signs it but refuses to inherit an unverified trust claim
            # unless the control core explicitly reviewed it.
            self.assertEqual(record.registry_key_id, "evidence-ingest")
            result = control.submit_proposal(
                control.create_task("t", "worker", "goal"),
                proposal(evidence_ids=("forged",), risk=RiskTier.MEDIUM),
            )
            self.assertFalse(result.allowed)
            self.assertIn(result.status, {VerdictStatus.INSUFFICIENT_EVIDENCE, VerdictStatus.BLOCKED_BY_POLICY})

    def test_evidence_registered_without_signature_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            result = control.submit_proposal(
                control.create_task("t", "worker", "goal"),
                proposal(evidence_ids=("not-registered",)),
            )
            self.assertFalse(result.allowed)
            self.assertIn("UNKNOWN_EVIDENCE", [finding.code for finding in result.findings])

    def test_registry_rejects_conflicting_reregistration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            with self.assertRaises(Exception) as ctx:
                control.evidence_registry.register(
                    {
                        "evidence_id": "ev-1",
                        "source_id": "usgs",
                        "lineage_id": "lineage-b",
                        "retrieved_at": "2026-10-26T00:00:00Z",
                        "observed_fields": ["x"],
                        "blind_spots": ["y"],
                        "review_status": "verified",
                    }
                )
            self.assertEqual(getattr(ctx.exception, "code", ""), "EVIDENCE_CONFLICT")

    def test_tampered_registry_record_is_detected(self) -> None:
        with tempfile.TemporaryDirectory():
            keys = keyring()
            registry = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest")
            record = registry.register(
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
            forged = replace(record, review_status="verified", lineage_id="different-lineage")
            with self.assertRaises(Exception) as ctx:
                registry.verify_record(forged)
            self.assertIn(getattr(ctx.exception, "code", ""), {"BAD_SIGNATURE", "UNTRUSTED_SIGNING_KEY"})

    def test_submit_time_evidence_is_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            from whyward.models import EvidenceRef

            fake = EvidenceRef(
                evidence_id="inline",
                source_id="usgs",
                lineage_id="inline-lineage",
                review_status="verified",
                registry_signature="not-a-real-signature",
                registry_key_id="evidence-ingest",
            )
            result = control.submit_proposal(
                control.create_task("t", "worker", "goal"),
                proposal(evidence_ids=("inline",)),
                evidence={"inline": fake},
            )
            self.assertFalse(result.allowed)
            self.assertIn("UNKNOWN_EVIDENCE", [finding.code for finding in result.findings])


class W03FreshnessTests(unittest.TestCase):
    def stale_catalog(self, tmp: str, *, valid_until: str, review_after: str | None = None) -> Path:
        import shutil

        target = Path(tmp) / "catalog"
        shutil.copytree(CATALOG, target)
        shard = target / "facts" / "geology.earthquakes.jsonl"
        lines = shard.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["freshness"] = {
            "class": "volatile",
            "valid_from": "1990-01-01",
            "valid_until": valid_until,
            "review_after": review_after or valid_until,
        }
        lines[0] = json.dumps(record, ensure_ascii=False)
        shard.write_text("\n".join(lines) + "\n", encoding="utf-8")
        manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
        manifest["shards"][0]["sha256"] = hashlib.sha256(shard.read_bytes()).hexdigest()
        (target / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return target

    def test_expired_record_is_withheld(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.stale_catalog(tmp, valid_until="2020-01-01")
            control = build_control(tmp)
            from whyward.evidence import KnowledgeStore as Store

            control.knowledge_store = Store.load(catalog)
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["verdict"], VerdictStatus.INSUFFICIENT_EVIDENCE.value)

    def test_review_overdue_record_is_flagged_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.stale_catalog(tmp, valid_until="2099-01-01", review_after="2020-01-01")
            store = KnowledgeStore.load(catalog)
            result = store.answer_query(
                "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
                accepted_review_statuses={"verified", "demo_verified"},
            )
            self.assertEqual(result.status, "FOUND_STALE")
            self.assertIn("review_after", " ".join(result.reasons))

    def test_stale_evidence_is_reported_in_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, profile="production")

            control.evidence_registry.register(
                {
                    "evidence_id": "ev-old",
                    "source_id": "usgs",
                    "lineage_id": "lineage-old",
                    "retrieved_at": "2020-01-01T00:00:00Z",
                    "observed_fields": ["x"],
                    "blind_spots": ["y"],
                    "review_status": "verified",
                    "freshness": {"class": "volatile", "valid_until": "2020-02-01"},
                }
            )
            result = control.submit_proposal(
                control.create_task("t", "worker", "goal"), proposal(evidence_ids=("ev-old",))
            )
            self.assertFalse(result.allowed)
            self.assertIn("EVIDENCE_STALE", [finding.code for finding in result.findings])


class W04CatalogIntegrityTests(unittest.TestCase):
    def copy_catalog(self, tmp: str) -> Path:
        import shutil

        target = Path(tmp) / "catalog"
        shutil.copytree(CATALOG, target)
        return target

    def test_record_count_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.copy_catalog(tmp)
            manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
            manifest["shards"][0]["record_count"] = 999
            (catalog / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(catalog)
            self.assertEqual(ctx.exception.code, "CATALOG_COUNT_MISMATCH")

    def test_missing_checksum_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.copy_catalog(tmp)
            manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
            manifest["shards"][0].pop("sha256")
            (catalog / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(catalog)
            self.assertEqual(ctx.exception.code, "CATALOG_UNCHECKED_SHARD")

    def test_checksum_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.copy_catalog(tmp)
            shard = catalog / "facts" / "geology.earthquakes.jsonl"
            shard.write_text(shard.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(catalog)
            self.assertEqual(ctx.exception.code, "CATALOG_CHECKSUM_MISMATCH")

    def test_shard_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.copy_catalog(tmp)
            manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
            manifest["shards"][0]["path"] = "../outside.jsonl"
            (catalog / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(catalog)
            self.assertEqual(ctx.exception.code, "CATALOG_PATH_ESCAPE")

    def test_unsigned_catalog_rejected_when_signature_required(self) -> None:
        with tempfile.TemporaryDirectory():
            with self.assertRaises(IntegrityError) as ctx:
                KnowledgeStore.load(CATALOG, keyring=keyring(), require_signature=True)
            self.assertEqual(ctx.exception.code, "CATALOG_UNSIGNED")

    def test_signed_catalog_is_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            catalog = self.copy_catalog(tmp)
            keys = keyring()
            manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
            from whyward.identity import sign_document

            signed = sign_document(manifest, "demo-manifest-2026", keys.get("demo-manifest-2026"))
            (catalog / "manifest.json").write_text(
                json.dumps({"signature": signed["signature"], **signed["payload"]}, indent=2), encoding="utf-8"
            )
            store = KnowledgeStore.load(
                catalog, keyring=keys, require_signature=True, trust_key_ids={"demo-manifest-2026"}
            )
            self.assertTrue(store.signed)
            self.assertTrue(store.dataset_digest)


class W05PolicyStrictnessTests(unittest.TestCase):
    def valid_policy(self) -> dict:
        return json.loads(json.dumps(Policy.default().to_dict()))

    def test_missing_key_is_a_configuration_error(self) -> None:
        payload = self.valid_policy()
        payload.pop("min_independent_lineages")
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_dict(payload)
        self.assertEqual(ctx.exception.code, "POLICY_MISSING_KEYS")
        self.assertIn("min_independent_lineages", ctx.exception.details["missing"])

    def test_unknown_key_is_rejected(self) -> None:
        payload = self.valid_policy()
        payload["allowed_toolz"] = ["run_python"]
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_dict(payload)
        self.assertEqual(ctx.exception.code, "POLICY_UNKNOWN_KEYS")

    def test_missing_risk_tier_is_a_configuration_error(self) -> None:
        payload = self.valid_policy()
        payload["min_independent_lineages"].pop("critical")
        with self.assertRaises(PolicyError):
            Policy.from_dict(payload)

    def test_run_python_requires_human_outside_dev(self) -> None:
        payload = self.valid_policy()
        payload["allowed_tools"] = ["write_text", "run_python"]
        payload["human_required_tools"] = []
        with self.assertRaises(PolicyError) as ctx:
            Policy.from_dict(payload)
        self.assertEqual(ctx.exception.code, "POLICY_UNSAFE_TOOL")

    def test_default_policy_does_not_allow_code_execution(self) -> None:
        policy = Policy.default()
        self.assertNotIn("run_python", policy.allowed_tools)
        self.assertIn("run_python", policy.human_required_tools)

    def test_unsigned_policy_rejected_when_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(Policy.production_example()), encoding="utf-8")
            with self.assertRaises(PolicyError) as ctx:
                Policy.load(path, require_signature=True)
            self.assertEqual(ctx.exception.code, "POLICY_UNSIGNED")

    def test_signed_policy_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            path = Path(tmp) / "policy.json"
            document = Policy.dev().signed_document("policy-signing", keys.get("policy-signing"))
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = Policy.load(path, keyring=keys, require_signature=True)
            self.assertEqual(loaded.digest(), Policy.dev().digest())

    def test_tampered_policy_signature_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            path = Path(tmp) / "policy.json"
            document = Policy.dev().signed_document("policy-signing", keys.get("policy-signing"))
            document["policy"]["max_autonomy_without_human"] = 99
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(IntegrityError):
                Policy.load(path, keyring=keys, require_signature=True)

    def test_training_wheels_are_detectable(self) -> None:
        payload = json.loads(json.dumps(Policy.production_example()))
        self.assertEqual(payload["profile"], "production")
        self.assertNotIn("demo_verified", payload["accepted_review_statuses"])


class W06LedgerConcurrencyTests(unittest.TestCase):
    def test_many_writers_keep_the_ledger_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            go = Path(tmp) / "go"
            code = (
                "import os, sys, time\n"
                "from whyward.ledger import Ledger\n"
                "l = Ledger(sys.argv[1])\n"
                "while not os.path.exists(sys.argv[2]):\n"
                "    time.sleep(0.001)\n"
                "for i in range(120):\n"
                "    l.append('E', 'writer', {'i': i})\n"
            )
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
            procs = [
                subprocess.Popen([sys.executable, "-c", code, str(path), str(go)], env=env)
                for _ in range(4)
            ]
            time.sleep(0.4)
            go.write_text("go", encoding="utf-8")
            self.assertEqual([proc.wait() for proc in procs], [0, 0, 0, 0])
            ledger = Ledger(path)
            valid, message = ledger.verify()
            self.assertTrue(valid, message)
            self.assertEqual(ledger.event_count, 4 * 120)
            indexes = [event["index"] for event in ledger.iter_events()]
            self.assertEqual(indexes, list(range(1, 4 * 120 + 1)))

    def test_tampered_ledger_is_rejected_on_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = Ledger(path)
            ledger.append("A", "tester", {"value": 1})
            text = path.read_text(encoding="utf-8").replace('"value":1', '"value":999')
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(IntegrityError) as ctx:
                Ledger(path)
            self.assertEqual(ctx.exception.code, "LEDGER_INVALID")

    def test_truncation_is_detected_by_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            path = Path(tmp) / "ledger.jsonl"
            anchor = Path(tmp) / "anchor.json"
            ledger = Ledger(path, keyring=keys, signing_key_id="audit-ledger")
            for index in range(5):
                ledger.append("E", "tester", {"index": index})
            ledger.anchor(anchor)
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            shorter = Ledger(path, keyring=keys)
            valid, message = shorter.verify_against_anchor(anchor)
            self.assertFalse(valid)
            self.assertIn("truncation", message)

    def test_signed_events_verify_and_detect_key_removal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            path = Path(tmp) / "ledger.jsonl"
            ledger = Ledger(path, keyring=keys, signing_key_id="audit-ledger")
            ledger.append("E", "tester", {"x": 1})
            require_signed = Ledger(path, keyring=keys, require_signature=True)
            self.assertTrue(require_signed.verify()[0])
            with self.assertRaises(IntegrityError) as ctx:
                Ledger(path, keyring=Keyring({"someone-else": "x" * 40}))
            self.assertIn("signature", ctx.exception.message.lower())


class W07CapabilityTests(unittest.TestCase):
    def test_capability_is_scoped_and_single_use(self) -> None:
        broker = CapabilityBroker(Keyring({"capability": "k" * 40}))
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p1", actions=[action])
        broker.consume(token, action)
        with self.assertRaises(CapabilityError):
            broker.consume(token, action)

    def test_capability_survives_restart_as_spent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from whyward.capability import SqliteUsedTokenStore

            store_path = Path(tmp) / "used.sqlite3"
            keys = Keyring({"capability": "k" * 40})
            action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
            first_broker = CapabilityBroker(
                keyring=keys, key_id="capability", used_store=SqliteUsedTokenStore(store_path)
            )
            token = first_broker.issue(proposal_id="p1", actions=[action])
            first = CapabilityBroker(keyring=keys, key_id="capability", used_store=SqliteUsedTokenStore(store_path))
            first.consume(token, action)
            restarted = CapabilityBroker(
                keyring=keys, key_id="capability", used_store=SqliteUsedTokenStore(store_path)
            )
            with self.assertRaises(CapabilityError) as ctx:
                restarted.consume(token, action)
            self.assertEqual(ctx.exception.code, "CAPABILITY_REPLAYED")

    def test_capability_rejects_modified_action(self) -> None:
        broker = CapabilityBroker(Keyring({"capability": "k" * 40}))
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p1", actions=[action])
        tampered = ActionRequest("a1", "write_text", "b.txt", {"content": "x"})
        with self.assertRaises(CapabilityError) as ctx:
            broker.consume(token, tampered)
        self.assertEqual(ctx.exception.code, "CAPABILITY_OUT_OF_SCOPE")

    def test_capability_rejects_wrong_audience(self) -> None:
        broker = CapabilityBroker(Keyring({"capability": "k" * 40}), audience="exec-a")
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p1", actions=[action], audience="exec-a")
        other = CapabilityBroker(Keyring({"capability": "k" * 40}), audience="exec-b")
        with self.assertRaises(CapabilityError) as ctx:
            other.consume(token, action)
        self.assertEqual(ctx.exception.code, "CAPABILITY_WRONG_AUDIENCE")

    def test_expired_capability_is_rejected(self) -> None:
        now = [1000.0]
        broker = CapabilityBroker(Keyring({"capability": "k" * 40}), clock=lambda: now[0])
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p1", actions=[action], ttl_seconds=10)
        now[0] += 11
        with self.assertRaises(CapabilityError) as ctx:
            broker.consume(token, action)
        self.assertEqual(ctx.exception.code, "CAPABILITY_EXPIRED")

    def test_revoked_capability_is_rejected(self) -> None:
        broker = CapabilityBroker(Keyring({"capability": "k" * 40}), used_store=InMemoryUsedTokenStore())
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p1", actions=[action])
        self.assertEqual(broker.revoke_all(), 1)
        with self.assertRaises(CapabilityError) as ctx:
            broker.consume(token, action)
        self.assertEqual(ctx.exception.code, "CAPABILITY_REVOKED")

    def test_broker_requires_strong_key(self) -> None:
        with self.assertRaises(ConfigurationError):
            CapabilityBroker(b"short")


class W08KillSwitchTests(unittest.TestCase):
    def test_kill_switch_stops_actions_already_authorized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stop = Path(tmp) / "STOP"
            control = build_control(tmp, kill_switch_file=stop)
            evidence(control, "ev-1", "lineage-a")
            target = proposal(resources=("one.txt", "two.txt"), parameters={"content": "x"})
            task = control.create_task("t", "worker", "goal")
            # Engage the switch after review by patching the broker's blocked hook state.

            original = control.kill_switch_engaged

            calls = {"count": 0}

            def flaky() -> bool:
                calls["count"] += 1
                # Allow the initial gate check, block during execution.
                return calls["count"] > 3

            control.kill_switch_engaged = flaky  # type: ignore[assignment]
            control.capability_broker.set_blocked_hook(flaky)
            control.executor.set_blocked_hook(flaky)
            decision = control.submit_proposal(task, target)
            control.kill_switch_engaged = original  # type: ignore[assignment]
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.status, VerdictStatus.FAIL)
            self.assertEqual(decision.code, "KILL_SWITCH_ENGAGED")
            self.assertFalse((Path(tmp) / "workspace" / "one.txt").exists())
            self.assertFalse((Path(tmp) / "workspace" / "two.txt").exists())

    def test_engage_kill_switch_revokes_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stop = Path(tmp) / "STOP"
            control = build_control(tmp, kill_switch_file=stop)
            action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
            token = control.capability_broker.issue(proposal_id="p1", actions=[action])
            control.engage_kill_switch("test drill", actor="auditor")
            self.assertTrue(control.kill_switch_engaged())
            with self.assertRaises(CapabilityError):
                control.capability_broker.consume(token, action)
            events = [event["event_type"] for event in control.ledger.iter_events()]
            self.assertIn("KILL_SWITCH_ENGAGED", events)
            control.release_kill_switch(actor="auditor")
            self.assertFalse(control.kill_switch_engaged())


class W09W10CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        return subprocess.run(
            [sys.executable, "-m", "whyward.cli", *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_verify_ledger_reports_json_and_exit_2_when_tampered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "ledger.jsonl"
            from whyward.ledger import Ledger

            writer = Ledger(ledger)
            writer.append("A", "tester", {"value": 1})
            ledger.write_text(
                ledger.read_text(encoding="utf-8").replace('"value":1', '"value":2'), encoding="utf-8"
            )
            proc = self.run_cli("verify-ledger", str(ledger))
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["valid"])
            self.assertEqual(payload["error"], "LEDGER_INVALID")

    def test_ask_exit_code_reflects_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            found = self.run_cli(
                "ask",
                "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
                "--catalog",
                str(CATALOG),
                "--ledger",
                str(Path(tmp) / "l.jsonl"),
                "--state-dir",
                tmp,
                "--profile",
                "dev",
            )
            self.assertEqual(found.returncode, 0, found.stderr)
            self.assertIn("PASS_WITHIN_SCOPE", found.stdout)

            withheld = self.run_cli(
                "ask",
                "Động đất năm 2004 tại California có độ lớn bao nhiêu?",
                "--catalog",
                str(CATALOG),
                "--ledger",
                str(Path(tmp) / "l2.jsonl"),
                "--state-dir",
                tmp,
                "--profile",
                "dev",
            )
            self.assertEqual(withheld.returncode, 3, withheld.stderr)
            self.assertIn("INSUFFICIENT_EVIDENCE", withheld.stdout)

    def test_status_and_doctor_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            status = self.run_cli(
                "status", "--profile", "dev", "--ledger", str(Path(tmp) / "l.jsonl"), "--state-dir", tmp
            )
            self.assertEqual(status.returncode, 0, status.stderr)
            payload = json.loads(status.stdout)
            self.assertEqual(payload["policy"]["profile"], "dev")
            doctor = self.run_cli(
                "doctor", "--profile", "dev", "--catalog", str(CATALOG), "--state-dir", tmp
            )
            self.assertEqual(doctor.returncode, 0, doctor.stderr)
            self.assertIn("isolation", json.loads(doctor.stdout))


class W11ProfileTests(unittest.TestCase):
    def test_default_profile_does_not_accept_demo_fixtures(self) -> None:
        self.assertNotIn("demo_verified", Policy.default().accepted_review_statuses)
        self.assertNotIn("demo-source", Policy.default().allowed_source_ids)

    def test_dev_profile_is_loud(self) -> None:
        policy = Policy.dev()
        self.assertEqual(policy.profile, "dev")
        self.assertIn("run_python", policy.allowed_tools)
        import io

        from whyward.observability import StructuredLogger

        buffer = io.StringIO()
        logger = StructuredLogger(stream=buffer)
        from whyward.control import ControlPlane
        from whyward.ledger import Ledger

        with tempfile.TemporaryDirectory() as tmp:
            ControlPlane(policy=policy, ledger=Ledger(Path(tmp) / "l.jsonl"), logger=logger)
        self.assertIn("dev_profile_active", buffer.getvalue())

    def test_production_profile_rejects_demo_catalog_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp, profile="production")
            result = control.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")
            self.assertEqual(result["verdict"], VerdictStatus.INSUFFICIENT_EVIDENCE.value)


class W13ResourceLimitTests(unittest.TestCase):
    def test_write_over_limit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from whyward.policy import PolicyLimits

            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            executor = SandboxExecutor(
                Path(tmp) / "ws", broker, limits=replace(PolicyLimits(), max_write_bytes=16)
            )
            action = ActionRequest("a", "write_text", "big.txt", {"content": "x" * 32})
            token = broker.issue(proposal_id="p", actions=[action])
            with self.assertRaises(Exception) as ctx:
                executor.execute(action, token)
            self.assertEqual(getattr(ctx.exception, "code", ""), "WRITE_TOO_LARGE")

    def test_read_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from whyward.policy import PolicyLimits

            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir(parents=True)
            (workspace / "big.bin").write_bytes(b"a" * 4096)
            executor = SandboxExecutor(
                workspace, broker, limits=replace(PolicyLimits(), max_read_bytes=1024)
            )
            action = ActionRequest("a", "read_text", "big.bin", {"max_chars": 5})
            token = broker.issue(proposal_id="p", actions=[action])
            result = executor.execute(action, token)
            self.assertTrue(result["ok"])
            self.assertEqual(result["bytes_read"], 1024)
            self.assertTrue(result["truncated"])

    @unittest.skipIf(os.name == "nt", "symlink creation needs elevated rights on Windows")
    def test_symlink_write_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir(parents=True)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (workspace / "link").symlink_to(outside, target_is_directory=True)
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("a", "write_text", "link/escaped.txt", {"content": "x"})
            token = broker.issue(proposal_id="p", actions=[action])
            with self.assertRaises(CapabilityError):
                executor.execute(action, token)
            self.assertFalse((outside / "escaped.txt").exists())

    @unittest.skipIf(os.name == "nt", "symlink creation needs elevated rights on Windows")
    def test_symlink_file_write_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir(parents=True)
            target = Path(tmp) / "target.txt"
            target.write_text("original", encoding="utf-8")
            (workspace / "alias.txt").symlink_to(target)
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("a", "write_text", "alias.txt", {"content": "overwritten", "overwrite": True})
            token = broker.issue(proposal_id="p", actions=[action])
            with self.assertRaises(Exception):
                executor.execute(action, token)
            self.assertEqual(target.read_text(encoding="utf-8"), "original")

    def test_overwrite_requires_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir(parents=True)
            (workspace / "existing.txt").write_text("original", encoding="utf-8")
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("a", "write_text", "existing.txt", {"content": "new"})
            token = broker.issue(proposal_id="p", actions=[action])
            with self.assertRaises(Exception) as ctx:
                executor.execute(action, token)
            self.assertEqual(getattr(ctx.exception, "code", ""), "OVERWRITE_NOT_DECLARED")
            self.assertEqual((workspace / "existing.txt").read_text(), "original")

    def test_pre_image_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir(parents=True)
            (workspace / "existing.txt").write_text("original", encoding="utf-8")
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest(
                "a", "write_text", "existing.txt", {"content": "new", "overwrite": True}
            )
            token = broker.issue(proposal_id="p", actions=[action])
            result = executor.execute(action, token)
            self.assertTrue(result["ok"])
            self.assertTrue(result["pre_image"]["existed"])
            self.assertEqual(result["pre_image"]["sha256"], sha256("original"))


class W14ExecutionIsolationTests(unittest.TestCase):
    def test_run_python_is_disabled_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            broker = CapabilityBroker(keyring=keys, key_id="capability")
            workspace = Path(tmp) / "ws"
            workspace.mkdir(parents=True)
            (workspace / "prog.py").write_text("print('hi')", encoding="utf-8")
            executor = SandboxExecutor(workspace, broker)
            action = ActionRequest("a", "run_python", "prog.py", {})
            token = broker.issue(proposal_id="p", actions=[action])
            with self.assertRaises(Exception) as ctx:
                executor.execute(action, token)
            self.assertEqual(getattr(ctx.exception, "code", ""), "PYTHON_EXECUTION_DISABLED")

    def test_run_python_is_human_gated_even_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = replace(Policy.dev(), human_required_tools=frozenset({"run_python"}))
            control = build_control(tmp, allow_python=True, policy=policy)
            evidence(control, "ev-1", "lineage-a")
            workspace = Path(tmp) / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            (workspace / "prog.py").write_text("print('hi')", encoding="utf-8")
            task = control.create_task("t", "worker", "run code")
            result = control.submit_proposal(
                task, proposal(proposal_id="run", tool="run_python", resources=("prog.py",), parameters={})
            )
            self.assertEqual(result.status, VerdictStatus.AWAITING_HUMAN)

    def test_container_backend_builds_hardened_command(self) -> None:
        from whyward.isolation import ContainerPolicy, build_container_command

        command = build_container_command(
            "/usr/bin/docker",
            ContainerPolicy(image="python:3.12-slim"),
            program_name="prog.py",
            args=[],
            workspace=Path("/tmp/ws"),
        )
        joined = " ".join(command)
        for flag in ("--network none", "--cap-drop ALL", "--read-only", "--pids-limit", "no-new-privileges", "--user"):
            self.assertIn(flag, joined)
        self.assertNotIn("--privileged", joined)
        self.assertIn("/tmp/ws:/work:rw", joined)

    def test_no_container_runtime_fails_closed(self) -> None:
        from whyward.errors import ConfigurationError as ConfigError
        from whyward.isolation import DockerSandboxBackend

        if DockerSandboxBackend.try_create() is not None:
            self.skipTest("container runtime is available in this environment")
        with self.assertRaises(ConfigError):
            DockerSandboxBackend(runtime="definitely-not-a-runtime")


class W15LifecycleTests(unittest.TestCase):
    def test_resubmitting_a_finished_task_returns_a_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            target = proposal()
            task = control.create_task("t", "worker", "goal")
            first = control.submit_proposal(task, target)
            self.assertTrue(first.allowed)
            second = control.submit_proposal(task, target)
            self.assertFalse(second.allowed)
            self.assertEqual(second.status, VerdictStatus.REJECTED_STATE)
            self.assertEqual(second.code, "TASK_TERMINAL")

    def test_illegal_transition_raises_typed_error_internally(self) -> None:
        from whyward.errors import StateError

        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            task = control.create_task("t", "worker", "goal")
            with self.assertRaises(StateError):
                control._transition(task, TaskState.COMPLETED)

    def test_evidence_warnings_never_break_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a", observed_fields=(), blind_spots=())
            result = control.submit_proposal(
                control.create_task("t", "worker", "goal"), proposal()
            )
            self.assertTrue(result.allowed)
            self.assertIn("OBSERVABILITY_PROFILE_INCOMPLETE", [finding.code for finding in result.findings])


if __name__ == "__main__":
    unittest.main()
