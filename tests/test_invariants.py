"""Invariant tests: properties that must hold for *every* input, not just examples.

These are deliberately cheap, deterministic and dependency-free (no hypothesis
needed) so they can run on every commit.
"""

from __future__ import annotations

import random
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from support import approval, build_control, evidence, keyring, proposal

from whyward.capability import CapabilityBroker, InMemoryUsedTokenStore
from whyward.errors import CapabilityError
from whyward.ledger import Ledger
from whyward.models import ActionRequest, RiskTier, VerdictStatus


class GateInvariantTests(unittest.TestCase):
    def test_execution_never_happens_without_an_allowed_verdict(self) -> None:
        rng = random.Random(20261026)
        tools = ["write_text", "read_text", "run_python", "run_shell", "delete_tree"]
        resources = ["ok.txt", "policy/x.json", "../escape.txt", "/etc/passwd", "sub/dir/file.txt"]
        risks = list(RiskTier)
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            workspace = Path(tmp) / "workspace"
            for index in range(120):
                risk = rng.choice(risks)
                target = proposal(
                    proposal_id=f"p-{index}",
                    tool=rng.choice(tools),
                    resources=(rng.choice(resources),),
                    risk=risk,
                    evidence_ids=rng.choice([("ev-1",), ("ev-1", "ev-2"), ()]),
                    parameters={"content": "x", "expected_sha256": "0" * 64},
                )
                task = control.create_task(f"t-{index}", "worker", "invariant")
                decision = control.submit_proposal(task, target)
                if not decision.allowed:
                    for action in target.actions:
                        self.assertFalse(
                            (workspace / action.resource).exists()
                            and action.resource.startswith("ok"),
                            f"action executed despite verdict {decision.status}",
                        )
                else:
                    self.assertEqual(decision.status, VerdictStatus.PASS_WITHIN_SCOPE)
                    self.assertEqual(len(decision.execution_results), len(target.actions))

    def test_withheld_tasks_never_reach_execution_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            task = control.create_task("t", "worker", "goal")
            decision = control.submit_proposal(task, proposal(evidence_ids=()))
            self.assertEqual(decision.status, VerdictStatus.INSUFFICIENT_EVIDENCE)
            self.assertEqual(decision.task_state.value, "WITHHELD")
            self.assertEqual(task.state.value, "WITHHELD")

    def test_every_blocking_finding_maps_to_a_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            task = control.create_task("t", "worker", "goal")
            decision = control.submit_proposal(
                task, proposal(tool="run_shell", resources=("x.sh",), risk=RiskTier.MEDIUM)
            )
            blocking = [finding for finding in decision.findings if finding.blocking]
            self.assertTrue(blocking)
            self.assertEqual(len(decision.reasons), len(blocking))
            for finding, reason in zip(blocking, decision.reasons):
                self.assertIn(finding.message, reason)

    def test_decision_digest_is_stable_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            digests = []
            for tmp in (tmp_a, tmp_b):
                control = build_control(tmp)
                evidence(control, "ev-1", "lineage-a")
                target = proposal()
                control.submit_proposal(control.create_task("t", "w", "g"), target)
                digests.append(target.digest())
            self.assertEqual(digests[0], digests[1])


class LedgerInvariantTests(unittest.TestCase):
    def test_threaded_writers_keep_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "ledger.jsonl")

            def writer(worker_id: int) -> None:
                for index in range(50):
                    ledger.append("E", f"w{worker_id}", {"i": index})

            threads = [threading.Thread(target=writer, args=(worker_id,)) for worker_id in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            valid, message = ledger.verify()
            self.assertTrue(valid, message)
            indexes = [event["index"] for event in ledger.iter_events()]
            self.assertEqual(indexes, list(range(1, 301)))
            self.assertEqual(len({event["event_id"] for event in ledger.iter_events()}), 300)

    def test_every_event_hash_is_unique(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "ledger.jsonl")
            for _index in range(40):
                ledger.append("E", "w", {"same": "payload"})
            hashes = [event["event_hash"] for event in ledger.iter_events()]
            self.assertEqual(len(set(hashes)), len(hashes))


class CapabilityInvariantTests(unittest.TestCase):
    def test_one_use_per_action_even_under_concurrency(self) -> None:
        broker = CapabilityBroker(keyring(), key_id="capability", used_store=InMemoryUsedTokenStore())
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p", actions=[action])
        successes: list[int] = []
        failures: list[int] = []

        def attempt() -> None:
            try:
                broker.consume(token, action)
                successes.append(1)
            except CapabilityError:
                failures.append(1)

        threads = [threading.Thread(target=attempt) for _ in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 23)

    def test_any_action_mutation_breaks_scope(self) -> None:
        broker = CapabilityBroker(keyring(), key_id="capability")
        action = ActionRequest("a1", "write_text", "dir/a.txt", {"content": "x", "overwrite": False})
        token = broker.issue(proposal_id="p", actions=[action])
        mutations = [
            replace(action, resource="dir/b.txt"),
            replace(action, tool="read_text"),
            replace(action, parameters={"content": "y", "overwrite": False}),
            replace(action, parameters={"content": "x", "overwrite": True}),
            replace(action, action_id="a2"),
            replace(action, reversible=False),
        ]
        for mutated in mutations:
            with self.assertRaises(CapabilityError):
                broker.consume(token, mutated)

    def test_scope_never_widens_with_extra_actions(self) -> None:
        broker = CapabilityBroker(keyring(), key_id="capability")
        action = ActionRequest("a1", "write_text", "a.txt", {"content": "x"})
        token = broker.issue(proposal_id="p", actions=[action])
        with self.assertRaises(CapabilityError):
            broker.consume(token, ActionRequest("a2", "write_text", "b.txt", {"content": "x"}))


class ApprovalInvariantTests(unittest.TestCase):
    def test_any_proposal_edit_breaks_the_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            evidence(control, "ev-2", "lineage-b")
            target = proposal(risk=RiskTier.HIGH, autonomy=4, evidence_ids=("ev-1", "ev-2"))
            task = control.create_task("t", "worker", "goal")
            decision = approval(control, task.task_id, target)
            edits = [
                replace(target, actions=(ActionRequest("a-0", "write_text", "other.txt", {"content": "x"}),)),
                replace(target, risk_tier=RiskTier.CRITICAL),
                replace(target, rollback_plan=""),
                replace(target, requested_autonomy=5),
            ]
            for edited in edits:
                edited_task = control.create_task("t-edit", "worker", "goal")
                result = control.submit_proposal(edited_task, edited, human_decision=decision)
                self.assertFalse(result.allowed, "edited proposal reused an old approval")


if __name__ == "__main__":
    unittest.main()
