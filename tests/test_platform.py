"""Tests for observability, signing, logging and operator tooling."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from support import build_control, evidence, keyring, proposal


class MetricsTests(unittest.TestCase):
    def test_counters_gauges_histograms(self) -> None:
        from whyward.observability import Metrics

        metrics = Metrics()
        metrics.counter("gate_decisions", 2, labels={"verdict": "PASS_WITHIN_SCOPE"}, help_text="decisions")
        metrics.gauge("ledger_events", 5)
        metrics.observe("lookup_duration", 0.02, labels={"verdict": "PASS_WITHIN_SCOPE"})
        text = metrics.prometheus_text()
        self.assertIn("# TYPE whyward_gate_decisions_total counter", text)
        self.assertIn('whyward_gate_decisions_total{verdict="PASS_WITHIN_SCOPE"} 2', text)
        self.assertIn("# TYPE whyward_ledger_events gauge", text)
        self.assertIn("whyward_lookup_duration_seconds_bucket", text)
        self.assertIn('le="+Inf"', text)
        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["counters"]["gate_decisions{'verdict': 'PASS_WITHIN_SCOPE'}"], 2)

    def test_timer_records_observation(self) -> None:
        from whyward.observability import Metrics

        metrics = Metrics()
        with metrics.timer("work"):
            pass
        self.assertEqual(metrics.snapshot()["histograms"]["work{}"]["count"], 1)

    def test_label_escaping(self) -> None:
        from whyward.observability import Metrics

        metrics = Metrics()
        metrics.counter("x", 1, labels={"why": 'he said "hi"'})
        self.assertIn('why="he said \\"hi\\""', metrics.prometheus_text())


class StructuredLogTests(unittest.TestCase):
    def test_json_lines_with_trace(self) -> None:
        from whyward.observability import StructuredLogger

        buffer = io.StringIO()
        logger = StructuredLogger(stream=buffer)
        logger.info("event_a", task_id="t1", trace_id="f" * 32)
        logger.warning("event_b", detail="x")
        lines = [json.loads(line) for line in buffer.getvalue().strip().splitlines()]
        self.assertEqual(lines[0]["event"], "event_a")
        self.assertEqual(lines[0]["trace_id"], "f" * 32)
        self.assertEqual(lines[1]["level"], "warning")
        self.assertNotIn("trace_id", lines[1])

    def test_level_filter(self) -> None:
        from whyward.observability import StructuredLogger

        buffer = io.StringIO()
        logger = StructuredLogger(stream=buffer, level="error")
        logger.info("silent")
        logger.error("loud")
        self.assertNotIn("silent", buffer.getvalue())
        self.assertIn("loud", buffer.getvalue())


class TraceContextTests(unittest.TestCase):
    def test_parse_and_generate(self) -> None:
        from whyward.observability import format_traceparent, parse_traceparent, valid_trace_id

        trace_id = "1" * 32
        parsed_trace, parsed_span = parse_traceparent(f"00-{trace_id}-{'2' * 16}-01")
        self.assertEqual(parsed_trace, trace_id)
        self.assertEqual(parsed_span, "2" * 16)
        generated_trace, _generated_span = parse_traceparent("garbage")
        self.assertTrue(valid_trace_id(generated_trace))
        self.assertEqual(format_traceparent(trace_id, parsed_span), f"00-{trace_id}-{'2' * 16}-01")


class IdentityTests(unittest.TestCase):
    def test_weak_keys_are_rejected(self) -> None:
        from whyward.errors import ConfigurationError
        from whyward.identity import Keyring

        with self.assertRaises(ConfigurationError):
            Keyring({"a": "short"})

    def test_invalid_key_id_is_rejected(self) -> None:
        from whyward.errors import ConfigurationError
        from whyward.identity import Keyring

        with self.assertRaises(ConfigurationError):
            Keyring({"bad key id!": "x" * 40})

    def test_keyring_from_env(self) -> None:
        from whyward.identity import Keyring

        os.environ["WHYWARD_KEY_TEST__KEY"] = "y" * 40
        try:
            ring = Keyring.from_env()
            self.assertIn("test-key", ring.ids())
        finally:
            del os.environ["WHYWARD_KEY_TEST__KEY"]

    def test_signature_roundtrip_and_tamper(self) -> None:
        from whyward.identity import sign_payload, verify_signature

        key = b"k" * 40
        payload = {"a": 1, "b": [1, 2]}
        signature = sign_payload(key, payload)
        self.assertTrue(verify_signature(key, payload, signature))
        self.assertFalse(verify_signature(key, {"a": 2, "b": [1, 2]}, signature))

    def test_envelope_defaults_to_fail_closed(self) -> None:
        from whyward.errors import IntegrityError
        from whyward.identity import verify_envelope

        with self.assertRaises(IntegrityError):
            verify_envelope({"payload": {}}, keyring())

    def test_unknown_key_is_not_trusted(self) -> None:
        from whyward.errors import IntegrityError
        from whyward.identity import Keyring, sign_document, verify_envelope

        document = sign_document({"x": 1}, "not-configured", bytes.fromhex("ab" * 32))
        with self.assertRaises(IntegrityError) as ctx:
            verify_envelope(document, Keyring({"other": "z" * 40}))
        self.assertEqual(ctx.exception.code, "UNKNOWN_KEY_ID")

    def test_api_token_validation(self) -> None:
        from whyward.errors import ConfigurationError
        from whyward.identity import ApiTokenStore

        store = ApiTokenStore()
        with self.assertRaises(ConfigurationError):
            store.add("short", "subject", ["ask"])
        store.add("ww_" + "a" * 30, "subject", ["ask"])
        principal = store.authenticate("Bearer ww_" + "a" * 30)
        self.assertEqual(principal.subject, "subject")
        self.assertTrue(principal.has_scope("ask"))
        self.assertFalse(principal.has_scope("admin"))

    def test_admin_scope_implies_all(self) -> None:
        from whyward.identity import ApiPrincipal

        principal = ApiPrincipal(subject="root", scopes=frozenset({"admin"}))
        self.assertTrue(principal.has_scope("ask"))


class LedgerAnchorTests(unittest.TestCase):
    def test_anchor_detects_rewrite(self) -> None:
        from whyward.ledger import Ledger

        with tempfile.TemporaryDirectory() as tmp:
            keys = keyring()
            path = Path(tmp) / "ledger.jsonl"
            anchor = Path(tmp) / "anchor.json"
            ledger = Ledger(path, keyring=keys, signing_key_id="audit-ledger")
            ledger.append("E", "a", {"i": 1})
            ledger.append("E", "a", {"i": 2})
            ledger.anchor(anchor)
            # Rewrite the whole ledger (same length, attacker-controlled content).
            other = Ledger(Path(tmp) / "other.jsonl")
            other.append("E", "a", {"i": 99})
            other.append("E", "a", {"i": 100})
            path.write_text(Path(tmp, "other.jsonl").read_text(encoding="utf-8"), encoding="utf-8")
            valid, message = Ledger(path).verify_against_anchor(anchor)
            self.assertFalse(valid)
            self.assertIn("rewrite", message)

    def test_missing_anchor_reports_failure(self) -> None:
        from whyward.ledger import Ledger

        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "l.jsonl")
            valid, message = ledger.verify_against_anchor(Path(tmp) / "nope.json")
            self.assertFalse(valid)
            self.assertIn("missing", message)

    def test_actor_and_trace_are_typed(self) -> None:
        from whyward.ledger import Ledger

        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "l.jsonl")
            event = ledger.append("E", {"kind": "human", "subject": "auditor"}, {"x": 1}, trace_id="a" * 32)
            self.assertEqual(event["actor"]["subject"], "auditor")
            self.assertEqual(event["schema_version"], 2)
            self.assertEqual(ledger.event_count, 1)


class ControlPlaneObservabilityTests(unittest.TestCase):
    def test_metrics_record_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            evidence(control, "ev-1", "lineage-a")
            control.submit_proposal(control.create_task("t", "worker", "goal"), proposal())
            text = control.metrics.prometheus_text()
            self.assertIn('whyward_gate_decisions_total{verdict="PASS_WITHIN_SCOPE"} 1', text)
            control.answer_question("Valdivia 1960 magnitude?")
            self.assertIn("whyward_lookups_total", control.metrics.prometheus_text())

    def test_status_reports_wiring(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            status = control.status()
            self.assertTrue(status["evidence"]["registry_configured"])
            self.assertFalse(status["execution"]["python_enabled"])
            self.assertTrue(status["ledger"]["valid"])
            self.assertFalse(status["kill_switch_engaged"])

    def test_logger_gets_task_events(self) -> None:
        from whyward.observability import StructuredLogger

        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            control.logger = StructuredLogger(stream=buffer)
            evidence(control, "ev-1", "lineage-a")
            control.submit_proposal(control.create_task("t", "worker", "goal"), proposal())
        self.assertIn("task_completed", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
