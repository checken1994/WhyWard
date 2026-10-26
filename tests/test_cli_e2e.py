"""End-to-end CLI contract tests.

These run the real command line in a subprocess because exit codes, stdout JSON
and stderr are part of the product contract (scripts depend on them). Exit codes:
0 ok, 1 failure, 2 integrity, 3 withheld, 4 configuration, 5 unavailable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "examples" / "catalog"
DEV_POLICY = ROOT / "examples" / "policy.dev.json"
DEMO_KEYS = ROOT / "examples" / "keys" / "demo.keyring.json"
PRODUCTION_POLICY = ROOT / "examples" / "policy.production.json"


def run_cli(*argv: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    base = {
        "PYTHONPATH": str(ROOT / "src"),
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    if env:
        base.update(env)
    return subprocess.run(
        [sys.executable, "-m", "whyward", *argv],
        capture_output=True,
        text=True,
        env=base,
        timeout=180,
        check=False,
    )


class OperatorJourneyTests(unittest.TestCase):
    def test_full_journey(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "demo"
            demo = run_cli("demo", "--workdir", str(work), "--catalog", str(CATALOG))
            self.assertEqual(demo.returncode, 0, demo.stderr)
            ledger = work / "ledger.jsonl"
            self.assertTrue(ledger.exists())

            verify = run_cli(
                "verify-ledger", str(ledger), "--keyring", str(DEMO_KEYS), "--require-signature"
            )
            self.assertEqual(verify.returncode, 0)
            self.assertTrue(json.loads(verify.stdout)["valid"])

            anchor = work / "anchor.json"
            self.assertEqual(
                run_cli("checkpoint", str(ledger), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS)).returncode,
                0,
            )
            anchored = run_cli("verify-ledger", str(ledger), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS))
            self.assertEqual(anchored.returncode, 0, anchored.stdout)

            report = run_cli("report", str(ledger), "--keyring", str(DEMO_KEYS), "--limit", "10")
            self.assertEqual(report.returncode, 0, report.stderr)
            payload = json.loads(report.stdout)
            self.assertGreater(payload["ledger"]["events"], 0)

            status = run_cli("status", "--catalog", str(CATALOG), "--profile", "dev")
            self.assertEqual(status.returncode, 0)
            self.assertIn("policy", json.loads(status.stdout))

    def test_demo_is_deterministic_in_its_verdicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outputs = []
            for index in range(2):
                result = run_cli("demo", "--workdir", str(Path(tmp) / f"run{index}"), "--catalog", str(CATALOG))
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                outputs.append(payload["lookup_demo"]["verdict"])
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0], "PASS_WITHIN_SCOPE")


class WithheldExitCodeTests(unittest.TestCase):
    def ask(self, question: str, tmp: str) -> subprocess.CompletedProcess[str]:
        return run_cli(
            "ask",
            question,
            "--catalog",
            str(CATALOG),
            "--policy",
            str(DEV_POLICY),
            "--keyring",
            str(DEMO_KEYS),
            "--ledger",
            str(Path(tmp) / "ledger.jsonl"),
            "--state-dir",
            str(Path(tmp) / "state"),
        )

    def test_answer_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.ask("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["verdict"], "PASS_WITHIN_SCOPE")
            self.assertIn("9.5", payload["answer"])
            self.assertEqual(payload["evidence"]["source_id"], "usgs")

    def test_withheld_exits_three(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.ask("Động đất năm 2004 tại California có độ lớn bao nhiêu?", tmp)
            self.assertEqual(result.returncode, 3, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["verdict"], "INSUFFICIENT_EVIDENCE")
            self.assertIsNone(payload["answer"])

    def test_kill_switch_exits_five(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kill = Path(tmp) / "STOP"
            kill.write_text("stopped\n", encoding="utf-8")
            result = run_cli(
                "ask",
                "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
                "--catalog",
                str(CATALOG),
                "--policy",
                str(DEV_POLICY),
                "--keyring",
                str(DEMO_KEYS),
                "--ledger",
                str(Path(tmp) / "ledger.jsonl"),
                "--state-dir",
                str(Path(tmp) / "state"),
                "--kill-switch-file",
                str(kill),
            )
            self.assertEqual(result.returncode, 5, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["verdict"], "BLOCKED_BY_POLICY")

    def test_unsigned_policy_in_production_exits_four(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            unsigned = Path(tmp) / "policy.json"
            payload = json.loads(DEV_POLICY.read_text(encoding="utf-8"))["policy"]
            unsigned.write_text(json.dumps(payload), encoding="utf-8")
            result = run_cli(
                "ask",
                "q",
                "--catalog",
                str(CATALOG),
                "--policy",
                str(unsigned),
                "--require-signed-policy",
                "--keyring",
                str(DEMO_KEYS),
            )
            self.assertEqual(result.returncode, 4)
            self.assertEqual(json.loads(result.stdout)["error"], "POLICY_UNSIGNED")


class IntegrityExitCodeTests(unittest.TestCase):
    def test_tampered_ledger_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "demo"
            self.assertEqual(run_cli("demo", "--workdir", str(work), "--catalog", str(CATALOG)).returncode, 0)
            ledger = work / "ledger.jsonl"
            lines = ledger.read_text(encoding="utf-8").splitlines()
            event = json.loads(lines[2])
            event["payload"]["verdict"] = "PASS_WITHIN_SCOPE"
            lines[2] = json.dumps(event)
            ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = run_cli("verify-ledger", str(ledger), "--keyring", str(DEMO_KEYS))
            self.assertEqual(result.returncode, 2)
            self.assertFalse(json.loads(result.stdout)["valid"])

    def test_truncation_against_anchor_exits_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "demo"
            self.assertEqual(run_cli("demo", "--workdir", str(work), "--catalog", str(CATALOG)).returncode, 0)
            ledger = work / "ledger.jsonl"
            anchor = work / "anchor.json"
            run_cli("checkpoint", str(ledger), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS))
            kept = ledger.read_text(encoding="utf-8").splitlines()[:2]
            ledger.write_text("\n".join(kept) + "\n", encoding="utf-8")
            result = run_cli("verify-ledger", str(ledger), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS))
            self.assertEqual(result.returncode, 2)
            self.assertIn("truncation", result.stdout)

    def test_corrupt_catalog_exits_two(self) -> None:
        import shutil

        with tempfile.TemporaryDirectory() as tmp:
            catalog = Path(tmp) / "catalog"
            shutil.copytree(CATALOG, catalog)
            shard = sorted((catalog / "facts").glob("*.jsonl"))[0]
            shard.write_text(shard.read_text(encoding="utf-8").replace("1960", "1999", 1), encoding="utf-8")
            result = run_cli(
                "ask", "q", "--catalog", str(catalog), "--policy", str(DEV_POLICY), "--keyring", str(DEMO_KEYS)
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("CATALOG_CHECKSUM_MISMATCH", result.stdout)


class KeyManagementTests(unittest.TestCase):
    def test_keygen_and_sign_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            generated = run_cli("keygen", "--out", str(keys), "--key-id", "policy-signing")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            if os.name == "posix":
                self.assertEqual(oct(keys.stat().st_mode & 0o777), "0o600")

            policy = Path(tmp) / "policy.json"
            payload = json.loads(DEV_POLICY.read_text(encoding="utf-8"))["policy"]
            payload["profile"] = "production"
            payload["allowed_tools"] = ["read_text", "write_text"]
            payload["human_required_tools"] = ["run_python"]
            policy.write_text(json.dumps({"policy": payload}), encoding="utf-8")

            signed = run_cli(
                "sign",
                str(policy),
                "--key-id",
                "policy-signing",
                "--keyring",
                str(keys),
                "--root-key",
                "policy",
            )
            self.assertEqual(signed.returncode, 0, signed.stderr)
            verified = run_cli(
                "doctor", "--policy", str(policy), "--keyring", str(keys), "--catalog", str(CATALOG)
            )
            self.assertEqual(verified.returncode, 0)

    def test_keygen_refuses_to_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keys = Path(tmp) / "keys.json"
            self.assertEqual(run_cli("keygen", "--out", str(keys)).returncode, 0)
            second = run_cli("keygen", "--out", str(keys))
            self.assertEqual(second.returncode, 4)

    def test_token_command_writes_hashed_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "tokens.json"
            result = run_cli(
                "token", "--subject", "ci", "--scope", "ask", "--scope", "read", "--token-store", str(store)
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            token = json.loads(result.stdout)["token"]
            self.assertTrue(token.startswith("ww_"))
            stored = json.loads(store.read_text(encoding="utf-8"))
            self.assertNotIn(token, store.read_text(encoding="utf-8"))
            self.assertEqual(stored["tokens"][0]["subject"], "ci")
            if os.name == "posix":
                self.assertEqual(store.stat().st_mode & 0o777, 0o600)

    def test_serve_without_token_store_exits_four(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_cli(
                "serve",
                "--catalog",
                str(CATALOG),
                "--port",
                "0",
                "--ledger",
                str(Path(tmp) / "ledger.jsonl"),
                "--state-dir",
                str(Path(tmp) / "state"),
            )
            self.assertEqual(result.returncode, 4)
            self.assertIn("NO_API_TOKENS", result.stdout + result.stderr)


class DoctorTests(unittest.TestCase):
    def test_doctor_reports_checks(self) -> None:
        result = run_cli("doctor", "--profile", "dev", "--catalog", str(CATALOG), "--keyring", str(DEMO_KEYS))
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["checks"]["policy"]["profile"], "dev")
        self.assertTrue(payload["checks"]["catalog"]["ok"])

    def test_doctor_fails_on_bad_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_cli("doctor", "--profile", "dev", "--catalog", tmp)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads(result.stdout)["ok"])

    def test_production_policy_is_signed(self) -> None:
        result = run_cli(
            "doctor",
            "--policy",
            str(PRODUCTION_POLICY),
            "--keyring",
            str(DEMO_KEYS),
            "--catalog",
            str(CATALOG),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["checks"]["policy"]["profile"], "production")


if __name__ == "__main__":
    unittest.main()
