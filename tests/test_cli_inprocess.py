"""In-process CLI tests (fast, and they cover cli.py itself).

Subprocess/netserver tests live in test_cli_e2e.py; these call ``main()`` so the
argparse wiring, exit-code mapping and error handling are measured directly.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from support import CATALOG

from whyward import cli
from whyward.policy import Policy


def invoke(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(args))
    except SystemExit as exc:  # --version / --help
        code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class CliCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ledger = str(self.tmp / "ledger.jsonl")
        self.keyring = str(Path(__file__).resolve().parents[1] / "examples" / "keys" / "demo.keyring.json")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_version_and_no_command(self) -> None:
        code, out, _ = invoke("--version")
        self.assertEqual(code, 0)
        self.assertIn("WhyWard", out)
        code, out, _ = invoke()
        self.assertEqual(code, 0)
        self.assertIn("usage", out)

    def test_help(self) -> None:
        code, out, _ = invoke("--help")
        self.assertEqual(code, 0)
        self.assertIn("serve", out)

    def test_keygen_and_sign(self) -> None:
        output = str(self.tmp / "keys.json")
        code, out, _ = invoke("keygen", "--output", output)
        self.assertEqual(code, 0)
        self.assertTrue(Path(output).exists())
        if os.name == "posix":
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        code, out, _ = invoke("keygen", "--output", output)
        self.assertEqual(code, 4)  # refuses to overwrite
        policy_path = self.tmp / "policy.json"
        policy_path.write_text(json.dumps(Policy.production_example()), encoding="utf-8")
        code, out, _ = invoke(
            "sign", str(policy_path), "--key-id", "policy-signing", "--keyring", output, "--root-key", "policy"
        )
        self.assertEqual(code, 0, out)
        signed = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertIn("signature", signed)
        self.assertEqual(signed["signature"]["key_id"], "policy-signing")

    def test_ask_success_and_withheld(self) -> None:
        code, out, _ = invoke(
            "ask",
            "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
            "--catalog",
            str(CATALOG),
            "--profile",
            "dev",
            "--ledger",
            self.ledger,
            "--state-dir",
            str(self.tmp),
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["verdict"], "PASS_WITHIN_SCOPE")
        code, out, _ = invoke(
            "ask",
            "Động đất năm 2004 tại California có độ lớn bao nhiêu?",
            "--catalog",
            str(CATALOG),
            "--profile",
            "dev",
            "--ledger",
            str(self.tmp / "l2.jsonl"),
            "--state-dir",
            str(self.tmp / "s2"),
        )
        self.assertEqual(code, 3)

    def test_demo(self) -> None:
        code, out, _ = invoke(
            "demo", "--workdir", str(self.tmp / "demo"), "--catalog", str(CATALOG)
        )
        self.assertEqual(code, 0, out)
        payload = json.loads(out)
        self.assertTrue(payload["gate"]["allowed"])
        self.assertEqual(payload["lookup_demo"]["verdict"], "PASS_WITHIN_SCOPE")

    def test_status_and_doctor(self) -> None:
        code, out, _ = invoke(
            "status", "--profile", "dev", "--ledger", self.ledger, "--state-dir", str(self.tmp)
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["policy"]["profile"], "dev")
        code, out, _ = invoke(
            "doctor",
            "--profile",
            "dev",
            "--catalog",
            str(CATALOG),
            "--ledger",
            self.ledger,
            "--state-dir",
            str(self.tmp),
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["checks"]["catalog"]["ok"])

    def test_doctor_reports_failures(self) -> None:
        code, out, _ = invoke(
            "doctor",
            "--profile",
            "production",
            "--catalog",
            str(self.tmp / "missing"),
            "--state-dir",
            str(self.tmp),
        )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])

    def test_report(self) -> None:
        invoke("demo", "--workdir", str(self.tmp / "demo"), "--catalog", str(CATALOG))
        code, out, _ = invoke(
            "report", str(self.tmp / "demo" / "ledger.jsonl"), "--limit", "3", "--keyring", self.keyring
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn("TASK_COMPLETED_WITHIN_SCOPE", payload["event_counts"])

    def test_report_on_missing_ledger(self) -> None:
        code, out, _ = invoke("report", str(self.tmp / "nope.jsonl"), "--keyring", self.keyring)
        self.assertEqual(code, 0)  # empty ledger is valid
        self.assertEqual(json.loads(out)["ledger"]["events"], 0)

    def test_checkpoint_and_verify(self) -> None:
        invoke("demo", "--workdir", str(self.tmp / "demo"), "--catalog", str(CATALOG))
        ledger = str(self.tmp / "demo" / "ledger.jsonl")
        anchor = str(self.tmp / "anchor.json")
        code, out, _ = invoke("checkpoint", ledger, "--anchor", anchor, "--keyring", self.keyring)
        self.assertEqual(code, 0, out)
        code, out, _ = invoke("verify-ledger", ledger, "--anchor", anchor, "--keyring", self.keyring)
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["valid"])

    def test_verify_rejects_unsigned_when_required(self) -> None:
        from whyward.ledger import Ledger

        unsigned = self.tmp / "unsigned.jsonl"
        writer = Ledger(unsigned)
        writer.append("E", "test", {"x": 1})
        code, out, _ = invoke("verify-ledger", str(unsigned), "--require-signature")
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out)["valid"])

    def test_verify_detects_tampering(self) -> None:
        invoke("demo", "--workdir", str(self.tmp / "demo"), "--catalog", str(CATALOG))
        ledger = self.tmp / "demo" / "ledger.jsonl"
        ledger.write_text(
            ledger.read_text(encoding="utf-8").replace("TASK_RECEIVED", "TASK_TAMPERED"), encoding="utf-8"
        )
        code, out, _ = invoke("verify-ledger", str(ledger), "--keyring", self.keyring)
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out)["valid"])

    def test_token_command(self) -> None:
        code, out, _ = invoke("token", "--subject", "ci", "--scope", "ask")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["token"].startswith("ww_"))

    def test_unknown_keystore_is_a_configuration_error(self) -> None:
        code, out, _ = invoke(
            "status",
            "--profile",
            "production",
            "--policy",
            str(self.tmp / "missing.json"),
            "--ledger",
            self.ledger,
            "--state-dir",
            str(self.tmp),
        )
        self.assertEqual(code, 4)
        self.assertIn("error", json.loads(out))

    def test_kill_switch_via_cli_flag(self) -> None:
        stop = self.tmp / "STOP"
        stop.write_text("stop", encoding="utf-8")
        code, out, _ = invoke(
            "ask",
            "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
            "--catalog",
            str(CATALOG),
            "--profile",
            "dev",
            "--kill-switch-file",
            str(stop),
            "--ledger",
            self.ledger,
            "--state-dir",
            str(self.tmp),
        )
        self.assertEqual(code, 5)
        self.assertEqual(json.loads(out)["verdict"], "BLOCKED_BY_POLICY")


class BuildControlTests(unittest.TestCase):
    def test_production_profile_requires_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = invoke(
                "status", "--profile", "production", "--ledger", f"{tmp}/l.jsonl", "--state-dir", tmp
            )
            self.assertEqual(code, 4)
            self.assertIn("NO_SIGNING_KEYS", out)

    def test_dev_profile_uses_demo_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _out, _ = invoke("status", "--profile", "dev", "--ledger", f"{tmp}/l.jsonl", "--state-dir", tmp)
            self.assertEqual(code, 0)

    def test_env_secret_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["WHYWARD_CAPABILITY_SECRET"] = "z" * 40
            try:
                code, out, _ = invoke(
                    "status", "--profile", "production", "--ledger", f"{tmp}/l.jsonl", "--state-dir", tmp
                )
            finally:
                del os.environ["WHYWARD_CAPABILITY_SECRET"]
            self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
