"""End-to-end CLI tests: the operator journey, exercised as a real process."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from support import CATALOG

SRC = Path(__file__).resolve().parents[1] / "src"


def run_cli(*args: str, cwd: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    environment = {**os.environ, "PYTHONPATH": str(SRC)}
    environment.update(env or {})
    return subprocess.run(
        [sys.executable, "-m", "whyward.cli", *args],
        env=environment,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


class OperatorJourneyTests(unittest.TestCase):
    def test_full_journey(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            str(Path(tmp) / "state")
            ledger = str(Path(tmp) / "ledger.jsonl")

            keygen = run_cli("keygen", "--output", str(Path(tmp) / "keys.json"))
            self.assertEqual(keygen.returncode, 0, keygen.stderr)
            keys = json.loads(keygen.stdout)
            self.assertIn("capability", keys["key_ids"])

            keyring_path = str(Path(tmp) / "keys.json")
            policy_source = Path(__file__).resolve().parents[1] / "examples" / "policy.production.json"
            sign = run_cli(
                "sign",
                str(policy_source),
                "--key-id",
                "policy-signing",
                "--keyring",
                keyring_path,
                "--root-key",
                "policy",
            )
            self.assertEqual(sign.returncode, 0, sign.stderr)

            demo = run_cli(
                "demo",
                "--workdir",
                str(Path(tmp) / "demo"),
                "--catalog",
                str(CATALOG),
                "--keyring",
                keyring_path,
            )
            self.assertEqual(demo.returncode, 0, demo.stderr)
            payload = json.loads(demo.stdout)
            self.assertEqual(payload["gate"]["status"], "PASS_WITHIN_SCOPE")
            self.assertTrue(payload["ledger_verify"][0])
            self.assertEqual(payload["lookup_demo"]["verdict"], "PASS_WITHIN_SCOPE")

            anchor_path = str(Path(tmp) / "anchor.json")
            checkpoint = run_cli(
                "checkpoint", ledger, "--anchor", anchor_path, "--keyring", keyring_path
            )
            self.assertEqual(checkpoint.returncode, 0, checkpoint.stderr)

            verify = run_cli(
                "verify-ledger", ledger, "--anchor", anchor_path, "--keyring", keyring_path
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            report = json.loads(verify.stdout)
            self.assertTrue(report["valid"])
            self.assertTrue(report["anchor"]["valid"])

            summary = run_cli(
                "report",
                str(Path(tmp) / "demo" / "ledger.jsonl"),
                "--limit",
                "5",
                "--keyring",
                keyring_path,
            )
            self.assertEqual(summary.returncode, 0, summary.stderr)
            body = json.loads(summary.stdout)
            self.assertIn("TASK_COMPLETED_WITHIN_SCOPE", body["event_counts"])
            self.assertTrue(any(item["event_type"] == "TASK_COMPLETED_WITHIN_SCOPE" for item in body["decisions"]))

    def test_verify_detects_anchor_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            str(Path(tmp) / "ledger.jsonl")
            anchor = str(Path(tmp) / "anchor.json")
            run_cli("demo", "--workdir", str(Path(tmp) / "demo"), "--catalog", str(CATALOG))
            demo_ledger = str(Path(tmp) / "demo" / "ledger.jsonl")
            demo_keys = str(Path(__file__).resolve().parents[1] / "examples" / "keys" / "demo.keyring.json")
            self.assertEqual(
                run_cli("checkpoint", demo_ledger, "--anchor", anchor, "--keyring", demo_keys).returncode, 0
            )
            lines = Path(demo_ledger).read_text(encoding="utf-8").splitlines()
            Path(demo_ledger).write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            verify = run_cli("verify-ledger", demo_ledger, "--anchor", anchor, "--keyring", demo_keys)
            self.assertEqual(verify.returncode, 2)
            body = json.loads(verify.stdout)
            self.assertFalse(body["anchor"]["valid"])
            self.assertIn("truncation", body["anchor"]["message"])

    def test_ask_against_signed_policy_and_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(__file__).resolve().parents[1]
            proc = run_cli(
                "ask",
                "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
                "--catalog",
                str(CATALOG),
                "--policy",
                str(root / "examples" / "policy.dev.json"),
                "--keyring",
                str(root / "examples" / "keys" / "demo.keyring.json"),
                "--require-signed-policy",
                "--ledger",
                str(Path(tmp) / "l.jsonl"),
                "--state-dir",
                tmp,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "PASS_WITHIN_SCOPE")

    def test_unsigned_policy_is_rejected_when_signature_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            from whyward.policy import Policy

            policy_path.write_text(json.dumps(Policy.production_example()), encoding="utf-8")
            proc = run_cli(
                "ask",
                "x",
                "--catalog",
                str(CATALOG),
                "--policy",
                str(policy_path),
                "--keyring",
                str(Path(__file__).resolve().parents[1] / "examples" / "keys" / "demo.keyring.json"),
                "--require-signed-policy",
                "--state-dir",
                tmp,
                "--ledger",
                str(Path(tmp) / "l.jsonl"),
            )
            self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
            self.assertIn("POLICY_UNSIGNED", proc.stdout)

    def test_serve_refuses_to_start_without_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_cli(
                "serve",
                "--port",
                "0",
                "--profile",
                "dev",
                "--ledger",
                str(Path(tmp) / "l.jsonl"),
                "--state-dir",
                tmp,
            )
            self.assertEqual(proc.returncode, 4)
            self.assertIn("NO_API_TOKENS", proc.stdout)


class ServeWithAuthTests(unittest.TestCase):
    def test_authenticated_server_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            token = "ww_" + "t" * 40
            token_file = Path(tmp) / "tokens.json"
            token_file.write_text(
                json.dumps([{"token": token, "subject": "e2e", "scopes": ["ask", "audit"]}]), encoding="utf-8"
            )
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            env = {**os.environ, "PYTHONPATH": str(SRC)}
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "whyward.cli",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--token-file",
                    str(token_file),
                    "--profile",
                    "dev",
                    "--catalog",
                    str(CATALOG),
                    "--ledger",
                    str(Path(tmp) / "l.jsonl"),
                    "--state-dir",
                    tmp,
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.time() + 20
                ready = False
                while time.time() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.1)
                self.assertTrue(ready, "server did not start")

                anonymous = urllib.request.Request(
                    f"http://127.0.0.1:{port}/ask",
                    data=json.dumps({"question": "x"}).encode(),
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(anonymous, timeout=5)
                self.assertEqual(ctx.exception.code, 401)

                authorized = urllib.request.Request(
                    f"http://127.0.0.1:{port}/ask",
                    data=json.dumps({"question": "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?"}).encode(),
                    method="POST",
                )
                authorized.add_header("Authorization", f"Bearer {token}")
                with urllib.request.urlopen(authorized, timeout=10) as response:
                    body = json.loads(response.read().decode())
                self.assertEqual(body["verdict"], "PASS_WITHIN_SCOPE")

                verify = urllib.request.Request(f"http://127.0.0.1:{port}/ledger/verify")
                verify.add_header("Authorization", f"Bearer {token}")
                with urllib.request.urlopen(verify, timeout=5) as response:
                    self.assertTrue(json.loads(response.read().decode())["valid"])
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    process.kill()


if __name__ == "__main__":
    unittest.main()
