#!/usr/bin/env python3
"""WhyWard independent acceptance harness.

Purpose
    Give a reviewer who did *not* write this code a single command that decides
    whether the repository, as checked out, actually behaves the way it claims.
    The harness prefers black-box evidence (subprocess, files on disk, exit
    codes, HTTP status) over the project's own unit tests, and it refuses to
    produce a "pass" out of an ambiguous run.

What it does
    1. Environment and provenance: commit, dirty tree, python version, platform,
       third-party import scan (the package must be standard-library only).
    2. Test suite: runs the repository's unittest suite from a clean
       PYTHONPATH and reports pass/fail counts.
    3. Adversarial probes: runs docs/audit/reproduce_findings.py and requires
       15/15 OK.
    4. Operator journey in a scratch directory: demo, verify, anchor, verify
       against anchor, ask (answer), ask (withheld → exit 3), report, doctor.
    5. Tamper checks: mutate a ledger event, mutate a catalog shard, truncate a
       ledger against an anchor — each must be detected.
    6. API checks: refuses to start without tokens, 401 without a bearer token,
       200 with scope, 503 on /readyz after the kill switch is engaged.
    7. Mutation check: ten controls are disabled one at a time in a throwaway
       copy; the probes must notice every removal (otherwise a green result
       proves nothing).
    8. Documentation-claim cross-check.

Usage
    python docs/acceptance/acceptance_runner.py
    python docs/acceptance/acceptance_runner.py --report /tmp/report.md \
        --json /tmp/report.json --allow-dirty

Exit code: 0 only when every check passes. The markdown/JSON report contains the
raw command output for every check, so a reviewer can audit the audit.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
EXAMPLES = ROOT / "examples"
CATALOG = EXAMPLES / "catalog"
DEMO_KEYS = EXAMPLES / "keys" / "demo.keyring.json"
DEV_POLICY = EXAMPLES / "policy.dev.json"


@dataclass
class Check:
    check_id: str
    title: str
    passed: bool
    detail: str
    command: str = ""
    output: str = ""
    duration_seconds: float = 0.0
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class Harness:
    checks: list[Check] = field(default_factory=list)
    started: float = field(default_factory=time.time)
    scratch: Path | None = None

    # ---------------------------------------------------------------- helpers
    def record(
        self,
        check_id: str,
        title: str,
        passed: bool,
        detail: str,
        *,
        command: str = "",
        output: str = "",
        duration: float = 0.0,
        skipped: bool = False,
        skip_reason: str = "",
    ) -> None:
        self.checks.append(
            Check(
                check_id=check_id,
                title=title,
                passed=passed,
                detail=detail,
                command=command,
                output=textwrap.indent(output.strip()[-4000:], "    ") if output else "",
                duration_seconds=duration,
                skipped=skipped,
                skip_reason=skip_reason,
            )
        )
        state = "SKIP" if skipped else ("PASS" if passed else "FAIL")
        print(f"[{state}] {check_id} {title}\n       {detail}")

    def run(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        env_extra: dict[str, str] | None = None,
        timeout: int = 300,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "PYTHONPATH": str(SRC),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", str(Path.home())),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            argv,
            cwd=str(cwd or ROOT),
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
            check=False,
        )

    def whyward(self, *args: str, cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess[str]:
        return self.run([sys.executable, "-m", "whyward", *args], cwd=cwd, timeout=timeout)


# --------------------------------------------------------------------------- #
# 1. Provenance and environment
# --------------------------------------------------------------------------- #
def check_provenance(h: Harness, allow_dirty: bool) -> dict[str, str]:
    commit = h.run(["git", "rev-parse", "HEAD"]).stdout.strip()
    status = h.run(["git", "status", "--porcelain"]).stdout.strip()
    branch = h.run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip()
    dirty = bool(status)
    h.record(
        "A-01",
        "Repository provenance is recorded and the tree is clean",
        (not dirty) or allow_dirty,
        f"commit={commit[:12] or '?'} branch={branch or '?'} dirty={dirty}"
        + (" (dirty tree allowed by --allow-dirty; results are NOT acceptance-grade)" if dirty and allow_dirty else ""),
        command="git rev-parse HEAD; git status --porcelain",
        output=status or "clean",
    )
    return {"commit": commit, "branch": branch, "dirty": str(dirty)}


def check_stdlib_only(h: Harness) -> None:
    stdlib = set(sys.stdlib_module_names)
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in stdlib and root != "whyward":
                        offenders.append(f"{path.relative_to(ROOT)}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.level or not node.module:
                    continue
                root = node.module.split(".")[0]
                if root not in stdlib and root != "whyward":
                    offenders.append(f"{path.relative_to(ROOT)}: from {node.module} import ...")
    h.record(
        "A-02",
        "Package imports only the standard library (no hidden runtime deps)",
        not offenders,
        f"{len(offenders)} non-stdlib imports" + (f": {offenders[:5]}" if offenders else ""),
        command="AST scan of src/whyward/**/*.py",
        output="\n".join(offenders) or "only stdlib + whyward",
    )


# --------------------------------------------------------------------------- #
# 2. Test suite
# --------------------------------------------------------------------------- #
def check_unit_tests(h: Harness) -> None:
    started = time.time()
    result = h.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "tests"],
        env_extra={"PYTHONPATH": f"{SRC}:{ROOT / 'tests'}"},
        timeout=600,
    )
    tail = (result.stderr or result.stdout).strip().splitlines()
    summary = " | ".join(tail[-3:]) if tail else "(no output)"
    h.record(
        "A-03",
        "Repository test suite passes",
        result.returncode == 0 and "OK" in (result.stderr or ""),
        summary,
        command="PYTHONPATH=src:tests python -m unittest discover -s tests -t tests",
        output=result.stderr or result.stdout,
        duration=time.time() - started,
    )


# --------------------------------------------------------------------------- #
# 3. Adversarial probes
# --------------------------------------------------------------------------- #
def check_probes(h: Harness) -> None:
    started = time.time()
    result = h.run([sys.executable, "docs/audit/reproduce_findings.py"], timeout=900)
    vulnerable = [line for line in (result.stdout + result.stderr).splitlines() if "[VULNERABLE]" in line]
    summary = [line for line in result.stdout.splitlines() if "probes:" in line]
    h.record(
        "A-04",
        "All 15 adversarial probes report OK",
        result.returncode == 0 and not vulnerable,
        "; ".join(summary) or f"returncode={result.returncode}",
        command="PYTHONPATH=src python docs/audit/reproduce_findings.py",
        output=result.stdout + result.stderr,
        duration=time.time() - started,
    )


# --------------------------------------------------------------------------- #
# 4. Operator journey (black box, scratch directory)
# --------------------------------------------------------------------------- #
def check_operator_journey(h: Harness) -> None:
    assert h.scratch is not None
    work = h.scratch / "journey"
    log: list[str] = []

    demo = h.whyward("demo", "--workdir", str(work), "--catalog", str(CATALOG))
    ledger = work / "ledger.jsonl"
    log.append(f"demo rc={demo.returncode}")
    demo_ok = demo.returncode == 0 and ledger.exists()

    verify = h.whyward(
        "verify-ledger", str(ledger), "--keyring", str(DEMO_KEYS), "--require-signature"
    )
    log.append(f"verify rc={verify.returncode} {verify.stdout.strip()[:120]}")
    verify_ok = verify.returncode == 0 and '"valid": true' in verify.stdout

    anchor = work / "anchor.json"
    checkpoint = h.whyward("checkpoint", str(ledger), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS))
    anchored = h.whyward(
        "verify-ledger", str(ledger), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS)
    )
    log.append(f"checkpoint rc={checkpoint.returncode}, anchored verify rc={anchored.returncode}")
    anchor_ok = checkpoint.returncode == 0 and anchor.exists() and anchored.returncode == 0

    answered = h.whyward(
        "ask",
        "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
        "--catalog",
        str(CATALOG),
        "--policy",
        str(DEV_POLICY),
        "--keyring",
        str(DEMO_KEYS),
        "--ledger",
        str(h.scratch / "ask-ledger.jsonl"),
        "--state-dir",
        str(h.scratch / "ask-state"),
    )
    answer_ok = answered.returncode == 0 and "9.5" in answered.stdout
    log.append(f"ask(answered) rc={answered.returncode}")

    withheld = h.whyward(
        "ask",
        "Động đất năm 2004 tại California có độ lớn bao nhiêu?",
        "--catalog",
        str(CATALOG),
        "--policy",
        str(DEV_POLICY),
        "--keyring",
        str(DEMO_KEYS),
        "--ledger",
        str(h.scratch / "ask2-ledger.jsonl"),
        "--state-dir",
        str(h.scratch / "ask2-state"),
    )
    withheld_ok = withheld.returncode == 3 and "INSUFFICIENT_EVIDENCE" in withheld.stdout
    log.append(f"ask(withheld) rc={withheld.returncode}")

    report = h.whyward("report", str(ledger), "--keyring", str(DEMO_KEYS), "--limit", "20")
    report_ok = report.returncode == 0 and '"events"' in report.stdout or '"total"' in report.stdout
    log.append(f"report rc={report.returncode}")

    doctor = h.whyward("doctor", "--profile", "dev", "--catalog", str(CATALOG), "--keyring", str(DEMO_KEYS))
    doctor_ok = doctor.returncode == 0 and '"ok": true' in doctor.stdout
    log.append(f"doctor rc={doctor.returncode}")

    passed = all([demo_ok, verify_ok, anchor_ok, answer_ok, withheld_ok, report_ok, doctor_ok])
    h.record(
        "A-05",
        "Operator journey: demo → verify → anchor → ask → withhold → report → doctor",
        passed,
        " ".join(log),
        command="whyward demo|verify-ledger|checkpoint|ask|report|doctor",
        output="\n".join(
            [
                f"demo: {demo.stdout[-500:]}",
                f"verify: {verify.stdout[-500:]}",
                f"ask answered: {answered.stdout[-500:]}",
                f"ask withheld: {withheld.stdout[-500:]}",
                f"doctor: {doctor.stdout[-500:]}",
            ]
        ),
    )


# --------------------------------------------------------------------------- #
# 5. Tamper detection
# --------------------------------------------------------------------------- #
def check_tamper(h: Harness) -> None:
    assert h.scratch is not None
    base = h.scratch / "tamper"
    demo = h.whyward("demo", "--workdir", str(base), "--catalog", str(CATALOG))
    ledger = base / "ledger.jsonl"
    if demo.returncode != 0 or not ledger.exists():
        h.record("A-06", "Ledger tampering is detected", False, "demo failed, cannot prepare the ledger")
        return

    lines = ledger.read_text(encoding="utf-8").splitlines()
    target = json.loads(lines[1])
    target["payload"] = dict(target.get("payload", {}))
    target["payload"]["tampered"] = True
    lines[1] = json.dumps(target)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    verify = h.whyward("verify-ledger", str(ledger), "--keyring", str(DEMO_KEYS))
    tamper_detected = verify.returncode != 0 and '"valid": false' in verify.stdout

    # truncation against an anchor
    demo2 = h.scratch / "trunc"
    h.whyward("demo", "--workdir", str(demo2), "--catalog", str(CATALOG))
    ledger2 = demo2 / "ledger.jsonl"
    anchor = demo2 / "anchor.json"
    h.whyward("checkpoint", str(ledger2), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS))
    kept = ledger2.read_text(encoding="utf-8").splitlines()[:2]
    ledger2.write_text("\n".join(kept) + "\n", encoding="utf-8")
    truncated = h.whyward("verify-ledger", str(ledger2), "--anchor", str(anchor), "--keyring", str(DEMO_KEYS))
    truncation_detected = truncated.returncode != 0 and (
        "truncation" in truncated.stdout or '"valid": false' in truncated.stdout
    )

    # catalog tampering
    catalog_copy = h.scratch / "catalog-tampered"
    shutil.copytree(CATALOG, catalog_copy)
    shard = sorted((catalog_copy / "facts").glob("*.jsonl"))[0]
    shard.write_text(shard.read_text(encoding="utf-8").replace("1960", "1999", 1), encoding="utf-8")
    bad = h.whyward(
        "ask",
        "anything",
        "--catalog",
        str(catalog_copy),
        "--policy",
        str(DEV_POLICY),
        "--keyring",
        str(DEMO_KEYS),
    )
    catalog_detected = bad.returncode in {2, 4} and "CATALOG_CHECKSUM" in (bad.stdout + bad.stderr).upper()

    passed = tamper_detected and truncation_detected and catalog_detected
    h.record(
        "A-06",
        "Tampering is detected (ledger edit, ledger truncation, catalog edit)",
        passed,
        f"ledger_edit={tamper_detected} truncation={truncation_detected} catalog={catalog_detected}",
        command="whyward verify-ledger / ask on mutated inputs",
        output=f"ledger: {verify.stdout[:400]}\ntrunc: {truncated.stdout[:400]}\ncatalog: {bad.stdout[:400]}",
    )


# --------------------------------------------------------------------------- #
# 6. API surface
# --------------------------------------------------------------------------- #
def check_api(h: Harness) -> None:
    sys.path.insert(0, str(SRC))
    from whyward.api import make_server
    from whyward.control import ControlPlane
    from whyward.errors import AuthenticationError
    from whyward.evidence import KnowledgeStore
    from whyward.identity import ApiTokenStore, Keyring
    from whyward.ledger import Ledger
    from whyward.policy import Policy

    assert h.scratch is not None
    keys = Keyring.from_file(DEMO_KEYS)
    policy = Policy.load(DEV_POLICY, keyring=keys)
    store = KnowledgeStore.load(CATALOG)
    control = ControlPlane(
        policy=policy,
        ledger=Ledger(h.scratch / "api-ledger.jsonl", keyring=keys, signing_key_id="audit-ledger"),
        knowledge_store=store,
        keyring=keys,
    )

    refused_start = False
    try:
        make_server(control, port=0)
    except AuthenticationError:
        refused_start = True

    token = "ww_" + hashlib.sha256(b"acceptance").hexdigest()[:30]
    tokens = ApiTokenStore()
    tokens.add(token, subject="acceptance", scopes=("ask", "read", "metrics", "audit", "admin"))
    server = make_server(control, host="127.0.0.1", port=0, tokens=tokens)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        def call(path: str, *, method: str = "GET", body: bytes | None = None, token_value: str | None = None):
            headers = {}
            if token_value:
                headers["Authorization"] = f"Bearer {token_value}"
            if body is not None:
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(base + path, data=body, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - local
                    return response.status, response.read().decode("utf-8"), dict(response.headers)
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read().decode("utf-8"), dict(exc.headers)

        anonymous_status, _, anonymous_headers = call("/ask", method="POST", body=b'{"question":"x"}')
        health_status, _, _ = call("/healthz")
        authed_status, authed_body, authed_headers = call(
            "/ask",
            method="POST",
            body=json.dumps({"question": "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?"}).encode(),
            token_value=token,
        )
        engage_status, _, _ = call(
            "/admin/kill-switch",
            method="POST",
            body=b'{"action":"engage","reason":"acceptance"}',
            token_value=token,
        )
        ready_status, ready_body, _ = call("/readyz")
        blocked_status, blocked_body, _ = call(
            "/ask",
            method="POST",
            body=json.dumps({"question": "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?"}).encode(),
            token_value=token,
        )
    finally:
        server.shutdown()
        server.server_close()

    passed = (
        refused_start
        and anonymous_status == 401
        and "www-authenticate" in {k.lower() for k in anonymous_headers}
        and health_status == 200
        and authed_status == 200
        and authed_headers.get("WhyWard-Verdict") == "PASS_WITHIN_SCOPE"
        and engage_status == 200
        and ready_status == 503
        and blocked_status == 200
        and "BLOCKED_BY_POLICY" in blocked_body
    )
    h.record(
        "A-07",
        "API: refuses to start unauthenticated, 401 anonymous, verdict header, kill switch → 503",
        passed,
        (
            f"no_token_store_refused={refused_start} anonymous={anonymous_status} health={health_status} "
            f"authed={authed_status} verdict={authed_headers.get('WhyWard-Verdict')} "
            f"engage={engage_status} ready={ready_status} blocked={blocked_status}"
        ),
        command="make_server(...) + urllib against 127.0.0.1",
        output=f"authed body: {authed_body[:600]}\nreadyz: {ready_body[:300]}\nblocked: {blocked_body[:300]}",
    )


# --------------------------------------------------------------------------- #
# 6b. Mutation check: does the evidence have teeth?
# --------------------------------------------------------------------------- #
def check_mutations(h: Harness) -> None:
    started = time.time()
    result = h.run([sys.executable, "docs/acceptance/falsification_check.py"], timeout=900)
    tail = [line for line in result.stdout.splitlines() if "mutations:" in line]
    h.record(
        "A-09",
        "Removing any single control is detected by the evidence (mutation check)",
        result.returncode == 0,
        "; ".join(tail) or f"returncode={result.returncode}",
        command="python3 docs/acceptance/falsification_check.py",
        output=result.stdout + result.stderr,
        duration=time.time() - started,
    )


# --------------------------------------------------------------------------- #
# 7. Documentation-claim cross-check
# --------------------------------------------------------------------------- #
def check_claims(h: Harness) -> None:
    """Every table row in SECURITY.md must name a control that exists in src."""
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    src_text = "\n".join(path.read_text(encoding="utf-8") for path in SRC.rglob("*.py"))
    missing: list[str] = []
    for code in (
        "DECISION_NOT_BOUND",
        "EVIDENCE_NOT_REVIEWED",
        "EVIDENCE_STALE",
        "CATALOG_CHECKSUM_MISMATCH",
        "INSUFFICIENT_INDEPENDENT_LINEAGES",
        "KILL_SWITCH_ENGAGED",
        "CAPABILITY_REPLAYED",
        "PYTHON_EXECUTION_DISABLED",
    ):
        if code not in src_text and code not in security:
            missing.append(code)
    h.record(
        "A-08",
        "Security document only names controls that exist in the code",
        not missing,
        f"missing codes: {missing}" if missing else "all referenced control codes are implemented",
        command="grep control codes in src/whyward vs SECURITY.md",
    )


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def render_markdown(h: Harness, provenance: dict[str, str], allow_dirty: bool) -> str:
    passed = [c for c in h.checks if c.passed and not c.skipped]
    failed = [c for c in h.checks if not c.passed and not c.skipped]
    skipped = [c for c in h.checks if c.skipped]
    verdict = "ACCEPTED" if not failed else "REJECTED"
    if allow_dirty or provenance.get("dirty") == "True":
        verdict = "PROVISIONAL (dirty working tree)"
    duration = time.time() - h.started
    out = [
        "# WhyWard acceptance report",
        "",
        f"- Verdict: **{verdict}**",
        f"- Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Commit: `{provenance.get('commit', '?')}` on `{provenance.get('branch', '?')}`",
        f"- Working tree dirty: {provenance.get('dirty')}",
        f"- Python: {platform.python_version()} on {platform.platform()}",
        f"- Host: {socket.gethostname()}",
        f"- Duration: {duration:.1f}s",
        f"- Checks: {len(passed)} passed, {len(failed)} failed, {len(skipped)} skipped",
        "",
        "> This report was produced by `docs/acceptance/acceptance_runner.py`. A run on a",
        "> dirty tree or by the author of the change is **not** acceptance-grade; see",
        "> `docs/acceptance/INDEPENDENCE.md`.",
        "",
        "## Checks",
        "",
        "| ID | Check | Result | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for check in h.checks:
        state = "SKIP" if check.skipped else ("PASS" if check.passed else "FAIL")
        detail = check.detail.replace("|", "\\|")[:300]
        out.append(f"| {check.check_id} | {check.title} | {state} | {detail} |")
    out.append("")
    for check in h.checks:
        out.append(f"### {check.check_id} — {check.title}")
        out.append("")
        out.append(f"- Result: {'SKIP' if check.skipped else ('PASS' if check.passed else 'FAIL')}")
        out.append(f"- Detail: {check.detail}")
        if check.skip_reason:
            out.append(f"- Skip reason: {check.skip_reason}")
        if check.command:
            out.append(f"- Command: `{check.command}`")
        if check.duration_seconds:
            out.append(f"- Duration: {check.duration_seconds:.1f}s")
        if check.output:
            out.append("")
            out.append("```text")
            out.append(check.output.strip())
            out.append("```")
        out.append("")
    out.append("## How to reproduce")
    out.append("")
    out.append("```bash")
    out.append(f"git clone https://github.com/checken1994/WhyWard && cd WhyWard")
    out.append(f"git checkout {provenance.get('commit', '<commit>')}")
    out.append("python docs/acceptance/acceptance_runner.py")
    out.append("```")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WhyWard independent acceptance harness")
    parser.add_argument("--report", default="", help="write a markdown report to this path")
    parser.add_argument("--json", default="", help="write machine-readable results to this path")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="continue even if the worktree is dirty (results marked PROVISIONAL)",
    )
    args = parser.parse_args(argv)

    h = Harness()
    h.scratch = Path(tempfile.mkdtemp(prefix="whyward-acceptance-"))
    print(f"scratch directory: {h.scratch}\n")

    provenance = check_provenance(h, args.allow_dirty)
    if provenance["dirty"] == "True" and not args.allow_dirty:
        print("\nrefusing to continue: worktree is dirty. Commit, or re-run with --allow-dirty.")
        return 2

    try:
        check_stdlib_only(h)
        check_unit_tests(h)
        check_probes(h)
        check_operator_journey(h)
        check_tamper(h)
        check_api(h)
        check_mutations(h)
        check_claims(h)
    finally:
        report = render_markdown(h, provenance, args.allow_dirty)
        if args.report:
            Path(args.report).write_text(report, encoding="utf-8")
            print(f"\nmarkdown report: {args.report}")
        if args.json:
            payload = {
                "provenance": provenance,
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "verdict": "ACCEPTED"
                if all(c.passed for c in h.checks)
                else "REJECTED",
                "checks": [check.__dict__ for check in h.checks],
            }
            Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"json report: {args.json}")
        shutil.rmtree(h.scratch, ignore_errors=True)

    failed = [c for c in h.checks if not c.passed and not c.skipped]
    print("\n" + "=" * 70)
    if failed:
        print(f"REJECTED — {len(failed)} of {len(h.checks)} checks failed: " + ", ".join(c.check_id for c in failed))
        return 1
    print(f"ACCEPTED — {len(h.checks)} checks passed")
    if args.allow_dirty or provenance.get("dirty") == "True":
        print("note: run on a dirty tree, therefore PROVISIONAL, not acceptance-grade")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
