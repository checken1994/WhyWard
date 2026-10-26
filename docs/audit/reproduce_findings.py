#!/usr/bin/env python3
"""WhyWard security probes W-01 … W-15 (re-audit harness).

Every probe corresponds 1:1 to a finding in
``docs/audit/2026-10-26-danh-gia-he-thong.md``. The harness is written as an
*adversary*: for each finding it performs the unsafe action the old code
allowed and records what happened.

Verdicts
    [OK]          the system refused / degraded exactly as the fix intends.
    [VULNERABLE]  the unsafe behaviour is still reachable.
    [SKIP]        cannot be exercised on this platform (reported, never hidden).

Usage
    PYTHONPATH=src python3 docs/audit/reproduce_findings.py
    PYTHONPATH=src python3 docs/audit/reproduce_findings.py --only W-02,W-14
    PYTHONPATH=src python3 docs/audit/reproduce_findings.py --json out.json

Exit code is 0 only when no probe reports VULNERABLE. Everything runs inside a
temporary directory; no network is required and the repository is never
modified. These are defensive regression probes for this project's own code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
CATALOG = ROOT / "examples" / "catalog"
DEMO_KEYS = ROOT / "examples" / "keys" / "demo.keyring.json"

RESULTS: list[dict[str, str]] = []


def record(pid: str, title: str, verdict: str, detail: str) -> None:
    RESULTS.append({"id": pid, "title": title, "verdict": verdict, "detail": detail})
    print(f"[{verdict:<10}] {pid} {title}\n             {detail}\n")


def fresh_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="whyward-probe-"))


# --------------------------------------------------------------------------- #
# Shared fixtures
# --------------------------------------------------------------------------- #
def dev_control(
    tmp: Path,
    *,
    with_executor: bool = False,
    with_python: bool = False,
    policy: Any = None,
    catalog: Path | None = None,
):
    from whyward.capability import CapabilityBroker
    from whyward.control import ControlPlane
    from whyward.evidence import KnowledgeStore
    from whyward.execution import SandboxExecutor
    from whyward.identity import Keyring
    from whyward.ledger import Ledger
    from whyward.policy import Policy

    from whyward.registry import EvidenceRegistry

    keys = Keyring.from_file(DEMO_KEYS)
    policy = policy or Policy.dev()
    store = KnowledgeStore.load(catalog or CATALOG)
    registry = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest", path=tmp / "evidence.jsonl")
    ledger = Ledger(tmp / "ledger.jsonl", keyring=keys, signing_key_id="audit-ledger")
    broker = None
    executor = None
    if with_executor:
        broker = CapabilityBroker(keys, key_id="capability", used_store=_sqlite_store(tmp))
        executor = SandboxExecutor(tmp / "ws", broker, allow_python=with_python, limits=policy.limits)
        broker.set_blocked_hook(lambda: False)
        executor.set_blocked_hook(lambda: False)
    control = ControlPlane(
        policy=policy,
        ledger=ledger,
        capability_broker=broker,
        executor=executor,
        knowledge_store=store,
        evidence_registry=registry,
        keyring=keys,
        approval_keyring=keys,
        require_signed_approval=policy.review.require_human_decision_signature,
    )
    return control, keys


def _sqlite_store(tmp: Path):
    from whyward.capability import SqliteUsedTokenStore

    return SqliteUsedTokenStore(tmp / "capability.sqlite")


def register_trusted(control, *, evidence_id: str = "ev-1", lineage: str = "lineage-a", **extra):
    from whyward.models import now_iso

    payload = {
        "evidence_id": evidence_id,
        "source_id": "usgs",
        "lineage_id": lineage,
        "retrieved_at": now_iso(),
        "observed_fields": ("magnitude",),
        "blind_spots": ("no independent refetch",),
        "review_status": "verified",
    }
    payload.update(extra)
    control.register_reviewed_evidence(**payload)


def make_proposal(
    pid: str = "p-1",
    *,
    resource: str = "result.txt",
    risk: Any = None,
    evidence_ids: tuple[str, ...] = ("ev-1",),
    tool: str = "write_text",
    parameters: dict[str, Any] | None = None,
    autonomy: int = 0,
):
    from whyward.models import ActionRequest, Claim, Proposal, RiskTier

    return Proposal(
        proposal_id=pid,
        title="Probe proposal",
        summary="Write one file inside the sandbox.",
        rationale="Probe the boundary.",
        claims=(Claim(claim_id="c-1", statement="Scoped action.", evidence_ids=evidence_ids),),
        actions=(
            ActionRequest(
                action_id="a-1",
                tool=tool,
                resource=resource,
                parameters=parameters or {"content": "probe"},
            ),
        ),
        alternatives=("do nothing",),
        consequences_if_done=("one file appears",),
        consequences_if_not_done=("nothing changes",),
        unknowns=("probe unknown",),
        rollback_plan="delete the file",
        requested_autonomy=autonomy,
        risk_tier=risk or RiskTier.LOW,
    )


def approved(control, task_id: str, proposal, *, approver: str = "auditor"):
    """Build a fully-bound, signed HumanDecision the way an approval UI must."""
    from whyward.models import HumanDecision

    package = control.approval_package(proposal, (), task_id=task_id)
    decision = HumanDecision(
        decision_id=f"d-{task_id}",
        approver=approver,
        approved=True,
        proposal_digest=proposal.digest(),
        task_id=task_id,
        package_digest=package.package_digest,
        restatement="I approve writing exactly this file inside the probe sandbox.",
        reason="probe",
        comprehension={"action": True, "consequence": True, "rollback": True},
        expires_at=package.expires_at,
        nonce=f"nonce-{task_id}",
    )
    key = control.approval_keyring.get(control.approval_key_id)
    return control.sign_decision(decision, key_id=control.approval_key_id, key=key)


def run_cli(*argv: str) -> subprocess.CompletedProcess[str]:
    env = {"PYTHONPATH": str(SRC), "PATH": "/usr/local/bin:/usr/bin:/bin"}
    return subprocess.run(
        [sys.executable, "-m", "whyward", *argv],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


# --------------------------------------------------------------------------- #
# W-01  Approval replay: one decision, two proposals
# --------------------------------------------------------------------------- #
def probe_w01() -> None:
    title = "Human approval không bị ràng buộc với proposal (replay được)"
    tmp = fresh_dir()
    control, _ = dev_control(tmp, with_executor=True)
    register_trusted(control, evidence_id="ev-1", lineage="lineage-a")

    from whyward.models import RiskTier

    register_trusted(control, evidence_id="ev-2", lineage="lineage-b")
    safe = make_proposal("p-safe", resource="safe.txt", risk=RiskTier.HIGH, evidence_ids=("ev-1", "ev-2"))
    task = control.create_task("t-safe", "worker", "write safe.txt")
    decision = approved(control, task.task_id, safe)
    first = control.submit_proposal(task, safe, human_decision=decision)

    other = make_proposal(
        "p-other",
        resource="secret.txt",
        parameters={"content": "pwned"},
        risk=RiskTier.HIGH,
        evidence_ids=("ev-1", "ev-2"),
    )
    other_task = control.create_task("t-other", "worker", "something else entirely")
    second = control.submit_proposal(other_task, other, human_decision=decision)
    wrote = (tmp / "ws" / "secret.txt").exists()

    if second.allowed or wrote:
        record("W-01", title, "VULNERABLE", f"replay accepted: {second.status.value}")
    else:
        record(
            "W-01",
            title,
            "OK",
            f"first={first.status.value}, replay={second.status.value}; blocking: {second.reasons[:2]}",
        )


# --------------------------------------------------------------------------- #
# W-02  Self-declared review_status
# --------------------------------------------------------------------------- #
def probe_w02() -> None:
    from whyward.models import EvidenceRef

    title = "Bằng chứng tự khai 'verified' được hệ thống tin"
    tmp = fresh_dir()
    control, _ = dev_control(tmp)
    control.register_evidence(
        EvidenceRef(
            evidence_id="forged-1",
            source_id="usgs",
            lineage_id="attacker-lineage",
            observed_fields=("x",),
            blind_spots=("y",),
            review_status="verified",
        )
    )
    stored = control.evidence_registry.get("forged-1")
    proposal = make_proposal("p-forged", evidence_ids=("forged-1",))
    decision = control.submit_proposal(control.create_task("t", "worker", "probe"), proposal)

    if stored.review_status == "verified" and decision.allowed:
        record("W-02", title, "VULNERABLE", "caller-asserted review_status was honoured")
    else:
        record(
            "W-02",
            title,
            "OK",
            f"stored status={stored.review_status!r} (registry re-signed, downgraded); verdict={decision.status.value}",
        )


# --------------------------------------------------------------------------- #
# W-03  Expired evidence is still answered
# --------------------------------------------------------------------------- #
def probe_w03() -> None:
    from datetime import UTC, datetime

    from whyward.evidence import KnowledgeStore

    title = "freshness/valid_until không được thi hành"
    tmp = fresh_dir()
    catalog = tmp / "catalog"
    shutil.copytree(CATALOG, catalog)
    shard = catalog / "facts" / "geology.earthquakes.jsonl"
    lines = shard.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["freshness"] = {
        "class": "volatile",
        "valid_from": "1990-01-01",
        "valid_until": "1991-01-01",
        "review_after": "1991-01-01",
    }
    lines[0] = json.dumps(first, ensure_ascii=False)
    shard.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["shards"]:
        path = catalog / entry["path"] if "path" in entry else catalog / entry["file"]
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (catalog / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    store = KnowledgeStore.load(catalog)
    result = store.answer_query(
        "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
        accepted_review_statuses={"verified", "demo_verified"},
        now=datetime(2026, 10, 26, tzinfo=UTC),
    )
    if result.status == "FOUND":
        record("W-03", title, "VULNERABLE", f"expired record still answered: {result.value!r}")
    else:
        record("W-03", title, "OK", f"status={result.status}, reasons={result.reasons}")


# --------------------------------------------------------------------------- #
# W-04  Manifest checksum / record_count not enforced
# --------------------------------------------------------------------------- #
def probe_w04() -> None:
    from whyward.evidence import KnowledgeStore
    from whyward.errors import WhyWardError

    title = "manifest record_count/sha256 không được thi hành"
    tmp = fresh_dir()
    catalog = tmp / "catalog"
    shutil.copytree(CATALOG, catalog)
    shard = catalog / "facts" / "geology.earthquakes.jsonl"
    original = shard.read_text(encoding="utf-8")
    shard.write_text(original.replace("1960", "1999", 1), encoding="utf-8")
    tamper_blocked = False
    detail = ""
    try:
        KnowledgeStore.load(catalog)
    except WhyWardError as exc:
        tamper_blocked = True
        detail = f"checksum mismatch -> {exc.code}"

    shard.write_text(original, encoding="utf-8")
    manifest = json.loads((catalog / "manifest.json").read_text(encoding="utf-8"))
    manifest["shards"][0]["record_count"] = 99
    (catalog / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    count_blocked = False
    try:
        KnowledgeStore.load(catalog)
    except WhyWardError as exc:
        count_blocked = True
        detail += f"; record_count mismatch -> {exc.code}"

    if tamper_blocked and count_blocked:
        record("W-04", title, "OK", detail)
    else:
        record("W-04", title, "VULNERABLE", detail or "tampered catalog loaded")


# --------------------------------------------------------------------------- #
# W-05  High risk with a single evidence lineage
# --------------------------------------------------------------------------- #
def probe_w05() -> None:
    from whyward.models import RiskTier

    title = "min_independent_lineages không được thi hành"
    tmp = fresh_dir()
    control, _ = dev_control(tmp, with_executor=True)
    register_trusted(control, evidence_id="ev-1", lineage="lineage-a")
    proposal = make_proposal("p-high", risk=RiskTier.HIGH, evidence_ids=("ev-1",), autonomy=4)
    task = control.create_task("t", "worker", "probe")
    decision = control.submit_proposal(task, proposal, human_decision=approved(control, task.task_id, proposal))
    codes = [finding.code for finding in decision.findings]

    if decision.allowed:
        record("W-05", title, "VULNERABLE", f"single lineage accepted for HIGH risk ({codes})")
    else:
        record("W-05", title, "OK", f"blocked: {codes or decision.reasons[:2]}")


# --------------------------------------------------------------------------- #
# W-06  Concurrent appends corrupt the ledger
# --------------------------------------------------------------------------- #
def probe_w06() -> None:
    from whyward.ledger import Ledger

    title = "Ghi ledger đồng thời làm hỏng chuỗi hash"
    tmp = fresh_dir()
    path = tmp / "ledger.jsonl"
    ledger = Ledger(path)
    threads = [threading.Thread(target=ledger.append, args=("PROBE", f"actor-{i}", {"i": i})) for i in range(24)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    valid, message = Ledger(path).verify()
    events = list(Ledger(path).iter_events())
    if valid and len(events) == 24:
        record("W-06", title, "OK", f"24/24 concurrent appends, chain valid ({message})")
    else:
        record("W-06", title, "VULNERABLE", f"valid={valid}, events={len(events)}, reason={message}")


# --------------------------------------------------------------------------- #
# W-07  Capability token survives a restart
# --------------------------------------------------------------------------- #
def probe_w07() -> None:
    from whyward.capability import CapabilityBroker

    title = "Capability token dùng lại được sau khi khởi động lại"
    tmp = fresh_dir()
    keys_path = DEMO_KEYS
    from whyward.identity import Keyring

    keys = Keyring.from_file(keys_path)
    action = make_proposal().actions[0]
    first = CapabilityBroker(keys, key_id="capability", used_store=_sqlite_store(tmp))
    token = first.issue(proposal_id="p-1", actions=[action])
    first.consume(token, action)

    second = CapabilityBroker(keys, key_id="capability", used_store=_sqlite_store(tmp))
    try:
        second.consume(token, action)
    except Exception as exc:  # noqa: BLE001 - the rejection type is what we probe
        record("W-07", title, "OK", f"replay after restart rejected: {getattr(exc, 'code', type(exc).__name__)}")
        return
    record("W-07", title, "VULNERABLE", "token replay after restart was accepted")


# --------------------------------------------------------------------------- #
# W-08  Kill switch does not revoke execution
# --------------------------------------------------------------------------- #
def probe_w08() -> None:
    title = "Kill switch không thu hồi quyền thực thi/cấp token"
    tmp = fresh_dir()
    control, _ = dev_control(tmp, with_executor=True)
    register_trusted(control, evidence_id="ev-1", lineage="lineage-a")
    control.capability_broker.set_blocked_hook(control.kill_switch_engaged)
    control.executor.set_blocked_hook(control.kill_switch_engaged)

    control.engage_kill_switch("probe")
    action = make_proposal().actions[0]
    refused_issue = False
    try:
        control.capability_broker.issue(proposal_id="p-1", actions=[action])
    except Exception:  # noqa: BLE001 - probe
        refused_issue = True
    decision = control.submit_proposal(control.create_task("t", "worker", "probe"), make_proposal())
    wrote = (tmp / "ws" / "result.txt").exists()

    if refused_issue and not wrote and not decision.allowed:
        record("W-08", title, "OK", f"issue refused, execution refused ({decision.status.value})")
    else:
        record(
            "W-08",
            title,
            "VULNERABLE",
            f"issued={not refused_issue}, wrote={wrote}, verdict={decision.status.value}",
        )


# --------------------------------------------------------------------------- #
# W-09  verify-ledger crashes with a traceback on a corrupt file
# --------------------------------------------------------------------------- #
def probe_w09() -> None:
    title = "verify-ledger ném traceback thay vì mã lỗi có kiểm soát"
    tmp = fresh_dir()
    path = tmp / "ledger.jsonl"
    path.write_text('{"event_hash": "deadbeef"}\nnot json at all\n', encoding="utf-8")
    result = run_cli("verify-ledger", str(path))
    if "Traceback" in result.stderr:
        record("W-09", title, "VULNERABLE", "traceback leaked to stderr")
    elif result.returncode == 2:
        record("W-09", title, "OK", f"exit=2 controlled failure: {result.stderr.strip()[:160]}")
    else:
        record("W-09", title, "VULNERABLE", f"unexpected exit={result.returncode}: {result.stderr.strip()[:160]}")


# --------------------------------------------------------------------------- #
# W-10  Withheld answers exit 0
# --------------------------------------------------------------------------- #
def probe_w10() -> None:
    title = "'ask' trả exit 0 khi câu trả lời bị giữ lại"
    tmp = fresh_dir()
    control, keys = dev_control(tmp)
    keyring_path = tmp / "keys.json"
    keyring_path.write_text(DEMO_KEYS.read_text(encoding="utf-8"), encoding="utf-8")
    result = run_cli(
        "ask",
        "Câu hỏi hoàn toàn không có trong catalog?",
        "--ledger",
        str(tmp / "ledger.jsonl"),
        "--state-dir",
        str(tmp / "state"),
        "--policy",
        str(ROOT / "examples" / "policy.dev.json"),
        "--keyring",
        str(keyring_path),
        "--catalog",
        str(CATALOG),
    )
    if result.returncode == 3:
        record("W-10", title, "OK", "exit=3 (WITHHELD) for an unanswerable question")
    else:
        record("W-10", title, "VULNERABLE", f"exit={result.returncode}: {result.stdout.strip()[:160]}")


# --------------------------------------------------------------------------- #
# W-11  demo_verified evidence accepted by the production profile
# --------------------------------------------------------------------------- #
def probe_w11() -> None:
    from whyward.policy import Policy
    from whyward.review import has_blockers, review_proposal
    from whyward.registry import EvidenceRegistry
    from whyward.identity import Keyring

    title = "demo_verified được chấp nhận trong profile production"
    tmp = fresh_dir()
    keys = Keyring.from_file(DEMO_KEYS)
    registry = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest")
    registry.register(
        {
            "evidence_id": "ev-demo",
            "source_id": "usgs",
            "lineage_id": "lineage-a",
            "retrieved_at": "2026-10-26T00:00:00Z",
            "observed_fields": ["x"],
            "blind_spots": ["y"],
            "review_status": "demo_verified",
        }
    )
    proposal = make_proposal("p-demo", evidence_ids=("ev-demo",))
    findings = review_proposal(proposal, registry, Policy.default())
    codes = [finding.code for finding in findings]
    if has_blockers(findings):
        record("W-11", title, "OK", f"production review blocks it: {codes}")
    else:
        record("W-11", title, "VULNERABLE", "demo_verified passed production review")


# --------------------------------------------------------------------------- #
# W-12  API answers without authentication
# --------------------------------------------------------------------------- #
def probe_w12() -> None:
    from whyward.api import make_server
    from whyward.errors import AuthenticationError

    title = "API trả lời không cần xác thực"
    tmp = fresh_dir()
    control, _ = dev_control(tmp)
    unauthenticated_blocked = False
    try:
        make_server(control, port=0)
    except AuthenticationError as exc:
        unauthenticated_blocked = exc.code == "NO_API_TOKENS"

    from whyward.identity import ApiTokenStore

    server = make_server(control, host="127.0.0.1", port=0, tokens=ApiTokenStore())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/ask", data=b"{}", method="POST")
        try:
            urllib.request.urlopen(request, timeout=10)  # noqa: S310 - local probe
            status = 200
        except urllib.error.HTTPError as exc:
            status = exc.code
    finally:
        server.shutdown()
        server.server_close()

    if unauthenticated_blocked and status == 401:
        record("W-12", title, "OK", "server refuses to start without tokens; unauthenticated /ask -> 401")
    else:
        record("W-12", title, "VULNERABLE", f"no_token_store_blocked={unauthenticated_blocked}, /ask status={status}")


# --------------------------------------------------------------------------- #
# W-13  Unbounded reads / writes
# --------------------------------------------------------------------------- #
def probe_w13() -> None:
    from whyward.capability import CapabilityBroker
    from whyward.execution import SandboxExecutor
    from whyward.identity import Keyring
    from whyward.policy import PolicyLimits

    title = "Đọc/ghi không có giới hạn kích thước"
    tmp = fresh_dir()
    keys = Keyring.from_file(DEMO_KEYS)
    broker = CapabilityBroker(keys, key_id="capability")
    limits = PolicyLimits(max_read_bytes=1024, max_write_bytes=1024)
    executor = SandboxExecutor(tmp / "ws", broker, limits=limits)
    workspace = tmp / "ws"
    (workspace / "big.txt").write_bytes(b"a" * 200_000)

    read_action = make_proposal("p-read", tool="read_text", resource="big.txt").actions[0]
    read_result = executor.execute(read_action, broker.issue(proposal_id="p-read", actions=[read_action]))

    write_action = make_proposal(
        "p-write", resource="huge.txt", parameters={"content": "b" * 200_000}
    ).actions[0]
    write_blocked = False
    try:
        executor.execute(write_action, broker.issue(proposal_id="p-write", actions=[write_action]))
    except Exception as exc:  # noqa: BLE001 - probe
        write_blocked = getattr(exc, "code", "") == "WRITE_TOO_LARGE"
    exists = (workspace / "huge.txt").exists()

    if read_result["truncated"] and write_blocked and not exists:
        record("W-13", title, "OK", "read truncated at the cap; oversized write refused before touching disk")
    else:
        record(
            "W-13",
            title,
            "VULNERABLE",
            f"truncated={read_result['truncated']}, write_blocked={write_blocked}, file_written={exists}",
        )


# --------------------------------------------------------------------------- #
# W-14  run_python reaches the host interpreter by default
# --------------------------------------------------------------------------- #
def probe_w14() -> None:
    from whyward.capability import CapabilityBroker
    from whyward.execution import SandboxExecutor
    from whyward.identity import Keyring
    from whyward.policy import Policy
    from whyward.review import has_blockers, review_proposal
    from whyward.registry import EvidenceRegistry

    title = "run_python chạy trên host interpreter (RCE ngoài sandbox)"
    tmp = fresh_dir()
    keys = Keyring.from_file(DEMO_KEYS)
    policy = Policy.default()
    broker = CapabilityBroker(keys, key_id="capability")
    executor = SandboxExecutor(tmp / "ws", broker)  # allow_python defaults to False
    action = make_proposal("p-py", tool="run_python", resource="probe.py").actions[0]
    refused = False
    try:
        executor.execute(action, broker.issue(proposal_id="p-py", actions=[action]))
    except Exception as exc:  # noqa: BLE001 - probe
        refused = getattr(exc, "code", "") == "PYTHON_EXECUTION_DISABLED"

    registry = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest")
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
    findings = review_proposal(make_proposal("p-py2", tool="run_python"), registry, policy)
    review_blocked = has_blockers(findings)

    if refused and review_blocked:
        record(
            "W-14",
            title,
            "OK",
            f"disabled by default (PYTHON_DISABLED); production review blocks it: {[f.code for f in findings]}",
        )
    else:
        record("W-14", title, "VULNERABLE", f"refused={refused}, review_blocked={review_blocked}")


# --------------------------------------------------------------------------- #
# W-15  Bad input surfaces as a raw ValueError
# --------------------------------------------------------------------------- #
def probe_w15() -> None:
    from whyward.control import ControlPlane
    from whyward.errors import WhyWardError
    from whyward.ledger import Ledger
    from whyward.policy import Policy

    title = "Input sai ném ValueError thô thay vì lỗi có kiểu"
    tmp = fresh_dir()
    control = ControlPlane(policy=Policy.default(), ledger=Ledger(tmp / "ledger.jsonl"))
    task = control.create_task("t", "worker", "probe")
    raw_value_error = False
    typed_error = False
    try:
        control.submit_proposal(
            task,
            {
                "proposal_id": "broken",
                "title": "no actions key",
                "risk_tier": "not-a-tier",
            },  # type: ignore[arg-type]
        )
    except WhyWardError as exc:
        typed_error = bool(getattr(exc, "code", ""))
    except (ValueError, TypeError, KeyError):
        raw_value_error = True

    if raw_value_error:
        record("W-15", title, "VULNERABLE", "raw ValueError/KeyError escaped the boundary")
    elif typed_error:
        record("W-15", title, "OK", "malformed proposals raise a typed WhyWardError with a code")
    else:
        record("W-15", title, "VULNERABLE", "malformed proposal was accepted silently")


PROBES: dict[str, Callable[[], None]] = {
    "W-01": probe_w01,
    "W-02": probe_w02,
    "W-03": probe_w03,
    "W-04": probe_w04,
    "W-05": probe_w05,
    "W-06": probe_w06,
    "W-07": probe_w07,
    "W-08": probe_w08,
    "W-09": probe_w09,
    "W-10": probe_w10,
    "W-11": probe_w11,
    "W-12": probe_w12,
    "W-13": probe_w13,
    "W-14": probe_w14,
    "W-15": probe_w15,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", default="", help="comma-separated probe ids, e.g. W-02,W-14")
    parser.add_argument("--json", default="", help="write the result table as JSON to this path")
    args = parser.parse_args(argv)

    selected = [item.strip() for item in args.only.split(",") if item.strip()] or list(PROBES)
    for pid in selected:
        if pid not in PROBES:
            print(f"unknown probe: {pid}", file=sys.stderr)
            return 2
        try:
            PROBES[pid]()
        except Exception as exc:  # noqa: BLE001 - a crashing probe is a finding
            record(pid, pid, "VULNERABLE", f"probe crashed: {type(exc).__name__}: {exc}")

    vulnerable = [row for row in RESULTS if row["verdict"] == "VULNERABLE"]
    print("-" * 78)
    print(f"{len(RESULTS)} probes: {len(RESULTS) - len(vulnerable)} OK, {len(vulnerable)} VULNERABLE")
    if vulnerable:
        print("still vulnerable: " + ", ".join(row["id"] for row in vulnerable))
    if args.json:
        Path(args.json).write_text(json.dumps(RESULTS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0 if not vulnerable else 1


if __name__ == "__main__":
    raise SystemExit(main())
