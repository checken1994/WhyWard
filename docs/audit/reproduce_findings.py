#!/usr/bin/env python3
"""WhyWard audit probes (2026-10-26).

Mục đích: tái lập một cách xác định (deterministic) các phát hiện trong
`docs/audit/2026-10-26-danh-gia-he-thong.md`, để nhóm phát triển có thể:

1. xác nhận phát hiện là thật, không phải suy đoán từ đọc code;
2. chuyển mỗi probe thành một regression test âm tính trong bộ test chuẩn;
3. chứng minh "đã sửa" bằng cách đổi kết quả probe từ VULNERABLE sang OK.

Cách chạy:

    PYTHONPATH=src python docs/audit/reproduce_findings.py
    PYTHONPATH=src python docs/audit/reproduce_findings.py --only W-02,W-06

Mọi probe chỉ ghi trong thư mục tạm. Không gọi mạng. Không sửa repo.

Quy ước kết quả:
    [VULNERABLE] hệ thống cho qua một hành vi mà bản đánh giá coi là không an toàn.
    [OK]         hành vi đã bị chặn đúng như kỳ vọng an toàn.
    [SKIP]       không áp dụng được trên nền tảng hiện tại.

Lưu ý: đây là script kiểm thử phòng thủ cho repo của chính dự án. Nó không
chứa exploit nhắm vào hệ thống bên thứ ba.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
CATALOG = ROOT / "examples" / "catalog"

SECRET = b"whyward-audit-secret-32-bytes-long!"

RESULTS: list[tuple[str, str, str, str]] = []


def record(pid: str, title: str, verdict: str, detail: str) -> None:
    RESULTS.append((pid, title, verdict, detail))
    print(f"[{verdict:<10}] {pid} {title}\n             {detail}\n")


def fresh_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="whyward-audit-"))


def make_control(tmp: Path, *, with_executor: bool = False, catalog: Path | None = None,
                 kill_switch_file: Path | None = None, policy=None):
    from whyward.capability import CapabilityBroker
    from whyward.control import ControlPlane
    from whyward.evidence import KnowledgeStore
    from whyward.execution import SandboxExecutor
    from whyward.ledger import Ledger
    from whyward.policy import Policy

    broker = CapabilityBroker(SECRET) if with_executor else None
    return ControlPlane(
        policy=policy or Policy.default(),
        ledger=Ledger(tmp / "ledger.jsonl"),
        capability_broker=broker,
        executor=SandboxExecutor(tmp / "ws", broker) if with_executor and broker else None,
        knowledge_store=KnowledgeStore.load(catalog) if catalog else None,
        kill_switch_file=kill_switch_file,
    )


def verified_evidence(eid: str, lineage: str):
    from whyward.models import EvidenceRef

    return EvidenceRef(
        evidence_id=eid,
        source_id="usgs",
        lineage_id=lineage,
        observed_fields=("whatever",),
        blind_spots=("none declared",),
        review_status="verified",
    )


def proposal(pid: str, *, resource: str = "hello.txt", risk=None, evidence_ids=("e1", "e2"),
             tool: str = "write_text", parameters=None):
    from whyward.models import ActionRequest, Claim, Proposal, RiskTier

    return Proposal(
        proposal_id=pid,
        title="audit proposal",
        summary="write a file",
        rationale="audit",
        claims=(Claim("c1", "anything", evidence_ids=evidence_ids),),
        alternatives=("do nothing",),
        consequences_if_done=("a file appears",),
        consequences_if_not_done=("nothing changes",),
        unknowns=("audit unknown",),
        rollback_plan="delete the file",
        requested_autonomy=0,
        risk_tier=risk or RiskTier.HIGH,
        actions=(ActionRequest("a1", tool, resource, parameters or {"content": "audit"}),),
    )


# --------------------------------------------------------------------------- #
# W-01  Human approval is not bound to the proposal it approved
# --------------------------------------------------------------------------- #
def probe_w01() -> None:
    from whyward.models import HumanDecision

    tmp = fresh_dir()
    cp = make_control(tmp, with_executor=True)
    cp.register_evidence(verified_evidence("e1", "lineage-1"))
    cp.register_evidence(verified_evidence("e2", "lineage-2"))

    decision = HumanDecision(
        decision_id="d-1",
        approver="ceo",
        approved=True,
        restatement="I approve writing hello.txt into the demo workspace only",
        comprehension={"action": True, "consequence": True, "rollback": True},
    )
    safe = cp.create_task("t-safe", "worker", "write hello")
    first = cp.submit_proposal(safe, proposal("p-safe", resource="hello.txt"), human_decision=decision)

    other = cp.create_task("t-other", "worker", "something the approver never saw")
    second = cp.submit_proposal(
        other,
        proposal("p-other", resource="prod/config/secret.txt", parameters={"content": "pwned"}),
        human_decision=decision,
    )
    wrote = (tmp / "ws" / "prod" / "config" / "secret.txt").exists()

    if first.allowed and second.allowed and wrote:
        record(
            "W-01",
            "Human approval không gắn với proposal (replay được)",
            "VULNERABLE",
            f"cùng một HumanDecision được chấp nhận cho 2 proposal khác nhau; "
            f"proposal thứ hai ghi được prod/config/secret.txt (verdict={second.status.value}). "
            f"HumanDecision không có trường proposal_id / proposal_fingerprint.",
        )
    else:
        record("W-01", "Human approval không gắn với proposal (replay được)", "OK",
               f"proposal thứ hai bị chặn (verdict={second.status.value}).")


# --------------------------------------------------------------------------- #
# W-02  Anyone holding the ControlPlane handle can self-certify evidence
# --------------------------------------------------------------------------- #
def probe_w02() -> None:
    from whyward.policy import Policy
    from whyward.review import has_blockers, review_proposal

    tmp = fresh_dir()
    cp = make_control(tmp)
    for index in (1, 2):
        cp.register_evidence(
            type(verified_evidence(f"forged-{index}", f"attacker-lineage-{index}"))(
                evidence_id=f"forged-{index}",
                source_id="usgs",
                lineage_id=f"attacker-lineage-{index}",
                observed_fields=("x",),
                blind_spots=("y",),
                review_status="verified",
            )
        )
    p = proposal("p-forged", evidence_ids=("forged-1", "forged-2"), risk=None)
    findings = review_proposal(p, cp._evidence, Policy.default())  # noqa: SLF001 - audit of internal state
    blocked = has_blockers(findings)

    if not blocked:
        record(
            "W-02",
            "Bằng chứng tự khai là 'verified' được review tin",
            "VULNERABLE",
            "2 EvidenceRef do bên gọi tự tạo (review_status='verified', source_id và lineage_id tự chọn) "
            "đi qua review_proposal với 0 blocking finding: registry bằng chứng không có chữ ký, "
            "không phân biệt evidence do control core nạp và evidence do worker khai.",
        )
    else:
        record("W-02", "Bằng chứng tự khai là 'verified' được review tin", "OK",
               "evidence tự khai bị chặn ở review.")


# --------------------------------------------------------------------------- #
# W-03  Freshness / review_after metadata is never enforced
# --------------------------------------------------------------------------- #
def probe_w03() -> None:
    tmp = fresh_dir()
    cat = tmp / "catalog"
    subprocess.run(["cp", "-r", str(CATALOG), str(cat)], check=True)
    shard = cat / "facts" / "geology.earthquakes.jsonl"
    lines = shard.read_text(encoding="utf-8").splitlines()
    record_obj = json.loads(lines[0])
    record_obj["freshness"] = {
        "class": "volatile",
        "valid_from": "1990-01-01",
        "valid_until": "1991-01-01",
        "review_after": "1991-01-01",
    }
    lines[0] = json.dumps(record_obj, ensure_ascii=False)
    shard.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = json.loads((cat / "manifest.json").read_text(encoding="utf-8"))
    manifest["shards"][0]["sha256"] = hashlib.sha256(shard.read_bytes()).hexdigest()
    (cat / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    cp = make_control(tmp, catalog=cat)
    result = cp.answer_question("Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?")

    if result["verdict"] == "PASS_WITHIN_SCOPE":
        record(
            "W-03",
            "freshness/valid_until không được thi hành",
            "VULNERABLE",
            f"record hết hạn từ 1991 vẫn được trả {result['verdict']}: {result['answer']!r}; "
            f"không có mã nguồn nào đọc trường freshness.",
        )
    else:
        record("W-03", "freshness/valid_until không được thi hành", "OK",
               f"record hết hạn bị hạ verdict: {result['verdict']}.")


# --------------------------------------------------------------------------- #
# W-04  Manifest integrity is optional and record_count is ignored
# --------------------------------------------------------------------------- #
def probe_w04() -> None:
    from whyward.evidence import KnowledgeStore

    tmp = fresh_dir()
    cat = tmp / "catalog"
    subprocess.run(["cp", "-r", str(CATALOG), str(cat)], check=True)
    manifest_path = cat / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    manifest["shards"][0]["record_count"] = 999
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    count_ignored = len(KnowledgeStore.load(cat).records)

    manifest["shards"][0].pop("sha256", None)
    manifest["shards"][0].pop("record_count", None)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        unsigned_loaded = len(KnowledgeStore.load(cat).records)
    except ValueError:
        unsigned_loaded = -1

    if unsigned_loaded >= 0:
        record(
            "W-04",
            "Checksum shard là tuỳ chọn, record_count không được kiểm",
            "VULNERABLE",
            f"manifest khai record_count=999 nhưng nạp {count_ignored} record không báo lỗi; "
            f"shard bị bỏ sha256 vẫn nạp {unsigned_loaded} record.",
        )
    else:
        record("W-04", "Checksum shard là tuỳ chọn, record_count không được kiểm", "OK",
               "manifest thiếu sha256 bị từ chối.")


# --------------------------------------------------------------------------- #
# W-05  Policy.from_dict silently weakens required lineages
# --------------------------------------------------------------------------- #
def probe_w05() -> None:
    from whyward.models import RiskTier
    from whyward.policy import Policy

    policy = Policy.from_dict(
        {
            "allowed_tools": ["write_text"],
            "protected_path_prefixes": [],
            "allowed_source_ids": ["usgs"],
            "accepted_review_statuses": ["verified"],
            "human_required_risk_tiers": ["critical"],
            "max_autonomy_without_human": 2,
        }
    )
    required = policy.required_lineages(RiskTier.CRITICAL)
    if required < 2:
        record(
            "W-05",
            "Policy thiếu key thì âm thầm hạ yêu cầu bằng chứng",
            "VULNERABLE",
            f"profile critical yêu cầu {required} lineage thay vì lỗi cấu hình "
            f"(default policy là 2); mọi thiếu key khác cũng lấy default im lặng.",
        )
    else:
        record("W-05", "Policy thiếu key thì âm thầm hạ yêu cầu bằng chứng", "OK",
               f"critical yêu cầu {required} lineage.")


# --------------------------------------------------------------------------- #
# W-06  Concurrent writers silently corrupt the ledger
# --------------------------------------------------------------------------- #
def probe_w06() -> None:
    from whyward.ledger import Ledger

    tmp = fresh_dir()
    path = tmp / "ledger.jsonl"
    go = tmp / "go"
    code = (
        "import os, sys, time\n"
        "from whyward.ledger import Ledger\n"
        "l = Ledger(sys.argv[1])\n"
        "while not os.path.exists(sys.argv[2]):\n"
        "    time.sleep(0.001)\n"
        "for i in range(400):\n"
        "    l.append('E', 'writer', {'i': i})\n"
    )
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    codes: list[int] = []
    indexes: list[int] = []
    ok, message = True, "no run"
    for _attempt in range(3):
        if path.exists():
            path.unlink()
        if go.exists():
            go.unlink()
        procs = [
            subprocess.Popen([sys.executable, "-c", code, str(path), str(go)], env=env, cwd=str(ROOT))
            for _ in range(3)
        ]
        time.sleep(0.3)  # để cả 3 process nạp xong state ban đầu
        go.write_text("go", encoding="utf-8")
        codes = [proc.wait() for proc in procs]
        indexes = [
            json.loads(line)["index"]
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        verifier = Ledger.__new__(Ledger)
        verifier.path = path
        ok, message = verifier.verify()
        if len(set(indexes)) != len(indexes) or not ok:
            break

    if len(set(indexes)) != len(indexes) or not ok:
        record(
            "W-06",
            "Nhiều process ghi cùng ledger thì ledger hỏng âm thầm",
            "VULNERABLE",
            f"3 writer, exit codes={codes} (đều 0), {len(indexes)} event / "
            f"{len(set(indexes))} index duy nhất; verify() -> {ok}: {message}",
        )
    else:
        record("W-06", "Nhiều process ghi cùng ledger thì ledger hỏng âm thầm", "OK",
               "ledger vẫn hợp lệ sau khi có nhiều writer.")


# --------------------------------------------------------------------------- #
# W-07  One-use capability is only one-use inside one process
# --------------------------------------------------------------------------- #
def probe_w07() -> None:
    from whyward.capability import CapabilityBroker
    from whyward.models import ActionRequest

    action = ActionRequest("a1", "write_text", "z.txt", {"content": "z"})
    token = CapabilityBroker(SECRET).issue(proposal_id="p", actions=[action])
    restarted = CapabilityBroker(SECRET)  # same secret, fresh in-memory used-set
    try:
        restarted.consume(token, action)
        record(
            "W-07",
            "Capability 'one-use' không sống qua restart",
            "VULNERABLE",
            "token phát hành trước khi restart vẫn được tiêu thụ sau restart: registry used-token "
            "chỉ nằm trong RAM, không có store bền và không có cơ chế thu hồi.",
        )
    except PermissionError as exc:
        record("W-07", "Capability 'one-use' không sống qua restart", "OK", f"bị chặn: {exc}")


# --------------------------------------------------------------------------- #
# W-08  Kill switch is not re-checked before/while executing actions
# --------------------------------------------------------------------------- #
def probe_w08() -> None:
    tmp = fresh_dir()
    stop = tmp / "STOP"
    cp = make_control(tmp, with_executor=True, kill_switch_file=stop)
    cp.register_evidence(verified_evidence("e1", "lineage-1"))
    cp.register_evidence(verified_evidence("e2", "lineage-2"))

    from whyward.models import ActionRequest, Claim, Proposal, RiskTier

    p = Proposal(
        proposal_id="p",
        title="t",
        summary="s",
        rationale="r",
        claims=(Claim("c", "x", evidence_ids=("e1", "e2")),),
        actions=(
            ActionRequest("a1", "write_text", "one.txt", {"content": "1"}),
            ActionRequest("a2", "write_text", "two.txt", {"content": "2"}),
        ),
        risk_tier=RiskTier.LOW,
    )
    task = cp.create_task("t", "worker", "goal")
    stop.write_text("stop", encoding="utf-8")  # engaged before submission
    blocked = cp.submit_proposal(task, p)

    task2 = cp.create_task("t2", "worker", "goal")
    stop.unlink()
    allowed = cp.submit_proposal(task2, p)
    stop.write_text("stop", encoding="utf-8")
    # a second task cannot start while engaged, but tokens already issued are not revoked
    from whyward.capability import CapabilityBroker
    from whyward.execution import SandboxExecutor

    broker = CapabilityBroker(SECRET)
    executor = SandboxExecutor(tmp / "ws2", broker)
    token = broker.issue(proposal_id="p", actions=(ActionRequest("a9", "write_text", "late.txt", {"content": "9"}),))
    late = executor.execute(ActionRequest("a9", "write_text", "late.txt", {"content": "9"}), token)

    if blocked.allowed is False and allowed.allowed and late.get("ok"):
        record(
            "W-08",
            "Kill switch chỉ chặn lúc submit, không thu hồi capability đã phát",
            "VULNERABLE",
            f"khi cờ STOP tồn tại: submit bị chặn ({blocked.status.value}) nhưng capability phát trước đó "
            f"vẫn ghi được late.txt ({late.get('ok')}) và control plane không kiểm lại kill switch trước "
            f"từng action (control.py:279-292).",
        )
    else:
        record("W-08", "Kill switch chỉ chặn lúc submit, không thu hồi capability đã phát", "OK",
               "kill switch chặn cả đường thực thi.")


# --------------------------------------------------------------------------- #
# W-09  CLI verify-ledger crashes on a tampered ledger
# --------------------------------------------------------------------------- #
def probe_w09() -> None:
    tmp = fresh_dir()
    ledger = tmp / "ledger.jsonl"
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    subprocess.run(
        [sys.executable, "-m", "whyward.cli", "ask", "--catalog", str(CATALOG),
         "--ledger", str(ledger), "Valdivia 1960 magnitude?"],
        env=env, cwd=str(ROOT), capture_output=True, check=False,
    )
    ledger.write_text(
        ledger.read_text(encoding="utf-8").replace("LOOKUP_ANSWERED", "LOOKUP_TAMPERED"),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "whyward.cli", "verify-ledger", str(ledger)],
        env=env, cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    crashed = "Traceback" in proc.stderr

    if crashed:
        record(
            "W-09",
            "CLI verify-ledger crash thay vì báo JSON + exit code",
            "VULNERABLE",
            f"ledger bị sửa: exit={proc.returncode}, stderr bắt đầu bằng "
            f"{proc.stderr.strip().splitlines()[-1][:90]!r}; không có output JSON kiểm toán được.",
        )
    else:
        record("W-09", "CLI verify-ledger crash thay vì báo JSON + exit code", "OK",
               f"exit={proc.returncode}.")


# --------------------------------------------------------------------------- #
# W-10  CLI ask returns exit 0 even when the answer is withheld
# --------------------------------------------------------------------------- #
def probe_w10() -> None:
    tmp = fresh_dir()
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", "whyward.cli", "ask", "--catalog", str(CATALOG),
         "--ledger", str(tmp / "ledger.jsonl"),
         "Động đất năm 2004 tại California có độ lớn bao nhiêu?"],
        env=env, cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    withheld = "INSUFFICIENT_EVIDENCE" in proc.stdout
    if withheld and proc.returncode == 0:
        record(
            "W-10",
            "CLI ask trả exit 0 khi câu trả lời bị withhold",
            "VULNERABLE",
            "verdict=INSUFFICIENT_EVIDENCE nhưng exit=0, nên script/CI không phân biệt được "
            "đã trả lời hay bị giữ lại.",
        )
    else:
        record("W-10", "CLI ask trả exit 0 khi câu trả lời bị withhold", "OK",
               f"exit={proc.returncode}.")


# --------------------------------------------------------------------------- #
# W-11  Default policy still accepts demo_verified facts
# --------------------------------------------------------------------------- #
def probe_w11() -> None:
    from whyward.policy import Policy

    accepted = Policy.default().accepted_review_statuses
    if "demo_verified" in accepted:
        record(
            "W-11",
            "Profile mặc định vẫn chấp nhận trạng thái demo_verified",
            "VULNERABLE",
            f"Policy.default().accepted_review_statuses={sorted(accepted)}; ROADMAP 0.2 yêu cầu bỏ trạng thái "
            f"này khỏi production profile nhưng chưa có profile tách biệt.",
        )
    else:
        record("W-11", "Profile mặc định vẫn chấp nhận trạng thái demo_verified", "OK",
               "default policy chỉ nhận verified.")


# --------------------------------------------------------------------------- #
# W-12  Local API has no authentication and no hardening headers
# --------------------------------------------------------------------------- #
def probe_w12() -> None:
    tmp = fresh_dir()
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    proc = subprocess.Popen(
        [sys.executable, "-m", "whyward.cli", "serve", "--port", str(port),
         "--catalog", str(CATALOG), "--ledger", str(tmp / "ledger.jsonl")],
        env=env, cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/ask",
            data=json.dumps({"question": "Valdivia 1960 magnitude?"}).encode(),
            headers={"Content-Type": "application/json"},  # deliberately no credentials
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            headers = dict(response.headers)
            status = response.status
        problems = []
        if status == 200 and body.get("answer"):
            problems.append("truy vấn dữ liệu không cần bất kỳ credential nào")
        if "X-Request-Id" not in headers and "X-Request-ID" not in {k.upper() for k in headers}:
            problems.append("không có request id / correlation id")
        if "X-Content-Type-Options" not in headers:
            problems.append("thiếu security headers")
        if problems:
            record("W-12", "Local API không có auth, không có hardening", "VULNERABLE",
                   f"/ask trả 200 + dữ liệu; {'; '.join(problems)}; Server header = "
                   f"{headers.get('Server')!r} (lộ phiên bản Python).")
        else:
            record("W-12", "Local API không có auth, không có hardening", "OK", "API từ chối truy vấn ẩn danh.")
    except (urllib.error.URLError, OSError) as exc:
        record("W-12", "Local API không có auth, không có hardening", "SKIP", f"không khởi động được server: {exc}")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# --------------------------------------------------------------------------- #
# W-13  read_text loads the whole file into memory before truncating
# --------------------------------------------------------------------------- #
def probe_w13() -> None:
    from whyward.capability import CapabilityBroker
    from whyward.execution import SandboxExecutor
    from whyward.models import ActionRequest

    tmp = fresh_dir()
    broker = CapabilityBroker(SECRET)
    executor = SandboxExecutor(tmp / "ws", broker)
    big = tmp / "ws" / "big.bin"
    size_mb = 64
    big.write_bytes(b"a" * (size_mb * 1024 * 1024))
    action = ActionRequest("a1", "read_text", "big.bin", {"max_chars": 10})
    token = broker.issue(proposal_id="p", actions=[action])
    result = executor.execute(action, token)
    if result["ok"] and len(result["content"]) == 10:
        record(
            "W-13",
            "read_text/write_text không có giới hạn kích thước",
            "VULNERABLE",
            f"file {size_mb} MB được đọc toàn bộ vào RAM rồi mới cắt còn 10 ký tự; "
            f"write_text cũng không giới hạn và luôn ghi đè file đích mà không lưu pre-image.",
        )
    else:
        record("W-13", "read_text/write_text không có giới hạn kích thước", "OK", "đã có giới hạn.")


# --------------------------------------------------------------------------- #
# W-14  Low risk + default policy allows arbitrary code with host privileges
# --------------------------------------------------------------------------- #
def probe_w14() -> None:
    from whyward.models import Claim, Proposal, RiskTier, ActionRequest

    if not Path("/etc/passwd").exists():
        record("W-14", "Risk thấp vẫn chạy được code tuỳ ý bằng quyền host", "SKIP", "không phải Linux/POSIX.")
        return
    tmp = fresh_dir()
    cp = make_control(tmp, with_executor=True)
    cp.register_evidence(verified_evidence("e1", "lineage-1"))
    (tmp / "ws").mkdir(parents=True, exist_ok=True)
    (tmp / "ws" / "prog.py").write_text(
        "open('probe_out.txt','w').write('ran')\n"
        "print('read /etc/passwd:', bool(open('/etc/passwd').read(10)))\n",
        encoding="utf-8",
    )
    p = Proposal(
        proposal_id="p",
        title="t",
        summary="s",
        rationale="r",
        claims=(Claim("c", "x", evidence_ids=("e1",)),),
        actions=(ActionRequest("a1", "run_python", "prog.py", {"timeout_seconds": 5}),),
        risk_tier=RiskTier.LOW,
        requested_autonomy=0,
    )
    task = cp.create_task("t", "worker", "run code")
    decision = cp.submit_proposal(task, p)
    stdout = (decision.execution_results[0].get("stdout") if decision.execution_results else "") or ""
    if decision.allowed and "True" in stdout:
        record(
            "W-14",
            "Risk thấp vẫn chạy được code tuỳ ý bằng quyền host",
            "VULNERABLE",
            f"verdict={decision.status.value}, human_required={decision.required_human}; "
            f"code đọc được /etc/passwd và ghi file: {stdout.strip()!r}. "
            f"Đây là giới hạn đã khai báo trong SECURITY.md nhưng chưa có chốt chặn kỹ thuật nào.",
        )
    else:
        record("W-14", "Risk thấp vẫn chạy được code tuỳ ý bằng quyền host", "OK",
               f"verdict={decision.status.value}.")


# --------------------------------------------------------------------------- #
# W-15  Re-submitting a finished task raises a raw exception
# --------------------------------------------------------------------------- #
def probe_w15() -> None:
    tmp = fresh_dir()
    cp = make_control(tmp, with_executor=True)
    cp.register_evidence(verified_evidence("e1", "lineage-1"))
    cp.register_evidence(verified_evidence("e2", "lineage-2"))
    task = cp.create_task("t", "worker", "goal")
    p = proposal("p", risk=None)
    from whyward.models import RiskTier

    p = proposal("p", risk=RiskTier.LOW)
    cp.submit_proposal(task, p)
    try:
        cp.submit_proposal(task, p)
        raised = ""
    except Exception as exc:  # noqa: BLE001 - audit: ta cần biết kiểu lỗi thô
        raised = f"{type(exc).__name__}: {exc}"
    if raised:
        record(
            "W-15",
            "Gọi lại submit_proposal trên task đã kết thúc ném exception thô",
            "VULNERABLE",
            f"{raised} — caller/HTTP layer nhận traceback thay vì GateDecision có mã lỗi ổn định; "
            f"state machine không có API để phát hiện/replay an toàn.",
        )
    else:
        record("W-15", "Gọi lại submit_proposal trên task đã kết thúc ném exception thô", "OK",
               "trả về quyết định có kiểm soát.")


PROBES = {
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
    parser = argparse.ArgumentParser(description="WhyWard audit probes")
    parser.add_argument("--only", help="danh sách ID, ví dụ W-01,W-06")
    parser.add_argument("--json", help="ghi kết quả ra file JSON")
    args = parser.parse_args(argv)

    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

    selected = [args.only.split(",")] if args.only else [None]
    ids = [pid.strip() for pid in selected[0]] if selected[0] else list(PROBES)

    print(f"WhyWard audit probes — repo={ROOT} python={sys.version.split()[0]}\n")
    for pid in ids:
        probe = PROBES.get(pid)
        if probe is None:
            print(f"bỏ qua ID không tồn tại: {pid}")
            continue
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - probe phải báo lỗi chứ không chết cả bộ
            record(pid, "probe error", "SKIP", f"{type(exc).__name__}: {exc}")

    vulnerable = [row for row in RESULTS if row[2] == "VULNERABLE"]
    print("-" * 78)
    print(f"Tổng: {len(RESULTS)} probe | VULNERABLE: {len(vulnerable)} | "
          f"OK: {sum(1 for r in RESULTS if r[2] == 'OK')} | "
          f"SKIP: {sum(1 for r in RESULTS if r[2] == 'SKIP')}")
    if args.json:
        Path(args.json).write_text(
            json.dumps(
                [{"id": r[0], "title": r[1], "verdict": r[2], "detail": r[3]} for r in RESULTS],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"JSON: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
