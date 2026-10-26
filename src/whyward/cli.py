"""WhyWard command line interface.

Exit codes are part of the contract:

    0  answered / verified / completed
    1  failure (execution, invalid state, unhandled)
    2  integrity failure (ledger/catalog tampering)
    3  withheld (insufficient evidence, awaiting human)
    4  configuration or authorization problem
    5  unavailable (kill switch, rate limit)
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from .api import SCOPE_ADMIN, SCOPE_ASK, SCOPE_AUDIT, SCOPE_METRICS, SCOPE_READ, run_server
from .capability import CapabilityBroker, SqliteUsedTokenStore
from .control import ControlPlane
from .errors import (
    EXIT_FAILURE,
    EXIT_INTEGRITY,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_WITHHELD,
    ConfigurationError,
    WhyWardError,
)
from .evidence import KnowledgeStore
from .execution import SandboxExecutor
from .identity import ApiTokenStore, Keyring, generate_api_token, sign_document
from .isolation import DockerSandboxBackend, isolation_report
from .ledger import Ledger
from .models import ActionRequest, Claim, Proposal, RiskTier, now_iso
from .policy import Policy
from .registry import EvidenceRegistry
from .version import __version__

EXIT_CONFIGURATION = 4
ERROR_EXIT = {
    "KILL_SWITCH_ENGAGED": EXIT_UNAVAILABLE,
    "NO_EVIDENCE_REGISTRY": EXIT_CONFIGURATION,
    "NO_EXECUTION_DOMAIN": EXIT_CONFIGURATION,
    "CONFIG_INVALID": EXIT_CONFIGURATION,
    "POLICY_INVALID": EXIT_CONFIGURATION,
    "UNAUTHENTICATED": EXIT_CONFIGURATION,
    "FORBIDDEN": EXIT_CONFIGURATION,
    "INTEGRITY_FAILURE": EXIT_INTEGRITY,
    "LEDGER_INVALID": EXIT_INTEGRITY,
}
VERDICT_EXIT = {
    "PASS_WITHIN_SCOPE": EXIT_OK,
    "FOUND_SCOPED": EXIT_OK,
    "FOUND_STALE": EXIT_OK,
    "INSUFFICIENT_EVIDENCE": EXIT_WITHHELD,
    "INSUFFICIENT_OBSERVABILITY": EXIT_WITHHELD,
    "AWAITING_HUMAN": EXIT_WITHHELD,
    "BLOCKED_BY_POLICY": EXIT_UNAVAILABLE,
    "FAIL": EXIT_FAILURE,
    "NOT_VERIFIED": EXIT_WITHHELD,
    "REJECTED_STATE": EXIT_FAILURE,
}


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _keyring(args: argparse.Namespace, *, allow_demo: bool = False) -> Keyring:
    path = getattr(args, "keyring", None)
    if path:
        return Keyring.from_file(path)
    from_env = Keyring.from_env()
    if from_env.ids():
        return from_env
    env_secret = os.environ.get("WHYWARD_CAPABILITY_SECRET", "")
    if env_secret:
        return Keyring({"capability": env_secret, **dict(Keyring.demo()._keys)})
    if allow_demo:
        return Keyring.demo()
    raise ConfigurationError(
        "No signing keys configured. Pass --keyring or set WHYWARD_KEY_<ID>; "
        "run 'whyward keygen' to create one.",
        code="NO_SIGNING_KEYS",
    )


def _optional_keyring(args: argparse.Namespace) -> Keyring | None:
    """Keyring if explicitly configured, else None.

    Deliberately does *not* fall back to demo keys: verifying a signature with a
    key that ships in the repo would make the check meaningless.
    """
    try:
        return _keyring(args)
    except WhyWardError:
        return None


def _load_policy(args: argparse.Namespace) -> Policy:
    profile = getattr(args, "profile", None)
    path = getattr(args, "policy", None)
    if path:
        require = bool(getattr(args, "require_signed_policy", False))
        # An explicitly configured keyring is always used for verification; without
        # one, Policy.load falls back to WHYWARD_KEY_* (and fails closed if the file
        # is signed by a key it cannot resolve).
        return Policy.load(
            path,
            keyring=_optional_keyring(args),
            require_signature=require,
            allow_dev_profile=True,
        )
    if profile == "dev" or profile is None:
        return Policy.dev()
    return Policy.default()


def _build_control(
    args: argparse.Namespace,
    *,
    workspace: Path | None = None,
    with_executor: bool = False,
    allow_python: bool = False,
) -> ControlPlane:
    policy = _load_policy(args)
    keyring = _keyring(args, allow_demo=policy.profile == "dev")
    ledger = Ledger(
        Path(args.ledger),
        keyring=keyring,
        signing_key_id="audit-ledger",
    )
    broker = None
    executor = None
    if with_executor:
        used_store = SqliteUsedTokenStore(Path(args.state_dir) / "capabilities.sqlite3")
        backend = None
        if allow_python:
            backend = DockerSandboxBackend.try_create()
            if backend is None:
                print(
                    "warning: no container runtime found; run_python will use subprocess with rlimits "
                    "(not OS isolation). Install docker/podman for the container backend.",
                    file=sys.stderr,
                )
        broker = CapabilityBroker(
            keyring=keyring,
            key_id="capability",
            used_store=used_store,
            blocked=None,
        )
        executor = SandboxExecutor(
            workspace or Path(args.state_dir) / "workspace",
            broker,
            limits=policy.limits,
            allow_python=allow_python and "run_python" in policy.allowed_tools,
            python_backend=backend,
        )
    store = None
    if getattr(args, "catalog", None):
        store = KnowledgeStore.load(
            args.catalog,
            require_checksum=policy.evidence.require_checksum_in_manifest,
            require_record_count=policy.evidence.require_record_count,
            keyring=keyring if getattr(args, "require_signed_catalog", False) else None,
            require_signature=bool(getattr(args, "require_signed_catalog", False)),
            trust_key_ids=policy.accepted_registry_key_ids,
        )
    registry = None
    if store is not None:
        registry = EvidenceRegistry(
            keyring=keyring,
            signing_key_id="evidence-ingest",
            path=Path(args.state_dir) / "evidence.jsonl",
        )
        if policy.profile == "dev":
            # Dev profile only: treat the bundled demo catalog as ingestion output.
            # Production registries are populated by the ingestion pipeline.
            for record in store.records:
                registry.register_from_catalog(catalog_record=record, review_status="demo_verified")
    control = ControlPlane(
        policy=policy,
        ledger=ledger,
        capability_broker=broker,
        executor=executor,
        knowledge_store=store,
        evidence_registry=registry,
        kill_switch_file=Path(args.kill_switch_file) if getattr(args, "kill_switch_file", None) else None,
        keyring=keyring,
    )
    if broker is not None:
        broker.set_blocked_hook(control.kill_switch_engaged)
    if executor is not None:
        executor.set_blocked_hook(control.kill_switch_engaged)
    return control


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _cmd_ask(args: argparse.Namespace) -> int:
    control = _build_control(args)
    result = control.answer_question(args.question, actor=args.actor, domain=args.domain)
    _print_json(result)
    return VERDICT_EXIT.get(str(result.get("verdict")), EXIT_FAILURE)


def _cmd_demo(args: argparse.Namespace) -> int:
    root = Path(args.workdir)
    workspace = root / "workspace"
    state = root / "state"
    args.state_dir = str(state)
    args.ledger = str(root / "ledger.jsonl")
    args.profile = "dev"
    control = _build_control(args, workspace=workspace, with_executor=True)
    if control.evidence_registry is None:  # pragma: no cover - demo always wires a registry
        raise WhyWardError("Demo requires an evidence registry", code="DEMO_WITHOUT_REGISTRY")
    control.register_reviewed_evidence(
        evidence_id="demo:write-requirement",
        source_id="internal-test",
        lineage_id="internal-test-suite",
        title="WhyWard demo requirement",
        observed_fields=("requested filename", "requested content"),
        blind_spots=("does not prove the file is useful to an end user",),
        retrieved_at=now_iso(),
        review_status="verified",
        observation_method="local deterministic demo fixture",
        freshness={"class": "historical_stable"},
    )
    content = "WhyWard: AI đề xuất, bằng chứng quyết định đường qua cổng.\n"
    proposal = Proposal(
        proposal_id="demo-write",
        title="Write a demo file inside the sandbox",
        summary="Create hello.txt inside the isolated demo workspace.",
        rationale="Demonstrate proposal -> signed evidence -> capability -> execution -> read-back.",
        claims=(
            Claim(
                claim_id="demo-claim",
                statement="The requested demo action is limited to hello.txt in the sandbox.",
                evidence_ids=("demo:write-requirement",),
            ),
        ),
        actions=(
            ActionRequest(
                action_id="write-hello",
                tool="write_text",
                resource="hello.txt",
                parameters={
                    "content": content,
                    "expected_sha256": __import__("hashlib").sha256(content.encode("utf-8")).hexdigest(),
                },
                reversible=True,
                expected_result="hello.txt exists with the exact requested bytes.",
            ),
        ),
        rollback_plan="Delete hello.txt from the demo workspace.",
        requested_autonomy=2,
        risk_tier=RiskTier.LOW,
    )
    task = control.create_task("demo-task", "cli-demo", "Demonstrate a governed sandbox write")
    decision = control.submit_proposal(task, proposal)
    lookup = None
    if args.catalog:
        lookup = control.answer_question(
            "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?", actor="cli-demo"
        )
    _print_json(
        {
            "system": "WhyWard",
            "version": __version__,
            "gate": decision.to_dict(),
            "workspace": str(workspace.resolve()),
            "ledger_verify": control.ledger.verify(),
            "checkpoint": control.ledger.checkpoint(),
            "status": control.status(),
            "lookup_demo": lookup,
        }
    )
    return EXIT_OK if decision.allowed else EXIT_FAILURE


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    try:
        ledger = Ledger(
            args.path,
            keyring=_optional_keyring(args),
            require_signature=args.require_signature,
        )
    except WhyWardError as exc:
        _print_json({"valid": False, "error": exc.code, "message": exc.message})
        return EXIT_INTEGRITY
    valid, message = ledger.verify()
    payload: dict[str, Any] = {
        "valid": valid,
        "message": message,
        "events": ledger.event_count,
        "head_hash": ledger.head,
    }
    if valid:
        payload["checkpoint"] = ledger.checkpoint()
    if args.anchor:
        anchor_valid, anchor_message = ledger.verify_against_anchor(args.anchor) if valid else (False, "ledger invalid")
        payload["anchor"] = {"valid": anchor_valid, "message": anchor_message}
        if not anchor_valid:
            valid = False
    _print_json(payload)
    return EXIT_OK if valid else EXIT_INTEGRITY


def _cmd_checkpoint(args: argparse.Namespace) -> int:
    ledger = Ledger(args.path, keyring=_optional_keyring(args), signing_key_id="audit-ledger")
    if args.anchor:
        checkpoint = ledger.anchor(args.anchor)
        _print_json({"checkpoint": checkpoint, "anchor": args.anchor})
    else:
        _print_json(ledger.checkpoint())
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:
    control = _build_control(args)
    payload = control.status()
    payload["isolation"] = isolation_report()
    _print_json(payload)
    return EXIT_OK


def _cmd_serve(args: argparse.Namespace) -> int:
    tokens = None
    require_auth = not args.insecure
    if require_auth:
        if args.token_file:
            tokens = ApiTokenStore.from_file(args.token_file)
        elif os.environ.get("WHYWARD_API_TOKENS"):
            tokens = ApiTokenStore.from_env()
        else:
            raise ConfigurationError(
                "Refusing to start an API without authentication. Provide --token-file, "
                "set WHYWARD_API_TOKENS, or explicitly pass --insecure for local testing.",
                code="NO_API_TOKENS",
            )
    control = _build_control(args)
    run_server(control, host=args.host, port=args.port, tokens=tokens, require_auth=require_auth)
    return EXIT_OK


def _cmd_keygen(args: argparse.Namespace) -> int:
    destination = Path(args.output)
    if destination.exists() and not args.force:
        _print_json({"error": "file exists", "path": str(destination), "hint": "use --force"})
        return EXIT_CONFIGURATION
    key_ids = args.key_id or [
        "capability",
        "evidence-ingest",
        "audit-ledger",
        "approval-authority",
        "policy-signing",
        "demo-manifest-2026",
    ]
    keys = {key_id: secrets.token_hex(32) for key_id in key_ids}
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(keys, indent=2) + "\n", encoding="utf-8")
    os.chmod(destination, 0o600)
    _print_json({"created": str(destination), "key_ids": sorted(keys), "note": "Keep this file outside the repo."})
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    keyring = _keyring(args)
    path = Path(args.path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    body = (raw.get(args.root_key) or raw) if args.root_key and isinstance(raw, dict) else raw
    if not isinstance(body, dict):
        raise ConfigurationError("Artifact must be a JSON object", code="ARTIFACT_INVALID")
    body = {k: v for k, v in body.items() if k != "signature"}
    signed = sign_document(body, args.key_id, keyring.get(args.key_id))
    document = {args.root_key: signed["payload"], "signature": signed["signature"]} if args.root_key else signed
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _print_json({"signed": str(path), "key_id": args.key_id, "algorithm": "hmac-sha256"})
    return EXIT_OK


def _cmd_token(args: argparse.Namespace) -> int:
    token = generate_api_token()
    payload: dict[str, Any] = {
        "token": token,
        "subject": args.subject,
        "scopes": list(args.scope or ["ask"]),
        "usage": "Authorization: Bearer <token>",
        "note": "The token is shown once; the store keeps only its sha256.",
    }
    if args.token_store:
        store_path = Path(args.token_store)
        store = ApiTokenStore.from_file(store_path) if store_path.exists() else ApiTokenStore()
        store.add(token, subject=args.subject, scopes=tuple(args.scope or ["ask"]))
        store.save(store_path)
        payload["token_store"] = str(store_path)
    _print_json(payload)
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "version": __version__,
        "python": sys.version.split()[0],
        "isolation": isolation_report(),
        "checks": {},
    }
    checks = payload["checks"]
    try:
        policy = _load_policy(args)
        checks["policy"] = {"ok": True, "profile": policy.profile, "digest": policy.digest()}
        if policy.profile == "dev":
            checks["policy"]["warning"] = "dev profile: not for production"
    except WhyWardError as exc:
        checks["policy"] = {"ok": False, "error": exc.code, "message": exc.message}
    try:
        profile_name = checks.get("policy", {}).get("profile")
        _keyring(args, allow_demo=profile_name == "dev")
        checks["keyring"] = {"ok": True}
    except WhyWardError as exc:
        checks["keyring"] = {"ok": False, "error": exc.code, "message": exc.message}
    if getattr(args, "catalog", None):
        try:
            store = KnowledgeStore.load(args.catalog)
            checks["catalog"] = {
                "ok": True,
                "dataset_version": store.dataset_version,
                "dataset_digest": store.dataset_digest,
                "signed": store.signed,
                "records": len(store.records),
            }
        except WhyWardError as exc:
            checks["catalog"] = {"ok": False, "error": exc.code, "message": exc.message}
    if getattr(args, "ledger", None) and Path(args.ledger).exists():
        try:
            ledger = Ledger(args.ledger)
            valid, message = ledger.verify()
            checks["ledger"] = {"ok": valid, "message": message, "events": ledger.event_count}
        except WhyWardError as exc:
            checks["ledger"] = {"ok": False, "error": exc.code, "message": exc.message}
    payload["ok"] = all(check.get("ok") for check in checks.values()) if checks else True
    _print_json(payload)
    return EXIT_OK if payload["ok"] else EXIT_FAILURE


def _cmd_report(args: argparse.Namespace) -> int:
    keyring = _optional_keyring(args)
    try:
        ledger = Ledger(args.path, keyring=keyring)
    except WhyWardError as exc:
        _print_json({"error": exc.code, "message": exc.message, "hint": "pass --keyring"})
        return EXIT_INTEGRITY
    counts: dict[str, int] = {}
    verdicts: dict[str, int] = {}
    decisions: list[dict[str, Any]] = []
    for event in ledger.iter_events():
        counts[event["event_type"]] = counts.get(event["event_type"], 0) + 1
        payload = event.get("payload", {})
        if isinstance(payload, dict):
            verdict = payload.get("verdict")
            if verdict:
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
            if event["event_type"] in {
                "HUMAN_DECISION_RECORDED",
                "TASK_COMPLETED_WITHIN_SCOPE",
                "TASK_BLOCKED_KILL_SWITCH",
                "EXECUTION_FAILED",
            }:
                decisions.append(
                    {
                        "event_id": event.get("event_id"),
                        "index": event.get("index"),
                        "timestamp": event.get("timestamp"),
                        "event_type": event.get("event_type"),
                        "actor": event.get("actor"),
                        "task_id": payload.get("task_id"),
                        "proposal_digest": payload.get("proposal_digest") or payload.get("decision_digest"),
                        "verdict": verdict,
                    }
                )
    valid, message = ledger.verify()
    _print_json(
        {
            "ledger": {"valid": valid, "message": message, "events": ledger.event_count, "head": ledger.head},
            "event_counts": dict(sorted(counts.items())),
            "verdict_counts": dict(sorted(verdicts.items())),
            "decisions": decisions[-args.limit :] if args.limit else decisions,
        }
    )
    return EXIT_OK if valid else EXIT_INTEGRITY


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def _common(parser: argparse.ArgumentParser, *, ledger_default: str = ".whyward-runtime/ledger.jsonl") -> None:
    parser.add_argument("--ledger", default=ledger_default, help="ledger JSONL path")
    parser.add_argument("--state-dir", default=".whyward-runtime", help="runtime state directory")
    parser.add_argument("--keyring", help="keyring JSON file (kept outside the repo)")
    parser.add_argument("--policy", help="policy JSON file")
    parser.add_argument("--profile", choices=["dev", "production"], help="built-in policy profile")
    parser.add_argument("--require-signed-policy", action="store_true")
    parser.add_argument("--require-signed-catalog", action="store_true")
    parser.add_argument("--catalog", help="catalog directory with manifest.json")
    parser.add_argument("--kill-switch-file", help="file whose presence engages the kill switch")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="whyward", description="WhyWard boundary control plane")
    parser.add_argument("--version", action="version", version=f"WhyWard {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    ask = subparsers.add_parser("ask", help="Ask the reviewed local catalog")
    ask.add_argument("question")
    ask.add_argument("--catalog", required=True)
    ask.add_argument("--domain")
    ask.add_argument("--actor", default="cli")
    ask.add_argument("--ledger", default=".whyward-runtime/ledger.jsonl")
    ask.add_argument("--state-dir", default=".whyward-runtime")
    ask.add_argument("--keyring")
    ask.add_argument("--policy")
    ask.add_argument("--profile", choices=["dev", "production"])
    ask.add_argument("--require-signed-policy", action="store_true")
    ask.add_argument("--require-signed-catalog", action="store_true")
    ask.add_argument("--kill-switch-file")
    ask.set_defaults(func=_cmd_ask)

    demo = subparsers.add_parser("demo", help="Run a governed sandbox-write demo")
    demo.add_argument("--workdir", default=".whyward-demo")
    demo.add_argument("--catalog")
    demo.add_argument("--policy")
    demo.add_argument("--keyring")
    demo.add_argument("--profile", choices=["dev", "production"])
    demo.add_argument("--kill-switch-file")
    demo.set_defaults(func=_cmd_demo)

    verify = subparsers.add_parser("verify-ledger", help="Verify a WhyWard hash-chain ledger")
    verify.add_argument("path")
    verify.add_argument("--anchor", help="checkpoint file to compare against")
    verify.add_argument("--keyring")
    verify.add_argument("--require-signature", action="store_true")
    verify.set_defaults(func=_cmd_verify_ledger)

    checkpoint = subparsers.add_parser("checkpoint", help="Print or anchor a ledger checkpoint")
    checkpoint.add_argument("path")
    checkpoint.add_argument("--anchor", help="write the checkpoint to this external path")
    checkpoint.add_argument("--keyring")
    checkpoint.set_defaults(func=_cmd_checkpoint)

    serve = subparsers.add_parser("serve", help="Run the authenticated API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--token-file", help="JSON file with API tokens")
    serve.add_argument("--insecure", action="store_true", help="disable auth (local testing only)")
    _common(serve)
    serve.set_defaults(func=_cmd_serve)

    status = subparsers.add_parser("status", help="Show what is actually enforced")
    _common(status)
    status.set_defaults(func=_cmd_status)

    keygen = subparsers.add_parser("keygen", help="Generate a keyring file")
    keygen.add_argument("--output", default=".whyward-keys/keyring.json")
    keygen.add_argument("--key-id", action="append")
    keygen.add_argument("--force", action="store_true")
    keygen.set_defaults(func=_cmd_keygen)

    sign = subparsers.add_parser("sign", help="Sign a policy or catalog manifest")
    sign.add_argument("path")
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--keyring")
    sign.add_argument("--root-key", help="wrap payload under this key (e.g. 'policy')")
    sign.set_defaults(func=_cmd_sign)

    token = subparsers.add_parser("token", help="Generate an API bearer token")
    token.add_argument("--subject", default="local-operator")
    token.add_argument("--scope", action="append", default=None, help="scope (repeatable)")
    token.add_argument("--token-store", default="", help="write the hashed token store here (0600)")
    token.set_defaults(func=_cmd_token)

    doctor = subparsers.add_parser("doctor", help="Check configuration, isolation and integrity")
    _common(doctor)
    doctor.set_defaults(func=_cmd_doctor)

    report = subparsers.add_parser("report", help="Export an audit report from the ledger")
    report.add_argument("path")
    report.add_argument("--limit", type=int, default=50)
    report.add_argument("--keyring")
    report.set_defaults(func=_cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_OK
    if hasattr(args, "scope") and args.scope is None:
        args.scope = [SCOPE_ASK, SCOPE_READ, SCOPE_AUDIT, SCOPE_METRICS, SCOPE_ADMIN]
    try:
        return int(args.func(args))
    except WhyWardError as exc:
        print(json.dumps({"error": exc.code, "message": exc.message, "details": exc.details}, ensure_ascii=False))
        return ERROR_EXIT.get(exc.code, exc.exit_code)
    except BrokenPipeError:  # pragma: no cover
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
