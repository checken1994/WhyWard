from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from . import __version__
from .api import run_server
from .capability import CapabilityBroker
from .control import ControlPlane
from .evidence import KnowledgeStore
from .execution import SandboxExecutor
from .ledger import Ledger
from .models import ActionRequest, Claim, EvidenceRef, Proposal, RiskTier
from .policy import Policy


def _print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _secret() -> bytes:
    configured = os.environ.get("WHYWARD_CAPABILITY_SECRET", "")
    if configured:
        return configured.encode("utf-8")
    return secrets.token_bytes(32)


def _load_policy(path: str | None) -> Policy:
    if not path:
        return Policy.default()
    return Policy.load(path)


def _build_control(
    *,
    ledger_path: Path,
    workspace: Path | None = None,
    catalog: str | None = None,
    policy_path: str | None = None,
    with_executor: bool = False,
    kill_switch_file: str | None = None,
) -> ControlPlane:
    policy = _load_policy(policy_path)
    ledger = Ledger(ledger_path)
    broker = CapabilityBroker(_secret()) if with_executor else None
    executor = SandboxExecutor(workspace, broker) if with_executor and workspace and broker else None
    store = KnowledgeStore.load(catalog) if catalog else None
    return ControlPlane(
        policy=policy,
        ledger=ledger,
        capability_broker=broker,
        executor=executor,
        knowledge_store=store,
        kill_switch_file=kill_switch_file,
    )


def _cmd_ask(args: argparse.Namespace) -> int:
    control = _build_control(
        ledger_path=Path(args.ledger),
        catalog=args.catalog,
        policy_path=args.policy,
        kill_switch_file=args.kill_switch_file,
    )
    _print_json(control.answer_question(args.question, actor="cli"))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    root = Path(args.workdir)
    workspace = root / "workspace"
    control = _build_control(
        ledger_path=root / "ledger.jsonl",
        workspace=workspace,
        catalog=args.catalog,
        policy_path=args.policy,
        with_executor=True,
        kill_switch_file=args.kill_switch_file,
    )
    evidence = EvidenceRef(
        evidence_id="demo:write-requirement",
        source_id="internal-test",
        lineage_id="internal-test-suite",
        title="WhyWard demo requirement",
        observed_fields=("requested filename", "requested content"),
        blind_spots=("does not prove the file is useful to an end user",),
        retrieved_at="2026-10-26T00:00:00Z",
        review_status="verified",
        observation_method="local deterministic demo fixture",
    )
    control.register_evidence(evidence)
    content = "WhyWard: AI đề xuất, bằng chứng quyết định đường qua cổng.\n"
    proposal = Proposal(
        proposal_id="demo-write",
        title="Write a demo file inside the sandbox",
        summary="Create hello.txt inside the isolated demo workspace.",
        rationale="Demonstrate proposal -> capability -> execution -> read-back.",
        claims=(
            Claim(
                claim_id="demo-claim",
                statement="The requested demo action is limited to hello.txt in the sandbox.",
                evidence_ids=(evidence.evidence_id,),
            ),
        ),
        actions=(
            ActionRequest(
                action_id="write-hello",
                tool="write_text",
                resource="hello.txt",
                parameters={
                    "content": content,
                    "expected_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
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
            "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?",
            actor="cli-demo",
        )
    _print_json(
        {
            "system": "WhyWard",
            "gate": decision.to_dict(),
            "workspace": str(workspace.resolve()),
            "ledger_verify": control.ledger.verify(),
            "checkpoint": control.ledger.checkpoint(),
            "lookup_demo": lookup,
        }
    )
    return 0 if decision.allowed else 2


def _cmd_verify_ledger(args: argparse.Namespace) -> int:
    ledger = Ledger(args.path)
    valid, message = ledger.verify()
    _print_json({"valid": valid, "message": message, "checkpoint": ledger.checkpoint() if valid else None})
    return 0 if valid else 2


def _cmd_checkpoint(args: argparse.Namespace) -> int:
    ledger = Ledger(args.path)
    _print_json(ledger.checkpoint())
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    control = _build_control(
        ledger_path=Path(args.ledger),
        catalog=args.catalog,
        policy_path=args.policy,
        kill_switch_file=args.kill_switch_file,
    )
    run_server(control, host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="whyward", description="WhyWard boundary control plane")
    parser.add_argument("--version", action="version", version=f"WhyWard {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    ask = subparsers.add_parser("ask", help="Ask the reviewed local catalog")
    ask.add_argument("question")
    ask.add_argument("--catalog", required=True)
    ask.add_argument("--ledger", default=".whyward-runtime/ledger.jsonl")
    ask.add_argument("--policy")
    ask.add_argument("--kill-switch-file")
    ask.set_defaults(func=_cmd_ask)

    demo = subparsers.add_parser("demo", help="Run a governed sandbox-write demo")
    demo.add_argument("--workdir", default=".whyward-demo")
    demo.add_argument("--catalog")
    demo.add_argument("--policy")
    demo.add_argument("--kill-switch-file")
    demo.set_defaults(func=_cmd_demo)

    verify = subparsers.add_parser("verify-ledger", help="Verify a WhyWard hash-chain ledger")
    verify.add_argument("path")
    verify.set_defaults(func=_cmd_verify_ledger)

    checkpoint = subparsers.add_parser("checkpoint", help="Print a ledger checkpoint for external anchoring")
    checkpoint.add_argument("path")
    checkpoint.set_defaults(func=_cmd_checkpoint)

    serve = subparsers.add_parser("serve", help="Run the local development API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--catalog")
    serve.add_argument("--ledger", default=".whyward-runtime/ledger.jsonl")
    serve.add_argument("--policy")
    serve.add_argument("--kill-switch-file")
    serve.set_defaults(func=_cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
