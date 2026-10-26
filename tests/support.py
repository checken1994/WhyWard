"""Shared fixtures for the WhyWard test suite.

Everything here mirrors what a real deployment would do: keys come from a
keyring file, evidence goes through the registry, approvals are signed and bound
to a proposal digest. Tests that need weaker behaviour must opt in explicitly,
which keeps the suite honest about the security model.
"""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from whyward.capability import CapabilityBroker, InMemoryUsedTokenStore
from whyward.control import ControlPlane
from whyward.evidence import KnowledgeStore
from whyward.execution import SandboxExecutor
from whyward.identity import Keyring
from whyward.ledger import Ledger
from whyward.models import ActionRequest, Claim, HumanDecision, Proposal, RiskTier, now_iso
from whyward.policy import Policy
from whyward.registry import EvidenceRegistry

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "examples" / "catalog"
KEYRING_FILE = ROOT / "examples" / "keys" / "demo.keyring.json"
APPROVER_KEY_ID = "approval-authority"


def keyring() -> Keyring:
    return Keyring.from_file(KEYRING_FILE)


class Clock:
    def __init__(self, current: datetime | None = None) -> None:
        self.current = current or datetime(2026, 10, 26, 12, 0, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs: Any) -> None:
        self.current = self.current + timedelta(**kwargs)

    def iso(self) -> str:
        return self.current.isoformat().replace("+00:00", "Z")


def build_control(
    tmp: str | Path,
    *,
    profile: str = "dev",
    with_executor: bool = True,
    allow_python: bool = False,
    with_catalog: bool = True,
    kill_switch_file: Path | None = None,
    clock: Clock | None = None,
    policy: Policy | None = None,
    register_catalog_evidence: bool = True,
) -> ControlPlane:
    root = Path(tmp)
    keys = keyring()
    effective_policy = policy or (Policy.dev() if profile == "dev" else Policy.default())
    ledger = Ledger(root / "ledger.jsonl", keyring=keys, signing_key_id="audit-ledger")
    registry = EvidenceRegistry(keyring=keys, signing_key_id="evidence-ingest")
    store = KnowledgeStore.load(CATALOG) if with_catalog else None
    if store is not None and register_catalog_evidence:
        for record in store.records:
            registry.register_from_catalog(catalog_record=record, review_status="demo_verified")
    broker = executor = None
    if with_executor:
        broker = CapabilityBroker(
            keyring=keys,
            key_id="capability",
            used_store=InMemoryUsedTokenStore(),
        )
        executor = SandboxExecutor(
            root / "workspace",
            broker,
            limits=effective_policy.limits,
            allow_python=allow_python,
        )
    control = ControlPlane(
        policy=effective_policy,
        ledger=ledger,
        capability_broker=broker,
        executor=executor,
        knowledge_store=store,
        evidence_registry=registry,
        kill_switch_file=kill_switch_file,
        keyring=keys,
        clock=clock,
    )
    if broker is not None:
        broker.set_blocked_hook(control.kill_switch_engaged)
    if executor is not None:
        executor.set_blocked_hook(control.kill_switch_engaged)
    return control


def evidence(control: ControlPlane, evidence_id: str, lineage: str, **overrides: Any) -> str:
    payload: dict[str, Any] = {
        "evidence_id": evidence_id,
        "source_id": "usgs",
        "lineage_id": lineage,
        "retrieved_at": now_iso(),
        "observed_fields": ("requested action", "sandbox resource"),
        "blind_spots": ("does not prove end-user value",),
        "review_status": "verified",
        "observation_method": "unit-test fixture",
    }
    payload.update(overrides)
    assert control.evidence_registry is not None
    control.evidence_registry.register(payload)
    return evidence_id


def proposal(
    *,
    proposal_id: str = "p-1",
    resources: Iterable[str] = ("result.txt",),
    tool: str = "write_text",
    parameters: dict[str, Any] | None = None,
    risk: RiskTier = RiskTier.LOW,
    evidence_ids: tuple[str, ...] = ("ev-1",),
    autonomy: int = 0,
    reversible: bool = True,
    rollback: str = "delete the file",
) -> Proposal:
    actions = tuple(
        ActionRequest(
            action_id=f"a-{index}",
            tool=tool,
            resource=resource,
            parameters=dict(parameters or {"content": "governed"}),
            reversible=reversible,
        )
        for index, resource in enumerate(resources)
    )
    return Proposal(
        proposal_id=proposal_id,
        title="Governed write",
        summary="Write a file inside the sandbox.",
        rationale="Exercise the boundary.",
        claims=(Claim(claim_id="c-1", statement="The action is scoped.", evidence_ids=evidence_ids),),
        actions=actions,
        alternatives=("do nothing",),
        consequences_if_done=("a file appears",),
        consequences_if_not_done=("nothing changes",),
        unknowns=("downstream consumers",),
        rollback_plan=rollback,
        requested_autonomy=autonomy,
        risk_tier=risk,
    )


def approval(
    control: ControlPlane,
    task_id: str,
    target_proposal: Proposal,
    *,
    approved: bool = True,
    sign: bool = True,
    key_id: str = APPROVER_KEY_ID,
    expires_in_seconds: int = 3600,
    nonce: str = "nonce-1",
    approver: str = "owner@example.invalid",
    restatement: str = "Tôi duyệt ghi file trong sandbox và hiểu có thể xoá để rollback.",
) -> HumanDecision:
    package = control.approval_package(target_proposal, findings=(), task_id=task_id)
    if expires_in_seconds != control.policy.review.approval_ttl_seconds:
        from whyward.models import _iso_plus

        package = replace(package, expires_at=_iso_plus(package.issued_at, expires_in_seconds))
    decision = HumanDecision(
        decision_id="decision-1",
        approver=approver,
        approved=approved,
        proposal_digest=target_proposal.digest(),
        task_id=task_id,
        package_digest=package.package_digest,
        restatement=restatement,
        reason="Phạm vi hẹp, có bằng chứng và rollback rõ.",
        comprehension={"action": True, "consequence": True, "rollback": True},
        decided_at=now_iso(),
        expires_at=package.expires_at,
        nonce=nonce,
    )
    if sign:
        decision = control.sign_decision(decision, key_id=key_id, key=keyring().get(key_id))
    return decision


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def temp_dir() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix="whyward-test-")
