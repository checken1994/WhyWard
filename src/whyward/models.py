from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import Enum
from typing import Any, cast

from .canonical import canonical_json, digest, jsonable

TASK_SCHEMA_VERSION = 2
LEDGER_EVENT_SCHEMA_VERSION = 2


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {RiskTier.LOW: 0, RiskTier.MEDIUM: 1, RiskTier.HIGH: 2, RiskTier.CRITICAL: 3}[self]

    @property
    def rank_value(self) -> int:
        return self.rank


class VerdictStatus(str, Enum):
    PASS_WITHIN_SCOPE = "PASS_WITHIN_SCOPE"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INSUFFICIENT_OBSERVABILITY = "INSUFFICIENT_OBSERVABILITY"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    AWAITING_HUMAN = "AWAITING_HUMAN"
    FOUND_STALE = "FOUND_STALE"
    REJECTED_STATE = "REJECTED_STATE"


class TaskState(str, Enum):
    RECEIVED = "RECEIVED"
    PROPOSED = "PROPOSED"
    UNDER_REVIEW = "UNDER_REVIEW"
    AWAITING_HUMAN = "AWAITING_HUMAN"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    WITHHELD = "WITHHELD"
    FAILED = "FAILED"
    FAILED_ROLLBACK_REQUIRED = "FAILED_ROLLBACK_REQUIRED"
    BLOCKED = "BLOCKED"

    @property
    def terminal(self) -> bool:
        return self in {
            TaskState.COMPLETED,
            TaskState.WITHHELD,
            TaskState.FAILED,
            TaskState.FAILED_ROLLBACK_REQUIRED,
            TaskState.BLOCKED,
        }


class FreshnessState(str, Enum):
    CURRENT = "current"
    REVIEW_OVERDUE = "review_overdue"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class EvidenceRef:
    """Evidence as *referenced by a proposal*.

    Note the absence of a caller-supplied ``review_status``: review status,
    signature and freshness are resolved from the EvidenceRegistry, never
    asserted by the worker. ``observed_fields``/``blind_spots`` are descriptive
    hints the registry may cross-check, not trust roots.
    """

    evidence_id: str
    source_id: str = ""
    lineage_id: str = ""
    title: str = ""
    source_url: str = ""
    observed_fields: tuple[str, ...] = ()
    blind_spots: tuple[str, ...] = ()
    retrieved_at: str = ""
    content_hash: str = ""
    observation_method: str = ""
    registry_signature: str = ""
    registry_key_id: str = ""
    review_status: str = ""
    freshness_state: str = ""

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], jsonable(self))

    def to_ref(self) -> EvidenceRef:
        """Convert a fully resolved record into a worker-facing reference."""
        return EvidenceRef(
            evidence_id=self.evidence_id,
            source_id=self.source_id,
            lineage_id=self.lineage_id,
            title=self.title,
            source_url=self.source_url,
            observed_fields=self.observed_fields,
            blind_spots=self.blind_spots,
            retrieved_at=self.retrieved_at,
            content_hash=self.content_hash,
            observation_method=self.observation_method,
        )

    @property
    def signed(self) -> bool:
        return bool(self.registry_signature and self.registry_key_id)


@dataclass(frozen=True)
class Claim:
    claim_id: str
    statement: str
    evidence_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    claim_type: str = "fact"
    scope: str = ""


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    tool: str
    resource: str
    parameters: dict[str, Any] = field(default_factory=dict)
    reversible: bool = True
    expected_result: str = ""

    def fingerprint(self) -> str:
        return digest(self)

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], jsonable(self))


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    title: str
    summary: str
    rationale: str
    claims: tuple[Claim, ...] = ()
    actions: tuple[ActionRequest, ...] = ()
    alternatives: tuple[str, ...] = ()
    consequences_if_done: tuple[str, ...] = ()
    consequences_if_not_done: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    rollback_plan: str = ""
    requested_autonomy: int = 0
    risk_tier: RiskTier = RiskTier.LOW

    def digest(self) -> str:
        """Stable digest binding a human decision, a capability and a ledger event."""
        return digest(self)

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], jsonable(self))

    def core_digest(self) -> str:
        """Digest that ignores descriptive text an approver was shown but need not sign."""
        return digest(
            {
                "proposal_id": self.proposal_id,
                "actions": [action.to_dict() for action in self.actions],
                "risk_tier": self.risk_tier.value,
                "rollback_plan": self.rollback_plan,
            }
        )


@dataclass(frozen=True)
class ApprovalPackage:
    """Exactly what a human is asked to approve, hashable and reviewable."""

    proposal_id: str
    proposal_digest: str
    task_id: str
    package_digest: str
    body: dict[str, Any] = field(default_factory=dict)
    issued_at: str = ""
    expires_at: str = ""

    @classmethod
    def build(
        cls,
        *,
        proposal: Proposal,
        task_id: str,
        body: dict[str, Any],
        issued_at: str,
        ttl_seconds: int,
    ) -> ApprovalPackage:
        package_body = {**body, "proposal_id": proposal.proposal_id, "task_id": task_id}
        return cls(
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest(),
            task_id=task_id,
            package_digest=digest(package_body),
            body=package_body,
            issued_at=issued_at,
            expires_at=_iso_plus(issued_at, ttl_seconds),
        )

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], jsonable(self))


def _iso_plus(iso_timestamp: str, seconds: int) -> str:
    try:
        base = parse_iso(iso_timestamp)
    except ValueError:
        base = datetime.now(UTC)
    shifted = datetime.fromtimestamp(base.timestamp() + seconds, UTC)
    return shifted.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class HumanDecision:
    """Approval bound to one proposal, one task, one human identity and one signature."""

    decision_id: str
    approver: str
    approved: bool
    proposal_digest: str = ""
    task_id: str = ""
    package_digest: str = ""
    decision_digest: str = ""
    restatement: str = ""
    reason: str = ""
    comprehension: dict[str, bool] = field(default_factory=dict)
    decided_at: str = field(default_factory=now_iso)
    expires_at: str = ""
    nonce: str = ""
    signature: str = ""
    key_id: str = ""
    auth_time: str = ""
    amr: tuple[str, ...] = ()

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "decision_id": self.decision_id,
            "approver": self.approver,
            "approved": bool(self.approved),
            "proposal_digest": self.proposal_digest,
            "task_id": self.task_id,
            "package_digest": self.package_digest,
            "restatement": self.restatement,
            "reason": self.reason,
            "comprehension": dict(self.comprehension),
            "decided_at": self.decided_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "auth_time": self.auth_time,
            "amr": list(self.amr),
        }

    def computed_digest(self) -> str:
        """Digest over the approve/reject semantics (not the written justification)."""
        return digest(
            {
                "proposal_digest": self.proposal_digest,
                "task_id": self.task_id,
                "package_digest": self.package_digest,
                "approver": self.approver,
                "approved": bool(self.approved),
                "comprehension": {str(k): bool(v) for k, v in sorted(self.comprehension.items())},
                "decided_at": self.decided_at,
                "expires_at": self.expires_at,
                "nonce": self.nonce,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        payload = cast(dict[str, Any], jsonable(self))
        payload["decision_digest"] = self.computed_digest()
        return payload


@dataclass(frozen=True)
class ReviewFinding:
    role: str
    code: str
    message: str
    blocking: bool = True

    def to_dict(self) -> dict[str, Any]:
        return cast(dict[str, Any], jsonable(self))


@dataclass(frozen=True)
class GateDecision:
    status: VerdictStatus
    allowed: bool
    reasons: tuple[str, ...] = ()
    findings: tuple[ReviewFinding, ...] = ()
    required_human: bool = False
    task_state: TaskState = TaskState.WITHHELD
    execution_results: tuple[dict[str, Any], ...] = ()
    approval_package: dict[str, Any] | None = None
    task_id: str = ""
    proposal_id: str = ""
    proposal_digest: str = ""
    policy_digest: str = ""
    dataset_digest: str = ""
    trace_id: str = ""
    code: str = ""
    decision_digest: str = ""

    def with_context(self, **fields: Any) -> GateDecision:
        return replace(self, **fields)

    def to_dict(self) -> dict[str, Any]:
        data = cast(dict[str, Any], jsonable(self))
        data["status"] = self.status.value
        data["task_state"] = self.task_state.value
        return data

    def summary(self) -> dict[str, Any]:
        """Short, stable summary used by CLIs and audit exports."""
        return {
            "verdict": self.status.value,
            "allowed": self.allowed,
            "code": self.code,
            "task_state": self.task_state.value,
            "required_human": self.required_human,
            "reasons": list(self.reasons),
            "proposal_digest": self.proposal_digest,
            "policy_digest": self.policy_digest,
        }


@dataclass
class TaskRecord:
    task_id: str
    requester: str
    goal: str
    state: TaskState = TaskState.RECEIVED
    proposal_id: str = ""
    proposal_digest: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    trace_id: str = ""
    transitions: tuple[str, ...] = ()

    def set_state(self, state: TaskState) -> None:
        self.state = state
        self.updated_at = now_iso()
        self.transitions = (*self.transitions, f"{state.value}@{self.updated_at}")

    def to_dict(self) -> dict[str, Any]:
        data = cast(dict[str, Any], jsonable(self))
        data["state"] = self.state.value
        return data


def proposal_fingerprint(proposal: Proposal) -> str:
    """Backwards-compatible helper name used by older call sites/tests."""
    return proposal.digest()


def evidence_ref_from_dict(data: Mapping[str, Any]) -> EvidenceRef:
    known = {f.name for f in EvidenceRef.__dataclass_fields__.values()}
    payload = {key: value for key, value in data.items() if key in known}
    for key in ("observed_fields", "blind_spots"):
        if key in payload and isinstance(payload[key], list):
            payload[key] = tuple(payload[key])
    return EvidenceRef(**payload)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = [
    "LEDGER_EVENT_SCHEMA_VERSION",
    "TASK_SCHEMA_VERSION",
    "ActionRequest",
    "ApprovalPackage",
    "Claim",
    "EvidenceRef",
    "FreshnessState",
    "GateDecision",
    "HumanDecision",
    "Proposal",
    "ReviewFinding",
    "RiskTier",
    "TaskRecord",
    "TaskState",
    "VerdictStatus",
    "canonical_json",
    "evidence_ref_from_dict",
    "now_iso",
    "parse_iso",
    "proposal_fingerprint",
]
