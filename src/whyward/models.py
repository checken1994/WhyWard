from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictStatus(str, Enum):
    PASS_WITHIN_SCOPE = "PASS_WITHIN_SCOPE"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INSUFFICIENT_OBSERVABILITY = "INSUFFICIENT_OBSERVABILITY"
    NOT_VERIFIED = "NOT_VERIFIED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    AWAITING_HUMAN = "AWAITING_HUMAN"


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


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    source_id: str
    lineage_id: str
    title: str = ""
    source_url: str = ""
    observed_fields: tuple[str, ...] = ()
    blind_spots: tuple[str, ...] = ()
    retrieved_at: str = ""
    content_hash: str = ""
    review_status: str = "unverified"
    observation_method: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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


@dataclass(frozen=True)
class HumanDecision:
    decision_id: str
    approver: str
    approved: bool
    restatement: str = ""
    reason: str = ""
    comprehension: dict[str, bool] = field(default_factory=dict)
    decided_at: str = field(default_factory=now_iso)


@dataclass(frozen=True)
class ReviewFinding:
    role: str
    code: str
    message: str
    blocking: bool = True


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

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["task_state"] = self.task_state.value
        return data


@dataclass
class TaskRecord:
    task_id: str
    requester: str
    goal: str
    state: TaskState = TaskState.RECEIVED
    proposal_id: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def set_state(self, state: TaskState) -> None:
        self.state = state
        self.updated_at = now_iso()
