"""The deterministic boundary around untrusted AI workers.

Workers propose; this plane checks signed evidence and policy; only the execution
domain receives narrow, task-bound capabilities; consequential approval is a
signed human decision bound to one proposal; everything is written to a
tamper-evident ledger.

Audit fixes implemented here:

* W-01 approval binding (proposal/task digests, expiry, signature, replay guard)
* W-02 signed evidence registry instead of caller-asserted review status
* W-03 freshness gating on every lookup and review
* W-08 kill switch checked before each action and able to revoke capabilities
* W-15 no raw exceptions for lifecycle errors: a typed GateDecision instead
"""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict

from .canonical import digest, sha256_text
from .capability import CapabilityBroker
from .errors import ConfigurationError, StateError, WhyWardError
from .evidence import KnowledgeStore
from .execution import SandboxExecutor
from .identity import Keyring, sign_payload, verify_signature
from .ledger import Ledger
from .models import (
    ApprovalPackage,
    EvidenceRef,
    GateDecision,
    HumanDecision,
    Proposal,
    RiskTier,
    TaskRecord,
    TaskState,
    VerdictStatus,
    now_iso,
    parse_iso,
)
from .observability import Metrics, StructuredLogger
from .policy import Policy
from .registry import EvidenceRegistry
from .review import has_blockers, review_proposal, verdict_for_findings
from .version import __version__
from .workers import Worker


class DecisionContext(TypedDict):
    """Fields every GateDecision carries so an audit trail can be reconstructed."""

    task_id: str
    proposal_id: str
    proposal_digest: str
    policy_digest: str
    dataset_digest: str
    trace_id: str


_ALLOWED_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.RECEIVED: frozenset({TaskState.PROPOSED, TaskState.BLOCKED}),
    TaskState.PROPOSED: frozenset({TaskState.UNDER_REVIEW, TaskState.BLOCKED}),
    TaskState.UNDER_REVIEW: frozenset(
        {TaskState.AWAITING_HUMAN, TaskState.AUTHORIZED, TaskState.WITHHELD, TaskState.BLOCKED}
    ),
    TaskState.AWAITING_HUMAN: frozenset({TaskState.AUTHORIZED, TaskState.WITHHELD, TaskState.BLOCKED}),
    TaskState.AUTHORIZED: frozenset({TaskState.EXECUTING, TaskState.VERIFYING, TaskState.BLOCKED}),
    TaskState.EXECUTING: frozenset(
        {TaskState.VERIFYING, TaskState.FAILED, TaskState.FAILED_ROLLBACK_REQUIRED, TaskState.BLOCKED}
    ),
    TaskState.VERIFYING: frozenset(
        {TaskState.COMPLETED, TaskState.FAILED, TaskState.FAILED_ROLLBACK_REQUIRED}
    ),
    TaskState.COMPLETED: frozenset(),
    TaskState.WITHHELD: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.FAILED_ROLLBACK_REQUIRED: frozenset(),
    TaskState.BLOCKED: frozenset(),
}


class ControlPlane:
    def __init__(
        self,
        *,
        policy: Policy,
        ledger: Ledger,
        capability_broker: CapabilityBroker | None = None,
        executor: SandboxExecutor | None = None,
        knowledge_store: KnowledgeStore | None = None,
        evidence_registry: EvidenceRegistry | None = None,
        kill_switch_file: str | Path | None = None,
        keyring: Keyring | None = None,
        approval_key_id: str = "approval-authority",
        approval_keyring: Keyring | None = None,
        require_signed_approval: bool | None = None,
        clock: Callable[[], datetime] | None = None,
        logger: StructuredLogger | None = None,
        metrics: Metrics | None = None,
        auto_register_catalog: bool | None = None,
    ):
        self.policy = policy
        self.ledger = ledger
        self.capability_broker = capability_broker
        self.executor = executor
        self.knowledge_store = knowledge_store
        self.kill_switch_file = Path(kill_switch_file) if kill_switch_file else None
        self.keyring = keyring
        self.approval_key_id = approval_key_id
        self.approval_keyring = approval_keyring or keyring
        self.require_signed_approval = (
            policy.review.require_human_decision_signature
            if require_signed_approval is None
            else require_signed_approval
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self.logger = logger or StructuredLogger()
        self.metrics = metrics or Metrics()
        self._lock = threading.Lock()
        self._engaged = False

        registry = evidence_registry
        if registry is None and knowledge_store is not None and policy.profile == "dev":
            registry = self._build_dev_registry(knowledge_store)
        self.evidence_registry = registry

        self.logger.info(
            "control_plane_start",
            profile=policy.profile,
            policy_digest=policy.digest(),
            dataset_version=knowledge_store.dataset_version if knowledge_store else None,
            dataset_digest=knowledge_store.dataset_digest if knowledge_store else None,
            evidence_registry=bool(registry),
            signed_approval=self.require_signed_approval,
            version=__version__,
        )
        if policy.profile == "dev":
            self.logger.warning(
                "dev_profile_active",
                detail=(
                    "Development profile: demo fixtures accepted and run_python may be enabled. "
                    "Do not deploy this profile."
                ),
            )

    # ------------------------------------------------------------------ #
    # Wiring helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _build_dev_registry(store: KnowledgeStore) -> EvidenceRegistry:
        registry = EvidenceRegistry(keyring=Keyring.demo(), signing_key_id="demo-manifest-2026")
        for record in store.records:
            registry.register_from_catalog(catalog_record=record, review_status="demo_verified")
        return registry

    @property
    def now(self) -> datetime:
        return self._clock()

    def register_evidence(self, evidence: EvidenceRef | Mapping[str, Any]) -> None:
        """Deprecated path kept for compatibility.

        Audit finding W-02: a caller-asserted ``review_status`` is never trusted.
        Anything registered here is re-signed by the registry *and* downgraded to
        ``unverified`` unless it already carries a valid registry signature.
        """
        if self.evidence_registry is None:
            raise ConfigurationError(
                "No EvidenceRegistry is configured; unsigned evidence cannot be trusted",
                code="NO_EVIDENCE_REGISTRY",
            )
        data = evidence.to_dict() if isinstance(evidence, EvidenceRef) else dict(evidence)
        # A caller can never certify its own evidence: force the untrusted status.
        data["review_status"] = "unverified"
        data["evidence_id"] = str(data.get("evidence_id", ""))
        data["source_id"] = str(data.get("source_id", ""))
        data["lineage_id"] = str(data.get("lineage_id", ""))
        data["retrieved_at"] = str(data.get("retrieved_at", "")) or now_iso()
        self.evidence_registry.register(data)

    def register_reviewed_evidence(
        self,
        *,
        evidence_id: str,
        source_id: str,
        lineage_id: str,
        retrieved_at: str,
        observed_fields: tuple[str, ...],
        blind_spots: tuple[str, ...],
        review_status: str = "verified",
        title: str = "",
        source_url: str = "",
        freshness: Mapping[str, Any] | None = None,
        observation_method: str = "",
    ) -> None:
        """Trusted ingestion entry point (control core / pipeline only)."""
        if self.evidence_registry is None:
            raise ConfigurationError("No EvidenceRegistry is configured", code="NO_EVIDENCE_REGISTRY")
        self.evidence_registry.register(
            {
                "evidence_id": evidence_id,
                "source_id": source_id,
                "lineage_id": lineage_id,
                "retrieved_at": retrieved_at,
                "observed_fields": list(observed_fields),
                "blind_spots": list(blind_spots),
                "review_status": review_status,
                "title": title,
                "source_url": source_url,
                "freshness": dict(freshness or {}),
                "observation_method": observation_method,
            }
        )

    # ------------------------------------------------------------------ #
    # Task lifecycle
    # ------------------------------------------------------------------ #
    def create_task(self, task_id: str, requester: str, goal: str, *, trace_id: str = "") -> TaskRecord:
        task = TaskRecord(task_id=task_id, requester=requester, goal=goal, trace_id=trace_id)
        self._event(
            "TASK_RECEIVED",
            {"kind": "requester", "subject": requester},
            {
                "task_id": task_id,
                "goal_sha256": hashlib.sha256(goal.encode("utf-8")).hexdigest(),
                "goal_excerpt": goal[:280],
            },
            trace_id=trace_id,
        )
        return task

    def _transition(self, task: TaskRecord, new_state: TaskState) -> None:
        if task.state == new_state:
            return
        if new_state not in _ALLOWED_TRANSITIONS[task.state]:
            raise StateError(
                f"Illegal task transition: {task.state.value} -> {new_state.value}",
                code="ILLEGAL_TRANSITION",
                details={"task_id": task.task_id, "from": task.state.value, "to": new_state.value},
            )
        task.set_state(new_state)

    def _event(
        self,
        event_type: str,
        actor: str | Mapping[str, Any],
        payload: Mapping[str, Any],
        *,
        trace_id: str = "",
    ) -> dict[str, Any]:
        return self.ledger.append(event_type, actor, payload, trace_id=trace_id)

    # ------------------------------------------------------------------ #
    # Kill switch
    # ------------------------------------------------------------------ #
    def kill_switch_engaged(self) -> bool:
        if os.environ.get("WHYWARD_KILL_SWITCH") == "1":
            return True
        if self._engaged:
            return True
        return bool(self.kill_switch_file and self.kill_switch_file.exists())

    def engage_kill_switch(self, reason: str, *, actor: str = "operator") -> dict[str, Any]:
        self._engaged = True
        if self.kill_switch_file is not None:
            self.kill_switch_file.parent.mkdir(parents=True, exist_ok=True)
            self.kill_switch_file.write_text(f"{now_iso()} {reason}\n", encoding="utf-8")
        revoked = self.capability_broker.revoke_all() if self.capability_broker else 0
        self.metrics.counter("kill_switch_engaged_total")
        self.logger.warning("kill_switch_engaged", reason=reason, revoked=revoked)
        return self._event(
            "KILL_SWITCH_ENGAGED",
            {"kind": "human", "subject": actor},
            {"reason": reason, "revoked_capabilities": revoked},
        )

    def release_kill_switch(self, *, actor: str = "operator") -> dict[str, Any]:
        self._engaged = False
        if self.kill_switch_file is not None and self.kill_switch_file.exists():
            self.kill_switch_file.unlink()
        return self._event(
            "KILL_SWITCH_RELEASED", {"kind": "human", "subject": actor}, {"released_at": now_iso()}
        )

    # ------------------------------------------------------------------ #
    # Human approval
    # ------------------------------------------------------------------ #
    def _human_required(self, proposal: Proposal) -> bool:
        return self.policy.human_required(
            proposal.risk_tier,
            [action.tool for action in proposal.actions],
            proposal.requested_autonomy,
            all(action.reversible for action in proposal.actions),
        )

    def approval_package(
        self, proposal: Proposal, findings: tuple[Any, ...], *, task_id: str = ""
    ) -> ApprovalPackage:
        body: dict[str, Any] = {
            "title": proposal.title,
            "what_will_happen": proposal.summary,
            "why": proposal.rationale,
            "alternatives_considered": list(proposal.alternatives),
            "consequences_if_done": list(proposal.consequences_if_done),
            "consequences_if_not_done": list(proposal.consequences_if_not_done),
            "unknowns": list(proposal.unknowns),
            "rollback_or_compensation": proposal.rollback_plan,
            "requested_autonomy": proposal.requested_autonomy,
            "risk_tier": proposal.risk_tier.value,
            "actions": [
                {
                    "action_id": action.action_id,
                    "tool": action.tool,
                    "resource": action.resource,
                    "reversible": action.reversible,
                    "expected_result": action.expected_result,
                    "parameters_sha256": digest(action.parameters),
                }
                for action in proposal.actions
            ],
            "review_findings": [finding.to_dict() for finding in findings],
            "human_must_understand": ["action", "consequence", "rollback"],
            "policy_digest": self.policy.digest(),
        }
        return ApprovalPackage.build(
            proposal=proposal,
            task_id=task_id,
            body=body,
            issued_at=self.now.isoformat().replace("+00:00", "Z"),
            ttl_seconds=self.policy.review.approval_ttl_seconds,
        )

    def _decision_digest_used(self, decision_digest: str) -> bool:
        for event in self.ledger.iter_events():
            if event.get("event_type") != "HUMAN_DECISION_RECORDED":
                continue
            payload = event.get("payload", {})
            if isinstance(payload, Mapping) and payload.get("decision_digest") == decision_digest:
                return True
        return False

    def verify_human_decision(
        self,
        decision: HumanDecision,
        *,
        proposal: Proposal,
        task: TaskRecord,
        package: ApprovalPackage,
    ) -> tuple[str, ...]:
        """Return blocking problem codes. Empty tuple means the approval is usable."""
        problems: list[str] = []
        if not str(decision.approver).strip():
            problems.append("DECISION_NO_APPROVER: approver identity is missing.")
        if decision.proposal_digest != proposal.digest():
            problems.append(
                "DECISION_NOT_BOUND: approval digest does not match the proposal being executed."
            )
        if decision.task_id != task.task_id:
            problems.append("DECISION_WRONG_TASK: approval was issued for a different task.")
        if decision.package_digest and decision.package_digest != package.package_digest:
            problems.append("DECISION_STALE_PACKAGE: approval was given for a different review package.")
        if len(decision.restatement.strip()) < self.policy.review.min_restatement_chars:
            problems.append("DECISION_NO_RESTATEMENT: approver must restate the decision in their own words.")
        required = {"action", "consequence", "rollback"}
        missing = sorted(key for key in required if decision.comprehension.get(key) is not True)
        if missing:
            problems.append(f"DECISION_NO_COMPREHENSION: comprehension not recorded for: {', '.join(missing)}.")
        if proposal.risk_tier == RiskTier.CRITICAL and not decision.reason.strip():
            problems.append("DECISION_NO_REASON: critical decisions require an explicit reason.")
        expires_at = decision.expires_at or package.expires_at
        if expires_at:
            try:
                if self.now > parse_iso(expires_at):
                    problems.append("DECISION_EXPIRED: approval has expired.")
            except ValueError:
                problems.append("DECISION_BAD_EXPIRY: approval expiry is not a valid timestamp.")
        if decision.nonce and self._decision_digest_used(decision.computed_digest()):
            problems.append("DECISION_REPLAYED: this approval was already consumed.")
        if self.require_signed_approval:
            if not decision.signature or not decision.key_id:
                problems.append("DECISION_UNSIGNED: this profile requires a signed approval.")
            else:
                if self.approval_keyring is None or not self.approval_keyring.has(decision.key_id):
                    problems.append("DECISION_UNTRUSTED_KEY: approval signed by an unknown key.")
                else:
                    key = self.approval_keyring.get(decision.key_id)
                    if not verify_signature(key, decision.unsigned_payload(), decision.signature):
                        problems.append("DECISION_BAD_SIGNATURE: approval signature does not verify.")
        return tuple(problems)

    @staticmethod
    def sign_decision(decision: HumanDecision, *, key_id: str, key: bytes) -> HumanDecision:
        """Helper for approval UIs/tests: produce the signature the core will check."""
        from dataclasses import replace

        signature = sign_payload(key, decision.unsigned_payload())
        return replace(decision, key_id=key_id, signature=signature)

    # ------------------------------------------------------------------ #
    # Submission
    # ------------------------------------------------------------------ #
    def run_worker(
        self,
        task: TaskRecord,
        worker: Worker,
        context: dict[str, Any] | None = None,
        human_decision: HumanDecision | None = None,
    ) -> GateDecision:
        proposal = worker.propose(task, context or {})
        return self.submit_proposal(task, proposal, human_decision=human_decision)

    def submit_proposal(
        self,
        task: TaskRecord,
        proposal: Proposal,
        *,
        human_decision: HumanDecision | None = None,
        evidence: Mapping[str, EvidenceRef] | None = None,
        trace_id: str = "",
    ) -> GateDecision:
        if not isinstance(proposal, Proposal):
            # Audit W-15: the boundary must reject malformed proposals with a
            # typed error instead of leaking AttributeError/ValueError.
            raise WhyWardError(
                "submit_proposal expects a Proposal instance; build one with Proposal.from_mapping()",
                code="PROPOSAL_INVALID",
                details={"received": type(proposal).__name__},
            )
        if not isinstance(task, TaskRecord):
            raise WhyWardError(
                "submit_proposal expects a TaskRecord from create_task()",
                code="TASK_INVALID",
                details={"received": type(task).__name__},
            )
        trace_id = trace_id or task.trace_id or digest(f"{task.task_id}:{proposal.proposal_id}")[:32]
        policy_digest = self.policy.digest()
        base: DecisionContext = {
            "task_id": task.task_id,
            "proposal_id": proposal.proposal_id,
            "proposal_digest": proposal.digest(),
            "policy_digest": policy_digest,
            "dataset_digest": self.knowledge_store.dataset_digest if self.knowledge_store else "",
            "trace_id": trace_id,
        }

        if task.state.terminal:
            self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.REJECTED_STATE.value})
            return GateDecision(
                status=VerdictStatus.REJECTED_STATE,
                allowed=False,
                reasons=(f"Task {task.task_id} is already in terminal state {task.state.value}.",),
                task_state=task.state,
                code="TASK_TERMINAL",
                **base,
            )

        if evidence:
            # Audit W-02: caller-supplied evidence is never merged as trusted state.
            self.logger.warning(
                "caller_supplied_evidence_ignored",
                detail="Evidence must be registered through EvidenceRegistry; ignoring submit-time evidence.",
                trace_id=trace_id,
            )

        task.proposal_id = proposal.proposal_id
        task.proposal_digest = proposal.digest()
        task.trace_id = trace_id
        self._transition(task, TaskState.PROPOSED)
        self._event(
            "PROPOSAL_RECEIVED",
            {"kind": "worker", "subject": task.requester},
            {
                "task_id": task.task_id,
                "proposal_id": proposal.proposal_id,
                "proposal_digest": base["proposal_digest"],
                "policy_digest": policy_digest,
                "dataset_digest": base["dataset_digest"],
                "risk_tier": proposal.risk_tier.value,
                "action_count": len(proposal.actions),
                "claim_count": len(proposal.claims),
                "requested_autonomy": proposal.requested_autonomy,
            },
            trace_id=trace_id,
        )
        self._transition(task, TaskState.UNDER_REVIEW)

        if self.kill_switch_engaged():
            self._transition(task, TaskState.BLOCKED)
            self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.BLOCKED_BY_POLICY.value})
            self._event(
                "TASK_BLOCKED_KILL_SWITCH",
                {"kind": "control-core", "subject": "kill-switch"},
                {"task_id": task.task_id, "proposal_digest": base["proposal_digest"]},
                trace_id=trace_id,
            )
            return GateDecision(
                status=VerdictStatus.BLOCKED_BY_POLICY,
                allowed=False,
                reasons=("WhyWard kill switch is engaged.",),
                task_state=task.state,
                code="KILL_SWITCH_ENGAGED",
                **base,
            )

        if self.evidence_registry is None:
            self._transition(task, TaskState.WITHHELD)
            self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
            return GateDecision(
                status=VerdictStatus.INSUFFICIENT_EVIDENCE,
                allowed=False,
                reasons=("No signed EvidenceRegistry is configured; evidence cannot be trusted.",),
                task_state=task.state,
                code="NO_EVIDENCE_REGISTRY",
                **base,
            )

        findings = review_proposal(proposal, self.evidence_registry, self.policy, now=self.now)
        self._event(
            "PROPOSAL_REVIEWED",
            {"kind": "control-core", "subject": "deterministic-review"},
            {
                "task_id": task.task_id,
                "proposal_id": proposal.proposal_id,
                "proposal_digest": base["proposal_digest"],
                "finding_codes": [finding.code for finding in findings],
                "blocking": has_blockers(findings),
            },
            trace_id=trace_id,
        )
        if has_blockers(findings):
            verdict = verdict_for_findings(findings)
            status = (
                VerdictStatus.BLOCKED_BY_POLICY
                if verdict == "BLOCKED_BY_POLICY"
                else VerdictStatus.INSUFFICIENT_EVIDENCE
            )
            self._transition(task, TaskState.WITHHELD)
            self.metrics.counter("gate_decisions_total", labels={"verdict": status.value})
            return GateDecision(
                status=status,
                allowed=False,
                reasons=tuple(finding.message for finding in findings if finding.blocking),
                findings=findings,
                task_state=task.state,
                code=verdict,
                **base,
            )

        if self._human_required(proposal):
            package = self.approval_package(proposal, findings, task_id=task.task_id)
            if human_decision is None:
                self._transition(task, TaskState.AWAITING_HUMAN)
                self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.AWAITING_HUMAN.value})
                return GateDecision(
                    status=VerdictStatus.AWAITING_HUMAN,
                    allowed=False,
                    reasons=("A signed human decision bound to this proposal is required.",),
                    findings=findings,
                    required_human=True,
                    task_state=task.state,
                    approval_package=package.to_dict(),
                    code="HUMAN_APPROVAL_REQUIRED",
                    **base,
                )
            problems = self.verify_human_decision(
                human_decision, proposal=proposal, task=task, package=package
            )
            self._event(
                "HUMAN_DECISION_RECORDED",
                {"kind": "human", "subject": human_decision.approver or "unknown"},
                {
                    "task_id": task.task_id,
                    "proposal_id": proposal.proposal_id,
                    "proposal_digest": base["proposal_digest"],
                    "decision_digest": human_decision.computed_digest(),
                    "decision_id": human_decision.decision_id,
                    "approved": bool(human_decision.approved),
                    "key_id": human_decision.key_id,
                    "problems": list(problems),
                },
                trace_id=trace_id,
            )
            if problems:
                self._transition(task, TaskState.AWAITING_HUMAN)
                self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.AWAITING_HUMAN.value})
                return GateDecision(
                    status=VerdictStatus.AWAITING_HUMAN,
                    allowed=False,
                    reasons=problems,
                    findings=findings,
                    required_human=True,
                    task_state=task.state,
                    approval_package=package.to_dict(),
                    code="APPROVAL_REJECTED",
                    **base,
                )
            if not human_decision.approved:
                self._transition(task, TaskState.WITHHELD)
                self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.BLOCKED_BY_POLICY.value})
                return GateDecision(
                    status=VerdictStatus.BLOCKED_BY_POLICY,
                    allowed=False,
                    reasons=("Human approver rejected the proposal.",),
                    findings=findings,
                    required_human=True,
                    task_state=task.state,
                    approval_package=package.to_dict(),
                    code="HUMAN_REJECTED",
                    **base,
                )

        self._transition(task, TaskState.AUTHORIZED)
        results: list[dict[str, Any]] = []
        if proposal.actions:
            if self.executor is None or self.capability_broker is None:
                self._transition(task, TaskState.BLOCKED)
                self.metrics.counter(
                    "gate_decisions_total",
                    labels={"verdict": VerdictStatus.INSUFFICIENT_OBSERVABILITY.value},
                )
                return GateDecision(
                    status=VerdictStatus.INSUFFICIENT_OBSERVABILITY,
                    allowed=False,
                    reasons=("No execution domain/capability broker is configured for side-effecting actions.",),
                    findings=findings,
                    required_human=self._human_required(proposal),
                    task_state=task.state,
                    code="NO_EXECUTION_DOMAIN",
                    **base,
                )
            self._transition(task, TaskState.EXECUTING)
            token = self.capability_broker.issue(
                proposal_id=proposal.proposal_id,
                actions=proposal.actions,
                task_id=task.task_id,
                proposal_digest=base["proposal_digest"],
                ttl_seconds=self.policy.review.approval_ttl_seconds + 60,
            )
            try:
                for action in proposal.actions:
                    if self.kill_switch_engaged():
                        raise StateError(
                            "Kill switch engaged while executing", code="KILL_SWITCH_ENGAGED"
                        )
                    result = self.executor.execute(action, token)
                    results.append(result)
                    self._event(
                        "ACTION_EXECUTED",
                        {"kind": "execution-domain", "subject": "sandbox"},
                        {
                            "task_id": task.task_id,
                            "proposal_id": proposal.proposal_id,
                            "proposal_digest": base["proposal_digest"],
                            "action_id": action.action_id,
                            "action_fingerprint": action.fingerprint(),
                            "ok": bool(result.get("ok")),
                            "readback_sha256": result.get("readback_sha256", ""),
                            "bytes": result.get("bytes", result.get("bytes_read", 0)),
                            "pre_image": result.get("pre_image"),
                        },
                        trace_id=trace_id,
                    )
            except Exception as exc:
                code = getattr(exc, "code", type(exc).__name__)
                self._event(
                    "EXECUTION_FAILED",
                    {"kind": "execution-domain", "subject": "sandbox"},
                    {
                        "task_id": task.task_id,
                        "proposal_id": proposal.proposal_id,
                        "proposal_digest": base["proposal_digest"],
                        "error_code": code,
                        "error": f"{type(exc).__name__}: {exc}",
                        "executed": len(results),
                    },
                    trace_id=trace_id,
                )
                final_state = (
                    TaskState.FAILED_ROLLBACK_REQUIRED
                    if results and any(item.get("ok") for item in results)
                    else TaskState.FAILED
                )
                self._transition(task, final_state)
                self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.FAIL.value})
                return GateDecision(
                    status=VerdictStatus.FAIL,
                    allowed=False,
                    reasons=(f"Execution failed [{code}]: {exc}",),
                    findings=findings,
                    required_human=self._human_required(proposal),
                    task_state=task.state,
                    execution_results=tuple(results),
                    code=code,
                    **base,
                )
            self._transition(task, TaskState.VERIFYING)
            if not all(bool(item.get("ok")) for item in results):
                final_state = (
                    TaskState.FAILED_ROLLBACK_REQUIRED
                    if any(item.get("ok") for item in results)
                    else TaskState.FAILED
                )
                self._transition(task, final_state)
                self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.FAIL.value})
                return GateDecision(
                    status=VerdictStatus.FAIL,
                    allowed=False,
                    reasons=("Read-back or execution verification failed.",),
                    findings=findings,
                    required_human=self._human_required(proposal),
                    task_state=task.state,
                    execution_results=tuple(results),
                    code="READBACK_MISMATCH",
                    **base,
                )
        else:
            self._transition(task, TaskState.VERIFYING)

        self._transition(task, TaskState.COMPLETED)
        decision_digest = digest(
            {
                "status": VerdictStatus.PASS_WITHIN_SCOPE.value,
                "task_id": task.task_id,
                "proposal_digest": base["proposal_digest"],
                "policy_digest": policy_digest,
                "results": results,
            }
        )
        self._event(
            "TASK_COMPLETED_WITHIN_SCOPE",
            {"kind": "control-core", "subject": "gate"},
            {
                "task_id": task.task_id,
                "proposal_id": proposal.proposal_id,
                "proposal_digest": base["proposal_digest"],
                "decision_digest": decision_digest,
                "executed_actions": len(results),
            },
            trace_id=trace_id,
        )
        self.metrics.counter("gate_decisions_total", labels={"verdict": VerdictStatus.PASS_WITHIN_SCOPE.value})
        self.logger.info(
            "task_completed",
            task_id=task.task_id,
            proposal_digest=base["proposal_digest"],
            actions=len(results),
            trace_id=trace_id,
        )
        return GateDecision(
            status=VerdictStatus.PASS_WITHIN_SCOPE,
            allowed=True,
            reasons=("Proposal passed the configured checks and read-back verification within scope.",),
            findings=findings,
            required_human=self._human_required(proposal),
            task_state=task.state,
            execution_results=tuple(results),
            code="PASS_WITHIN_SCOPE",
            decision_digest=decision_digest,
            **base,
        )

    # ------------------------------------------------------------------ #
    # Knowledge lookup
    # ------------------------------------------------------------------ #
    def answer_question(
        self,
        question: str,
        *,
        actor: str = "user",
        trace_id: str = "",
        domain: str | None = None,
    ) -> dict[str, Any]:
        question_hash = sha256_text(question)
        trace_id = trace_id or digest(question_hash)[:32]
        if self.kill_switch_engaged():
            self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.BLOCKED_BY_POLICY.value})
            self._event(
                "LOOKUP_BLOCKED",
                {"kind": "client", "subject": actor},
                {"question_sha256": question_hash},
                trace_id=trace_id,
            )
            return {
                "verdict": VerdictStatus.BLOCKED_BY_POLICY.value,
                "answer": None,
                "reasons": ["WhyWard kill switch is engaged."],
                "code": "KILL_SWITCH_ENGAGED",
                "trace_id": trace_id,
            }
        if self.knowledge_store is None:
            self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
            self._event(
                "LOOKUP_WITHHELD",
                {"kind": "client", "subject": actor},
                {"question_sha256": question_hash, "reason": "no_store"},
                trace_id=trace_id,
            )
            return {
                "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                "answer": None,
                "reasons": ["No reviewed knowledge store is configured."],
                "code": "NO_KNOWLEDGE_STORE",
                "trace_id": trace_id,
            }
        if self.evidence_registry is None:
            self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_OBSERVABILITY.value})
            return {
                "verdict": VerdictStatus.INSUFFICIENT_OBSERVABILITY.value,
                "answer": None,
                "reasons": ["No signed EvidenceRegistry is configured; provenance cannot be verified."],
                "code": "NO_EVIDENCE_REGISTRY",
                "trace_id": trace_id,
            }

        lookup = self.knowledge_store.answer_query(
            question,
            domain=domain,
            accepted_review_statuses=self.policy.accepted_review_statuses,
            now=self.now,
            reject_stale=self.policy.review.reject_stale_on_read,
        )
        base = {
            "lookup": lookup.to_dict(),
            "dataset_version": lookup.dataset_version,
            "dataset_digest": lookup.dataset_digest,
            "trace_id": trace_id,
        }

        if lookup.record is not None:
            try:
                record = self.evidence_registry.get(f"catalog:{lookup.record['record_id']}")
            except Exception as exc:
                code = getattr(exc, "code", "EVIDENCE_UNAVAILABLE")
                self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
                self._event(
                    "LOOKUP_WITHHELD",
                    {"kind": "client", "subject": actor},
                    {
                        "question_sha256": question_hash,
                        "reason": code,
                        "record_id": str(lookup.record.get("record_id", "")),
                        "dataset_digest": lookup.dataset_digest,
                    },
                    trace_id=trace_id,
                )
                return {
                    "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                    "answer": None,
                    "reasons": [f"Catalog record is not backed by registered evidence [{code}]."],
                    "code": code,
                    **base,
                }

            if record.source_id not in self.policy.allowed_source_ids:
                self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
                self._event(
                    "LOOKUP_WITHHELD",
                    {"kind": "client", "subject": actor},
                    {
                        "question_sha256": question_hash,
                        "reason": "source_not_allowlisted",
                        "source_id": record.source_id,
                    },
                    trace_id=trace_id,
                )
                return {
                    "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                    "answer": None,
                    "reasons": [f"Record source is not allowlisted: {record.source_id or 'unknown'}"],
                    "code": "SOURCE_NOT_ALLOWLISTED",
                    **base,
                }

            freshness = record.freshness_state(
                now=self.now, max_age_seconds_by_class=self.policy.evidence.max_age_seconds_by_class
            )
            if freshness.value == "expired":
                self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
                self._event(
                    "LOOKUP_WITHHELD",
                    {"kind": "client", "subject": actor},
                    {"question_sha256": question_hash, "reason": "evidence_expired"},
                    trace_id=trace_id,
                )
                return {
                    "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                    "answer": None,
                    "reasons": ["Evidence behind this record is past its valid_until window (STALE_AFTER)."],
                    "code": "EVIDENCE_EXPIRED",
                    **base,
                }
            if record.review_status not in self.policy.accepted_review_statuses:
                self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
                return {
                    "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                    "answer": None,
                    "reasons": [
                        f"Evidence review status {record.review_status!r} is not accepted by this profile."
                    ],
                    "code": "EVIDENCE_NOT_REVIEWED",
                    **base,
                }
        else:
            record = None

        if (
            lookup.status in {"FOUND", "FOUND_SCOPED", "FOUND_STALE"}
            and lookup.record is not None
            and record is not None
        ):
            evidence_ref = record.to_ref()
            entity = lookup.record.get("entity", {})
            name = (
                entity.get("canonical_name", lookup.record.get("record_id", ""))
                if isinstance(entity, Mapping)
                else ""
            )
            caveat = ""
            if lookup.status == "FOUND_SCOPED":
                caveat = " (trong phạm vi catalog hiện có)"
            if lookup.status == "FOUND_STALE":
                caveat = " (bằng chứng đã quá hạn review)"
            if lookup.attribute:
                answer = f"{name}: {lookup.attribute} = {lookup.value}{caveat}."
            else:
                answer = f"Tìm thấy record {name}{caveat}."
            verdict = (
                VerdictStatus.FOUND_STALE
                if lookup.status == "FOUND_STALE"
                else VerdictStatus.PASS_WITHIN_SCOPE
            )
            self.metrics.counter("lookups_total", labels={"verdict": verdict.value})
            self._event(
                "LOOKUP_ANSWERED",
                {"kind": "client", "subject": actor},
                {
                    "question_sha256": question_hash,
                    "record_id": str(lookup.record.get("record_id", "")),
                    "dataset_version": lookup.dataset_version,
                    "dataset_digest": lookup.dataset_digest,
                    "evidence_id": record.evidence_id,
                    "source_id": record.source_id,
                    "freshness": freshness.value,
                    "verdict": verdict.value,
                },
                trace_id=trace_id,
            )
            return {
                "verdict": verdict.value,
                "answer": answer,
                "evidence": evidence_ref.to_dict(),
                "reasons": list(lookup.reasons),
                "code": "ANSWERED" if verdict is VerdictStatus.PASS_WITHIN_SCOPE else "ANSWERED_STALE",
                **base,
            }

        self.metrics.counter("lookups_total", labels={"verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value})
        self._event(
            "LOOKUP_WITHHELD",
            {"kind": "client", "subject": actor},
            {
                "question_sha256": question_hash,
                "lookup_status": lookup.status,
                "dataset_digest": lookup.dataset_digest,
            },
            trace_id=trace_id,
        )
        return {
            "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
            "answer": None,
            "reasons": list(lookup.reasons) or ["No unique reviewed answer was found."],
            "code": lookup.status,
            **base,
        }

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #
    def status(self) -> dict[str, Any]:
        """Operator-facing state: what is actually enforced right now."""
        valid, message = self.ledger.verify()
        return {
            "system": "WhyWard",
            "version": __version__,
            "policy": {
                "profile": self.policy.profile,
                "digest": self.policy.digest(),
                "require_signed_approval": self.require_signed_approval,
                "require_registry_signature": self.policy.evidence.require_registry_signature,
                "allowed_tools": sorted(self.policy.allowed_tools),
            },
            "evidence": {
                "dataset_version": self.knowledge_store.dataset_version if self.knowledge_store else None,
                "dataset_digest": self.knowledge_store.dataset_digest if self.knowledge_store else None,
                "catalog_signed": self.knowledge_store.signed if self.knowledge_store else None,
                "registry_configured": self.evidence_registry is not None,
                "registry_digest": self.evidence_registry.digest() if self.evidence_registry else None,
                "registry_records": len(self.evidence_registry.all_records()) if self.evidence_registry else 0,
            },
            "execution": {
                "executor": type(self.executor).__name__ if self.executor else None,
                "python_enabled": bool(getattr(self.executor, "allow_python", False)),
                "python_backend": getattr(getattr(self.executor, "backend", None), "name", None),
                "durable_capabilities": bool(getattr(self.capability_broker, "durable", False)),
            },
            "ledger": {"valid": valid, "message": message, "events": self.ledger.event_count, "head": self.ledger.head},
            "kill_switch_engaged": self.kill_switch_engaged(),
        }


__all__ = ["ControlPlane"]
