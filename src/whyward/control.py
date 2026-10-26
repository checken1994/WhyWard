from __future__ import annotations

import hashlib
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping

from .capability import CapabilityBroker
from .evidence import KnowledgeStore
from .execution import SandboxExecutor
from .ledger import Ledger
from .models import (
    EvidenceRef,
    GateDecision,
    HumanDecision,
    Proposal,
    RiskTier,
    TaskRecord,
    TaskState,
    VerdictStatus,
)
from .policy import Policy
from .review import has_blockers, review_proposal
from .workers import Worker


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
    """The deterministic boundary around untrusted AI workers.

    Workers propose; this plane checks evidence and policy; only the
    execution domain receives narrow capabilities; consequential approval
    remains a human decision recorded outside the worker.
    """

    def __init__(
        self,
        *,
        policy: Policy,
        ledger: Ledger,
        capability_broker: CapabilityBroker | None = None,
        executor: SandboxExecutor | None = None,
        knowledge_store: KnowledgeStore | None = None,
        kill_switch_file: str | Path | None = None,
    ):
        self.policy = policy
        self.ledger = ledger
        self.capability_broker = capability_broker
        self.executor = executor
        self.knowledge_store = knowledge_store
        self.kill_switch_file = Path(kill_switch_file) if kill_switch_file else None
        self._evidence: dict[str, EvidenceRef] = {}

    def register_evidence(self, evidence: EvidenceRef) -> None:
        self._evidence[evidence.evidence_id] = evidence

    def create_task(self, task_id: str, requester: str, goal: str) -> TaskRecord:
        task = TaskRecord(task_id=task_id, requester=requester, goal=goal)
        self.ledger.append(
            "TASK_RECEIVED",
            requester,
            {"task_id": task_id, "goal_sha256": hashlib.sha256(goal.encode("utf-8")).hexdigest()},
        )
        return task

    def _transition(self, task: TaskRecord, new_state: TaskState) -> None:
        if task.state == new_state:
            return
        if new_state not in _ALLOWED_TRANSITIONS[task.state]:
            raise ValueError(f"Illegal task transition: {task.state.value} -> {new_state.value}")
        task.set_state(new_state)

    def kill_switch_engaged(self) -> bool:
        if os.environ.get("WHYWARD_KILL_SWITCH") == "1":
            return True
        return bool(self.kill_switch_file and self.kill_switch_file.exists())

    def approval_package(self, proposal: Proposal, findings: tuple) -> dict[str, Any]:
        return {
            "proposal_id": proposal.proposal_id,
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
                }
                for action in proposal.actions
            ],
            "review_findings": [asdict(finding) for finding in findings],
            "human_must_understand": ["action", "consequence", "rollback"],
        }

    @staticmethod
    def _validate_human_decision(decision: HumanDecision, proposal: Proposal) -> tuple[str, ...]:
        problems: list[str] = []
        if not decision.approver.strip():
            problems.append("Approver identity is missing.")
        if len(decision.restatement.strip()) < 20:
            problems.append("Approver must restate the decision in their own words.")
        required = {"action", "consequence", "rollback"}
        missing = sorted(key for key in required if decision.comprehension.get(key) is not True)
        if missing:
            problems.append(f"Approver comprehension is not recorded for: {', '.join(missing)}.")
        if proposal.risk_tier == RiskTier.CRITICAL and not decision.reason.strip():
            problems.append("Critical decisions require an explicit reason.")
        return tuple(problems)

    def _human_required(self, proposal: Proposal) -> bool:
        if proposal.risk_tier in self.policy.human_required_risk_tiers:
            return True
        if proposal.requested_autonomy > self.policy.max_autonomy_without_human:
            return True
        return any(not action.reversible for action in proposal.actions)

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
    ) -> GateDecision:
        if evidence:
            self._evidence.update(evidence)
        task.proposal_id = proposal.proposal_id
        self._transition(task, TaskState.PROPOSED)
        self.ledger.append(
            "PROPOSAL_RECEIVED",
            task.requester,
            {
                "task_id": task.task_id,
                "proposal_id": proposal.proposal_id,
                "risk_tier": proposal.risk_tier.value,
                "action_count": len(proposal.actions),
                "policy_fingerprint": self.policy.fingerprint(),
            },
        )
        self._transition(task, TaskState.UNDER_REVIEW)

        if self.kill_switch_engaged():
            self._transition(task, TaskState.BLOCKED)
            self.ledger.append("TASK_BLOCKED_KILL_SWITCH", "control-core", {"task_id": task.task_id})
            return GateDecision(
                status=VerdictStatus.BLOCKED_BY_POLICY,
                allowed=False,
                reasons=("WhyWard kill switch is engaged.",),
                task_state=task.state,
            )

        findings = review_proposal(proposal, self._evidence, self.policy)
        self.ledger.append(
            "PROPOSAL_REVIEWED",
            "control-core",
            {
                "task_id": task.task_id,
                "proposal_id": proposal.proposal_id,
                "finding_codes": [finding.code for finding in findings],
                "blocking": has_blockers(findings),
            },
        )
        if has_blockers(findings):
            policy_block = any(finding.code == "POLICY_VIOLATION" for finding in findings)
            self._transition(task, TaskState.WITHHELD)
            return GateDecision(
                status=VerdictStatus.BLOCKED_BY_POLICY if policy_block else VerdictStatus.INSUFFICIENT_EVIDENCE,
                allowed=False,
                reasons=tuple(finding.message for finding in findings if finding.blocking),
                findings=findings,
                task_state=task.state,
            )

        if self._human_required(proposal):
            package = self.approval_package(proposal, findings)
            if human_decision is None:
                self._transition(task, TaskState.AWAITING_HUMAN)
                return GateDecision(
                    status=VerdictStatus.AWAITING_HUMAN,
                    allowed=False,
                    reasons=("A human decision with recorded comprehension is required.",),
                    findings=findings,
                    required_human=True,
                    task_state=task.state,
                    approval_package=package,
                )
            problems = self._validate_human_decision(human_decision, proposal)
            self.ledger.append(
                "HUMAN_DECISION_RECORDED",
                human_decision.approver or "unknown",
                {
                    "task_id": task.task_id,
                    "proposal_id": proposal.proposal_id,
                    "approved": human_decision.approved,
                    "decision_id": human_decision.decision_id,
                    "comprehension_problems": list(problems),
                },
            )
            if problems:
                self._transition(task, TaskState.AWAITING_HUMAN)
                return GateDecision(
                    status=VerdictStatus.AWAITING_HUMAN,
                    allowed=False,
                    reasons=problems,
                    findings=findings,
                    required_human=True,
                    task_state=task.state,
                    approval_package=package,
                )
            if not human_decision.approved:
                self._transition(task, TaskState.WITHHELD)
                return GateDecision(
                    status=VerdictStatus.BLOCKED_BY_POLICY,
                    allowed=False,
                    reasons=("Human approver rejected the proposal.",),
                    findings=findings,
                    required_human=True,
                    task_state=task.state,
                    approval_package=package,
                )

        self._transition(task, TaskState.AUTHORIZED)
        results: list[dict[str, Any]] = []
        if proposal.actions:
            if self.executor is None or self.capability_broker is None:
                self._transition(task, TaskState.BLOCKED)
                return GateDecision(
                    status=VerdictStatus.INSUFFICIENT_OBSERVABILITY,
                    allowed=False,
                    reasons=("No execution domain/capability broker is configured for side-effecting actions.",),
                    findings=findings,
                    required_human=self._human_required(proposal),
                    task_state=task.state,
                )
            self._transition(task, TaskState.EXECUTING)
            token = self.capability_broker.issue(proposal_id=proposal.proposal_id, actions=proposal.actions)
            try:
                for action in proposal.actions:
                    result = self.executor.execute(action, token)
                    results.append(result)
                    self.ledger.append(
                        "ACTION_EXECUTED",
                        "execution-domain",
                        {
                            "task_id": task.task_id,
                            "proposal_id": proposal.proposal_id,
                            "action_id": action.action_id,
                            "ok": bool(result.get("ok")),
                        },
                    )
            except Exception as exc:
                self.ledger.append(
                    "EXECUTION_FAILED",
                    "execution-domain",
                    {"task_id": task.task_id, "proposal_id": proposal.proposal_id, "error": f"{type(exc).__name__}: {exc}"},
                )
                final_state = (
                    TaskState.FAILED_ROLLBACK_REQUIRED
                    if results and any(item.get("ok") for item in results)
                    else TaskState.FAILED
                )
                self._transition(task, final_state)
                return GateDecision(
                    status=VerdictStatus.FAIL,
                    allowed=False,
                    reasons=(f"Execution failed: {type(exc).__name__}: {exc}",),
                    findings=findings,
                    required_human=self._human_required(proposal),
                    task_state=task.state,
                    execution_results=tuple(results),
                )
            self._transition(task, TaskState.VERIFYING)
            if not all(bool(item.get("ok")) for item in results):
                final_state = (
                    TaskState.FAILED_ROLLBACK_REQUIRED
                    if any(item.get("ok") for item in results)
                    else TaskState.FAILED
                )
                self._transition(task, final_state)
                return GateDecision(
                    status=VerdictStatus.FAIL,
                    allowed=False,
                    reasons=("Read-back or execution verification failed.",),
                    findings=findings,
                    required_human=self._human_required(proposal),
                    task_state=task.state,
                    execution_results=tuple(results),
                )
        else:
            self._transition(task, TaskState.VERIFYING)

        self._transition(task, TaskState.COMPLETED)
        self.ledger.append(
            "TASK_COMPLETED_WITHIN_SCOPE",
            "control-core",
            {"task_id": task.task_id, "proposal_id": proposal.proposal_id},
        )
        return GateDecision(
            status=VerdictStatus.PASS_WITHIN_SCOPE,
            allowed=True,
            reasons=("Proposal passed the configured checks and read-back verification within scope.",),
            findings=findings,
            required_human=self._human_required(proposal),
            task_state=task.state,
            execution_results=tuple(results),
        )

    def answer_question(self, question: str, *, actor: str = "user") -> dict[str, Any]:
        question_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()
        if self.kill_switch_engaged():
            result = {
                "verdict": VerdictStatus.BLOCKED_BY_POLICY.value,
                "answer": None,
                "reasons": ["WhyWard kill switch is engaged."],
            }
            self.ledger.append("LOOKUP_BLOCKED", actor, {"question_sha256": question_hash})
            return result
        if self.knowledge_store is None:
            result = {
                "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                "answer": None,
                "reasons": ["No reviewed knowledge store is configured."],
            }
            self.ledger.append("LOOKUP_WITHHELD", actor, {"question_sha256": question_hash, "reason": "no_store"})
            return result

        lookup = self.knowledge_store.answer_query(
            question,
            accepted_review_statuses=self.policy.accepted_review_statuses,
        )
        if lookup.record is not None:
            evidence = lookup.record.get("evidence", {})
            source_id = str(evidence.get("source_id", "")) if isinstance(evidence, Mapping) else ""
            if source_id not in self.policy.allowed_source_ids:
                result = {
                    "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
                    "answer": None,
                    "lookup": lookup.to_dict(),
                    "reasons": [f"Record source is not allowlisted: {source_id or 'unknown'}"],
                }
                self.ledger.append(
                    "LOOKUP_WITHHELD",
                    actor,
                    {"question_sha256": question_hash, "reason": "source_not_allowlisted"},
                )
                return result

        if lookup.status in {"FOUND", "FOUND_SCOPED"} and lookup.record is not None:
            evidence_ref = self.knowledge_store.evidence_for_record(lookup.record)
            self.register_evidence(evidence_ref)
            entity = lookup.record.get("entity", {})
            name = entity.get("canonical_name", lookup.record.get("record_id", "")) if isinstance(entity, Mapping) else ""
            caveat = ""
            if lookup.status == "FOUND_SCOPED":
                caveat = " (trong phạm vi catalog hiện có)"
            if lookup.attribute:
                answer = f"{name}: {lookup.attribute} = {lookup.value}{caveat}."
            else:
                answer = f"Tìm thấy record {name}{caveat}."
            result = {
                "verdict": VerdictStatus.PASS_WITHIN_SCOPE.value,
                "answer": answer,
                "lookup": lookup.to_dict(),
                "evidence": evidence_ref.to_dict(),
                "reasons": list(lookup.reasons),
            }
            self.ledger.append(
                "LOOKUP_ANSWERED",
                actor,
                {
                    "question_sha256": question_hash,
                    "record_id": str(lookup.record.get("record_id", "")),
                    "dataset_version": lookup.dataset_version,
                },
            )
            return result

        result = {
            "verdict": VerdictStatus.INSUFFICIENT_EVIDENCE.value,
            "answer": None,
            "lookup": lookup.to_dict(),
            "reasons": list(lookup.reasons) or ["No unique reviewed answer was found."],
        }
        self.ledger.append(
            "LOOKUP_WITHHELD",
            actor,
            {"question_sha256": question_hash, "lookup_status": lookup.status},
        )
        return result
