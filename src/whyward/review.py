"""Deterministic review roles.

Every finding is produced by code that can be tested. Review never asks a model
for an opinion, and it never trusts a status a worker declared about itself:
evidence is resolved through the signed EvidenceRegistry (audit finding W-02).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

from .errors import EvidenceError
from .models import EvidenceRef, FreshnessState, Proposal, ReviewFinding, RiskTier
from .policy import Policy
from .registry import EvidenceRecord, EvidenceRegistry

EVIDENCE_FINDING_CODES = frozenset(
    {
        "CLAIM_WITHOUT_EVIDENCE",
        "UNKNOWN_EVIDENCE",
        "UNSIGNED_EVIDENCE",
        "EVIDENCE_NOT_REVIEWED",
        "EVIDENCE_STALE",
        "SOURCE_NOT_ALLOWLISTED",
        "INSUFFICIENT_INDEPENDENT_LINEAGES",
    }
)

POLICY_FINDING_CODES = frozenset({"POLICY_VIOLATION", "TOO_MANY_ACTIONS"})


def independent_lineage_count(evidence: Mapping[str, EvidenceRef], evidence_ids: tuple[str, ...]) -> int:
    lineages = {
        evidence[evidence_id].lineage_id
        for evidence_id in evidence_ids
        if evidence_id in evidence and evidence[evidence_id].lineage_id
    }
    return len(lineages)


def _resolve_evidence(
    evidence: EvidenceRegistry | Mapping[str, EvidenceRef],
    evidence_id: str,
) -> EvidenceRef | None:
    if isinstance(evidence, EvidenceRegistry):
        try:
            return evidence.get(evidence_id).to_ref()
        except EvidenceError:
            return None
    return evidence.get(evidence_id)


def review_proposal(
    proposal: Proposal,
    evidence: EvidenceRegistry | Mapping[str, EvidenceRef],
    policy: Policy,
    *,
    now: datetime | None = None,
) -> tuple[ReviewFinding, ...]:
    now = now or datetime.now(UTC)
    findings: list[ReviewFinding] = []

    # Missing-piece role: claims need traceable evidence.
    all_evidence_ids: list[str] = []
    for claim in proposal.claims:
        all_evidence_ids.extend(claim.evidence_ids)
        if not claim.evidence_ids:
            findings.append(
                ReviewFinding(
                    role="missing_piece",
                    code="CLAIM_WITHOUT_EVIDENCE",
                    message=f"Claim {claim.claim_id} has no evidence reference.",
                )
            )
        for evidence_id in claim.evidence_ids:
            record: EvidenceRecord | None = None
            if isinstance(evidence, EvidenceRegistry):
                try:
                    record = evidence.get(evidence_id)
                except EvidenceError as exc:
                    code = exc.code if exc.code in EVIDENCE_FINDING_CODES else "UNKNOWN_EVIDENCE"
                    findings.append(
                        ReviewFinding(
                            role="missing_piece",
                            code=code,
                            message=f"Claim {claim.claim_id} references rejected evidence {evidence_id}: {exc.message}",
                        )
                    )
                    continue
                ref: EvidenceRef = record.to_ref()
                if policy.evidence.require_registry_signature and not record.registry_signature:
                    findings.append(
                        ReviewFinding(
                            role="observability",
                            code="UNSIGNED_EVIDENCE",
                            message=f"Evidence {evidence_id} has no registry signature.",
                        )
                    )
                if record.registry_key_id and record.registry_key_id not in policy.accepted_registry_key_ids:
                    findings.append(
                        ReviewFinding(
                            role="observability",
                            code="UNSIGNED_EVIDENCE",
                            message=(
                                f"Evidence {evidence_id} is signed by key {record.registry_key_id!r}, "
                                "which the policy does not trust."
                            ),
                        )
                    )
            else:
                mapping_ref = evidence.get(evidence_id)
                if mapping_ref is None:
                    findings.append(
                        ReviewFinding(
                            role="missing_piece",
                            code="UNKNOWN_EVIDENCE",
                            message=f"Claim {claim.claim_id} references unknown evidence {evidence_id}.",
                        )
                    )
                    continue
                ref = mapping_ref
                if not ref.signed:
                    findings.append(
                        ReviewFinding(
                            role="observability",
                            code="UNSIGNED_EVIDENCE",
                            message=f"Evidence {evidence_id} is asserted without a registry signature.",
                        )
                    )
                elif ref.registry_key_id not in policy.accepted_registry_key_ids:
                    findings.append(
                        ReviewFinding(
                            role="observability",
                            code="UNSIGNED_EVIDENCE",
                            message=f"Evidence {evidence_id} uses an untrusted registry key {ref.registry_key_id!r}.",
                        )
                    )

            if ref.source_id not in policy.allowed_source_ids:
                findings.append(
                    ReviewFinding(
                        role="observability",
                        code="SOURCE_NOT_ALLOWLISTED",
                        message=f"Evidence {evidence_id} uses source {ref.source_id}, which is not allowlisted.",
                    )
                )
            review_status = str(ref.review_status or (record.review_status if record else ""))
            if review_status not in policy.accepted_review_statuses:
                findings.append(
                    ReviewFinding(
                        role="observability",
                        code="EVIDENCE_NOT_REVIEWED",
                        message=f"Evidence {evidence_id} is not in an accepted review state.",
                    )
                )
            if not ref.observed_fields or not ref.blind_spots:
                findings.append(
                    ReviewFinding(
                        role="observability",
                        code="OBSERVABILITY_PROFILE_INCOMPLETE",
                        message=f"Evidence {evidence_id} does not declare observed fields and blind spots.",
                        blocking=False,
                    )
                )
            if isinstance(evidence, EvidenceRegistry) and record is not None:
                state = record.freshness_state(
                    now=now, max_age_seconds_by_class=policy.evidence.max_age_seconds_by_class
                )
                if state is FreshnessState.EXPIRED:
                    findings.append(
                        ReviewFinding(
                            role="observability",
                            code="EVIDENCE_STALE",
                            message=f"Evidence {evidence_id} is past valid_until and cannot support this action.",
                        )
                    )
                elif state is FreshnessState.REVIEW_OVERDUE:
                    findings.append(
                        ReviewFinding(
                            role="observability",
                            code="EVIDENCE_STALE",
                            message=f"Evidence {evidence_id} is past review_after and must be re-reviewed.",
                            blocking=False,
                        )
                    )

    required = policy.required_lineages(proposal.risk_tier)
    actual = independent_lineage_count(
        {
            evidence_id: _resolve_evidence(evidence, evidence_id) or EvidenceRef(evidence_id=evidence_id)
            for evidence_id in dict.fromkeys(all_evidence_ids)
        },
        tuple(dict.fromkeys(all_evidence_ids)),
    )
    if proposal.claims and actual < required:
        findings.append(
            ReviewFinding(
                role="independence",
                code="INSUFFICIENT_INDEPENDENT_LINEAGES",
                message=(
                    f"Risk tier {proposal.risk_tier.value} requires {required} "
                    f"independent lineages; found {actual}."
                ),
            )
        )

    # Meta role: do not build or act without considering alternatives.
    if policy.risk_at_least(proposal.risk_tier, policy.require_alternatives_from) and not proposal.alternatives:
        findings.append(
            ReviewFinding(
                role="meta",
                code="ALTERNATIVES_MISSING",
                message="Proposal does not consider alternatives, including no-build or an external option.",
            )
        )

    # Consequence role: action and inaction both have consequences.
    if policy.risk_at_least(proposal.risk_tier, policy.require_consequences_from):
        if not proposal.consequences_if_done or not proposal.consequences_if_not_done:
            findings.append(
                ReviewFinding(
                    role="consequence",
                    code="CONSEQUENCES_MISSING",
                    message="Proposal must state consequences of acting and of not acting.",
                )
            )
        if not proposal.unknowns:
            findings.append(
                ReviewFinding(
                    role="missing_piece",
                    code="UNKNOWNS_NOT_DECLARED",
                    message="Higher-risk proposals must declare important unknowns.",
                    blocking=False,
                )
            )

    # Security role: every requested action must remain inside policy.
    for violation in policy.evaluate_proposal_limits(len(proposal.actions)):
        findings.append(ReviewFinding(role="security", code="TOO_MANY_ACTIONS", message=violation))
    seen_action_ids: set[str] = set()
    for action in proposal.actions:
        if action.action_id in seen_action_ids:
            findings.append(
                ReviewFinding(
                    role="security",
                    code="POLICY_VIOLATION",
                    message=f"Duplicate action_id in one proposal: {action.action_id}",
                )
            )
        seen_action_ids.add(action.action_id)
        for violation in policy.evaluate_action(action):
            findings.append(
                ReviewFinding(
                    role="security",
                    code="POLICY_VIOLATION",
                    message=f"Action {action.action_id}: {violation}",
                )
            )
        if not action.reversible and not proposal.rollback_plan.strip():
            findings.append(
                ReviewFinding(
                    role="consequence",
                    code="ROLLBACK_MISSING",
                    message=(
                        f"Action {action.action_id} is marked irreversible but no "
                        "rollback/compensation plan exists."
                    ),
                )
            )

    if proposal.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and not proposal.rollback_plan.strip():
        findings.append(
            ReviewFinding(
                role="consequence",
                code="HIGH_RISK_ROLLBACK_MISSING",
                message="High-risk proposals require an explicit rollback or compensation plan.",
            )
        )

    return tuple(findings)


def has_blockers(findings: tuple[ReviewFinding, ...]) -> bool:
    return any(finding.blocking for finding in findings)


def verdict_for_findings(findings: tuple[ReviewFinding, ...]) -> str:
    """Map blocking finding codes to a verdict name (stable, testable)."""
    codes = {finding.code for finding in findings if finding.blocking}
    if not codes:
        return "PASS_WITHIN_SCOPE"
    if codes & POLICY_FINDING_CODES:
        return "BLOCKED_BY_POLICY"
    return "INSUFFICIENT_EVIDENCE"
