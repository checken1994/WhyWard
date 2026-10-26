from __future__ import annotations

from typing import Mapping

from .models import EvidenceRef, Proposal, ReviewFinding, RiskTier
from .policy import Policy


def independent_lineage_count(evidence: Mapping[str, EvidenceRef], evidence_ids: tuple[str, ...]) -> int:
    lineages = {
        evidence[evidence_id].lineage_id
        for evidence_id in evidence_ids
        if evidence_id in evidence and evidence[evidence_id].lineage_id
    }
    return len(lineages)


def review_proposal(
    proposal: Proposal,
    evidence: Mapping[str, EvidenceRef],
    policy: Policy,
) -> tuple[ReviewFinding, ...]:
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
            ref = evidence.get(evidence_id)
            if ref is None:
                findings.append(
                    ReviewFinding(
                        role="missing_piece",
                        code="UNKNOWN_EVIDENCE",
                        message=f"Claim {claim.claim_id} references unknown evidence {evidence_id}.",
                    )
                )
                continue
            if ref.source_id not in policy.allowed_source_ids:
                findings.append(
                    ReviewFinding(
                        role="observability",
                        code="SOURCE_NOT_ALLOWLISTED",
                        message=f"Evidence {evidence_id} uses source {ref.source_id}, which is not allowlisted.",
                    )
                )
            if ref.review_status not in policy.accepted_review_statuses:
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

    required = policy.required_lineages(proposal.risk_tier)
    actual = independent_lineage_count(evidence, tuple(dict.fromkeys(all_evidence_ids)))
    if proposal.claims and actual < required:
        findings.append(
            ReviewFinding(
                role="independence",
                code="INSUFFICIENT_INDEPENDENT_LINEAGES",
                message=f"Risk tier {proposal.risk_tier.value} requires {required} independent lineages; found {actual}.",
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
    for action in proposal.actions:
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
                    message=f"Action {action.action_id} is marked irreversible but no rollback/compensation plan exists.",
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
