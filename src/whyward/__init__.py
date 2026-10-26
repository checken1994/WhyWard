"""WhyWard — an evidence-gated boundary control plane for AI workers."""

from .control import ControlPlane
from .evidence import KnowledgeStore, LookupResult
from .models import (
    ActionRequest,
    Claim,
    EvidenceRef,
    GateDecision,
    HumanDecision,
    Proposal,
    RiskTier,
    TaskRecord,
    TaskState,
    VerdictStatus,
)

__all__ = [
    "ActionRequest",
    "Claim",
    "ControlPlane",
    "EvidenceRef",
    "GateDecision",
    "HumanDecision",
    "KnowledgeStore",
    "LookupResult",
    "Proposal",
    "RiskTier",
    "TaskRecord",
    "TaskState",
    "VerdictStatus",
]

__version__ = "0.1.0"
