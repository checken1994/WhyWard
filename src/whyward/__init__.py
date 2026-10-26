"""WhyWard — an evidence-gated boundary control plane for AI workers."""

from .capability import CapabilityBroker, SqliteUsedTokenStore
from .control import ControlPlane
from .errors import (
    AuthenticationError,
    AuthorizationError,
    CapabilityError,
    ConfigurationError,
    EvidenceError,
    ExecutionError,
    IntegrityError,
    PolicyError,
    PolicyViolation,
    ResourceLimitExceeded,
    StateError,
    WhyWardError,
)
from .evidence import KnowledgeStore, LookupResult
from .identity import ApiTokenStore, Keyring, generate_api_token
from .ledger import Ledger
from .models import (
    ActionRequest,
    ApprovalPackage,
    Claim,
    EvidenceRef,
    GateDecision,
    HumanDecision,
    Proposal,
    ReviewFinding,
    RiskTier,
    TaskRecord,
    TaskState,
    VerdictStatus,
)
from .observability import Metrics, StructuredLogger
from .policy import Policy
from .registry import EvidenceRecord, EvidenceRegistry
from .review import review_proposal

__all__ = [
    "ActionRequest",
    "ApiTokenStore",
    "ApprovalPackage",
    "AuthenticationError",
    "AuthorizationError",
    "CapabilityBroker",
    "CapabilityError",
    "Claim",
    "ConfigurationError",
    "ControlPlane",
    "EvidenceError",
    "EvidenceRecord",
    "EvidenceRef",
    "EvidenceRegistry",
    "ExecutionError",
    "GateDecision",
    "HumanDecision",
    "IntegrityError",
    "Keyring",
    "KnowledgeStore",
    "Ledger",
    "LookupResult",
    "Metrics",
    "Policy",
    "PolicyError",
    "PolicyViolation",
    "Proposal",
    "ResourceLimitExceeded",
    "ReviewFinding",
    "RiskTier",
    "SqliteUsedTokenStore",
    "StateError",
    "StructuredLogger",
    "TaskRecord",
    "TaskState",
    "VerdictStatus",
    "WhyWardError",
    "generate_api_token",
    "review_proposal",
]

from .version import __version__ as __version__
