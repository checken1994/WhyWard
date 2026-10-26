from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .models import ActionRequest, RiskTier


def canonical_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Policy:
    allowed_tools: frozenset[str] = frozenset({"write_text", "read_text", "run_python"})
    protected_path_prefixes: tuple[str, ...] = (
        ".whyward",
        "control",
        "keys",
        "policy",
        "policies",
    )
    allowed_source_ids: frozenset[str] = frozenset({"usgs", "internal-test", "demo-source"})
    accepted_review_statuses: frozenset[str] = frozenset({"verified", "demo_verified"})
    human_required_risk_tiers: frozenset[RiskTier] = frozenset({RiskTier.HIGH, RiskTier.CRITICAL})
    max_autonomy_without_human: int = 2
    min_independent_lineages: dict[str, int] = field(
        default_factory=lambda: {"low": 1, "medium": 1, "high": 2, "critical": 2}
    )
    require_alternatives_from: RiskTier = RiskTier.MEDIUM
    require_consequences_from: RiskTier = RiskTier.MEDIUM

    @classmethod
    def default(cls) -> "Policy":
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": sorted(self.allowed_tools),
            "protected_path_prefixes": list(self.protected_path_prefixes),
            "allowed_source_ids": sorted(self.allowed_source_ids),
            "accepted_review_statuses": sorted(self.accepted_review_statuses),
            "human_required_risk_tiers": sorted(x.value for x in self.human_required_risk_tiers),
            "max_autonomy_without_human": self.max_autonomy_without_human,
            "min_independent_lineages": dict(self.min_independent_lineages),
            "require_alternatives_from": self.require_alternatives_from.value,
            "require_consequences_from": self.require_consequences_from.value,
        }

    def fingerprint(self) -> str:
        return sha256_text(canonical_json(self.to_dict()))

    def sign(self, key: bytes) -> str:
        return hmac.new(key, canonical_json(self.to_dict()).encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        return cls(
            allowed_tools=frozenset(data.get("allowed_tools", ["write_text", "read_text", "run_python"])),
            protected_path_prefixes=tuple(data.get("protected_path_prefixes", [])),
            allowed_source_ids=frozenset(data.get("allowed_source_ids", [])),
            accepted_review_statuses=frozenset(data.get("accepted_review_statuses", ["verified"])),
            human_required_risk_tiers=frozenset(
                RiskTier(x) for x in data.get("human_required_risk_tiers", ["high", "critical"])
            ),
            max_autonomy_without_human=int(data.get("max_autonomy_without_human", 2)),
            min_independent_lineages=dict(data.get("min_independent_lineages", {})),
            require_alternatives_from=RiskTier(data.get("require_alternatives_from", "medium")),
            require_consequences_from=RiskTier(data.get("require_consequences_from", "medium")),
        )

    @classmethod
    def load(cls, path: str | Path, *, signing_key: bytes | None = None) -> "Policy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        signature = raw.pop("signature", None)
        policy = cls.from_dict(raw)
        if signing_key is not None:
            if not signature:
                raise ValueError("Policy signing key supplied but policy has no signature")
            expected = policy.sign(signing_key)
            if not hmac.compare_digest(expected, str(signature)):
                raise ValueError("Policy signature verification failed")
        return policy

    @staticmethod
    def _risk_rank(risk: RiskTier) -> int:
        return {RiskTier.LOW: 0, RiskTier.MEDIUM: 1, RiskTier.HIGH: 2, RiskTier.CRITICAL: 3}[risk]

    def risk_at_least(self, risk: RiskTier, threshold: RiskTier) -> bool:
        return self._risk_rank(risk) >= self._risk_rank(threshold)

    def is_protected_resource(self, resource: str) -> bool:
        normalized = resource.replace("\\", "/").lstrip("/")
        parts = PurePosixPath(normalized).parts
        for prefix in self.protected_path_prefixes:
            prefix_parts = PurePosixPath(prefix.replace("\\", "/").lstrip("/")).parts
            if parts[: len(prefix_parts)] == prefix_parts:
                return True
        return False

    def evaluate_action(self, action: ActionRequest) -> tuple[str, ...]:
        violations: list[str] = []
        if action.tool not in self.allowed_tools:
            violations.append(f"Tool is not allowlisted: {action.tool}")
        if self.is_protected_resource(action.resource):
            violations.append(f"Resource is protected: {action.resource}")
        if ".." in PurePosixPath(action.resource.replace("\\", "/")).parts:
            violations.append(f"Resource attempts path traversal: {action.resource}")
        return tuple(violations)

    def required_lineages(self, risk: RiskTier) -> int:
        return int(self.min_independent_lineages.get(risk.value, 1))
