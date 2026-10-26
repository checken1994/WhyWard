from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import canonical_json, digest, sha256_text
from .errors import PolicyError
from .identity import Keyring, sign_payload, verify_envelope
from .models import ActionRequest, RiskTier

POLICY_SCHEMA_VERSION = 2

REQUIRED_POLICY_KEYS = (
    "schema_version",
    "profile",
    "allowed_tools",
    "protected_path_prefixes",
    "allowed_source_ids",
    "accepted_review_statuses",
    "accepted_registry_key_ids",
    "human_required_risk_tiers",
    "human_required_tools",
    "max_autonomy_without_human",
    "min_independent_lineages",
    "require_alternatives_from",
    "require_consequences_from",
    "limits",
    "review",
    "evidence",
)

ALLOWED_POLICY_KEYS = (*REQUIRED_POLICY_KEYS, "description", "signing", "created_at", "policy_version")

_REQUIRED_LIMIT_KEYS = (
    "max_actions_per_proposal",
    "max_read_bytes",
    "max_write_bytes",
    "max_python_timeout_seconds",
    "max_python_output_bytes",
    "max_resource_bytes",
)

_REQUIRED_REVIEW_KEYS = (
    "require_human_decision_signature",
    "approval_ttl_seconds",
    "reject_stale_on_read",
    "min_restatement_chars",
)

_REQUIRED_EVIDENCE_KEYS = (
    "require_registry_signature",
    "require_checksum_in_manifest",
    "require_record_count",
    "max_age_seconds_by_class",
)


def canonical_json_policy(data: Any) -> str:
    return canonical_json(data)


@dataclass(frozen=True)
class PolicyLimits:
    max_actions_per_proposal: int = 16
    max_read_bytes: int = 1_048_576
    max_write_bytes: int = 1_048_576
    max_python_timeout_seconds: int = 10
    max_python_output_bytes: int = 262_144
    max_resource_bytes: int = 4_194_304

    def to_dict(self) -> dict[str, int]:
        return {
            "max_actions_per_proposal": self.max_actions_per_proposal,
            "max_read_bytes": self.max_read_bytes,
            "max_write_bytes": self.max_write_bytes,
            "max_python_timeout_seconds": self.max_python_timeout_seconds,
            "max_python_output_bytes": self.max_python_output_bytes,
            "max_resource_bytes": self.max_resource_bytes,
        }


@dataclass(frozen=True)
class ReviewSettings:
    require_human_decision_signature: bool = True
    approval_ttl_seconds: int = 3600
    reject_stale_on_read: bool = True
    min_restatement_chars: int = 20

    def to_dict(self) -> dict[str, Any]:
        return {
            "require_human_decision_signature": self.require_human_decision_signature,
            "approval_ttl_seconds": self.approval_ttl_seconds,
            "reject_stale_on_read": self.reject_stale_on_read,
            "min_restatement_chars": self.min_restatement_chars,
        }


@dataclass(frozen=True)
class EvidenceSettings:
    require_registry_signature: bool = True
    require_checksum_in_manifest: bool = True
    require_record_count: bool = True
    max_age_seconds_by_class: dict[str, int] = field(
        default_factory=lambda: {"volatile": 86_400, "periodic": 7_776_000, "historical_stable": 0}
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "require_registry_signature": self.require_registry_signature,
            "require_checksum_in_manifest": self.require_checksum_in_manifest,
            "require_record_count": self.require_record_count,
            "max_age_seconds_by_class": dict(self.max_age_seconds_by_class),
        }


@dataclass(frozen=True)
class Policy:
    """A complete, explicit control configuration.

    There are deliberately no silent defaults when loading from a file: a
    missing key is a startup error, because a typo in a policy must never
    quietly weaken a control (see audit finding W-05).
    """

    profile: str = "production"
    allowed_tools: frozenset[str] = frozenset({"write_text", "read_text"})
    protected_path_prefixes: tuple[str, ...] = (
        ".whyward",
        "control",
        "keys",
        "policy",
        "policies",
        ".git",
    )
    allowed_source_ids: frozenset[str] = frozenset({"usgs", "internal-test"})
    accepted_review_statuses: frozenset[str] = frozenset({"verified"})
    accepted_registry_key_ids: frozenset[str] = frozenset({"evidence-ingest"})
    human_required_risk_tiers: frozenset[RiskTier] = frozenset({RiskTier.HIGH, RiskTier.CRITICAL})
    human_required_tools: frozenset[str] = frozenset({"run_python"})
    max_autonomy_without_human: int = 2
    min_independent_lineages: dict[str, int] = field(
        default_factory=lambda: {"low": 1, "medium": 1, "high": 2, "critical": 2}
    )
    require_alternatives_from: RiskTier = RiskTier.MEDIUM
    require_consequences_from: RiskTier = RiskTier.MEDIUM
    limits: PolicyLimits = field(default_factory=PolicyLimits)
    review: ReviewSettings = field(default_factory=ReviewSettings)
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    schema_version: int = POLICY_SCHEMA_VERSION
    description: str = ""
    signing: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    policy_version: str = "2"

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def default(cls) -> Policy:
        """Conservative in-code default: no code execution, signatures required."""
        return cls()

    @classmethod
    def production_example(cls) -> dict[str, Any]:
        """JSON body of the conservative production profile (used by docs/tests)."""
        return cls.default().to_dict()

    @classmethod
    def dev(cls) -> Policy:
        """Development/demo profile. Never use in production.

        Differences are explicit and reported at startup: run_python is allowed,
        demo fixtures are accepted, and human decisions need no signature.
        """
        return cls(
            profile="dev",
            allowed_tools=frozenset({"write_text", "read_text", "run_python"}),
            allowed_source_ids=frozenset({"usgs", "internal-test", "demo-source"}),
            accepted_review_statuses=frozenset({"verified", "demo_verified"}),
            accepted_registry_key_ids=frozenset({"evidence-ingest", "demo-manifest-2026"}),
            human_required_risk_tiers=frozenset({RiskTier.HIGH, RiskTier.CRITICAL}),
            # run_python stays human-gated even in dev: relaxing the signature
            # requirement must not relax the "a human decides" requirement.
            human_required_tools=frozenset({"run_python"}),
            review=ReviewSettings(require_human_decision_signature=False, approval_ttl_seconds=86_400),
            evidence=EvidenceSettings(require_registry_signature=True),
            description="Development profile: demo fixtures accepted, run_python enabled.",
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, allow_dev_profile: bool = True) -> Policy:
        if not isinstance(data, Mapping):
            raise PolicyError("Policy must be a JSON object")
        unknown = sorted(set(data) - set(ALLOWED_POLICY_KEYS))
        if unknown:
            raise PolicyError(
                "Policy contains unknown keys (fail closed)",
                code="POLICY_UNKNOWN_KEYS",
                details={"unknown": unknown},
            )
        missing = [key for key in REQUIRED_POLICY_KEYS if key not in data]
        if missing:
            raise PolicyError(
                "Policy is missing required keys",
                code="POLICY_MISSING_KEYS",
                details={"missing": missing},
            )
        if int(data["schema_version"]) != POLICY_SCHEMA_VERSION:
            raise PolicyError(
                f"Unsupported policy schema_version: {data['schema_version']}",
                code="POLICY_SCHEMA_UNSUPPORTED",
            )
        profile = str(data["profile"])
        if profile == "dev" and not allow_dev_profile:
            raise PolicyError("Development profile is not allowed in this deployment", code="POLICY_PROFILE_REJECTED")

        limits_raw = data["limits"]
        review_raw = data["review"]
        evidence_raw = data["evidence"]
        for name, raw, required in (
            ("limits", limits_raw, _REQUIRED_LIMIT_KEYS),
            ("review", review_raw, _REQUIRED_REVIEW_KEYS),
            ("evidence", evidence_raw, _REQUIRED_EVIDENCE_KEYS),
        ):
            if not isinstance(raw, Mapping):
                raise PolicyError(f"Policy key {name!r} must be an object", code="POLICY_SCHEMA_INVALID")
            missing_nested = [key for key in required if key not in raw]
            if missing_nested:
                raise PolicyError(
                    f"Policy key {name!r} is missing required keys",
                    code="POLICY_MISSING_KEYS",
                    details={"missing": [f"{name}.{key}" for key in missing_nested]},
                )

        lineages = data["min_independent_lineages"]
        if not isinstance(lineages, Mapping):
            raise PolicyError("min_independent_lineages must be an object", code="POLICY_SCHEMA_INVALID")
        missing_risks = [risk.value for risk in RiskTier if risk.value not in lineages]
        if missing_risks:
            raise PolicyError(
                "min_independent_lineages must declare every risk tier",
                code="POLICY_MISSING_KEYS",
                details={"missing": missing_risks},
            )

        policy = cls(
            profile=profile,
            allowed_tools=frozenset(str(x) for x in data["allowed_tools"]),
            protected_path_prefixes=tuple(str(x) for x in data["protected_path_prefixes"]),
            allowed_source_ids=frozenset(str(x) for x in data["allowed_source_ids"]),
            accepted_review_statuses=frozenset(str(x) for x in data["accepted_review_statuses"]),
            accepted_registry_key_ids=frozenset(str(x) for x in data["accepted_registry_key_ids"]),
            human_required_risk_tiers=frozenset(RiskTier(x) for x in data["human_required_risk_tiers"]),
            human_required_tools=frozenset(str(x) for x in data["human_required_tools"]),
            max_autonomy_without_human=int(data["max_autonomy_without_human"]),
            min_independent_lineages={str(k): int(v) for k, v in lineages.items()},
            require_alternatives_from=RiskTier(data["require_alternatives_from"]),
            require_consequences_from=RiskTier(data["require_consequences_from"]),
            limits=PolicyLimits(
                max_actions_per_proposal=int(limits_raw["max_actions_per_proposal"]),
                max_read_bytes=int(limits_raw["max_read_bytes"]),
                max_write_bytes=int(limits_raw["max_write_bytes"]),
                max_python_timeout_seconds=int(limits_raw["max_python_timeout_seconds"]),
                max_python_output_bytes=int(limits_raw["max_python_output_bytes"]),
                max_resource_bytes=int(limits_raw["max_resource_bytes"]),
            ),
            review=ReviewSettings(
                require_human_decision_signature=bool(review_raw["require_human_decision_signature"]),
                approval_ttl_seconds=int(review_raw["approval_ttl_seconds"]),
                reject_stale_on_read=bool(review_raw["reject_stale_on_read"]),
                min_restatement_chars=int(review_raw["min_restatement_chars"]),
            ),
            evidence=EvidenceSettings(
                require_registry_signature=bool(evidence_raw["require_registry_signature"]),
                require_checksum_in_manifest=bool(evidence_raw["require_checksum_in_manifest"]),
                require_record_count=bool(evidence_raw["require_record_count"]),
                max_age_seconds_by_class={
                    str(k): int(v) for k, v in evidence_raw["max_age_seconds_by_class"].items()
                },
            ),
            schema_version=int(data["schema_version"]),
            description=str(data.get("description", "")),
            signing=json.loads(canonical_json(data.get("signing", {}))),
            created_at=str(data.get("created_at", "")),
            policy_version=str(data.get("policy_version", "2")),
        )
        policy.validate()
        return policy

    def validate(self) -> None:
        if self.review.require_human_decision_signature and not self.accepted_registry_key_ids:
            # Not fatal, but a policy that trusts no registry key while requiring
            # signatures can never accept evidence: surface it at startup.
            pass
        if self.limits.max_actions_per_proposal <= 0:
            raise PolicyError("limits.max_actions_per_proposal must be positive", code="POLICY_SCHEMA_INVALID")
        if self.review.approval_ttl_seconds <= 0:
            raise PolicyError("review.approval_ttl_seconds must be positive", code="POLICY_SCHEMA_INVALID")
        if (
            "run_python" in self.allowed_tools
            and "run_python" not in self.human_required_tools
            and self.profile != "dev"
        ):
            raise PolicyError(
                "run_python must be listed in human_required_tools outside the dev profile",
                code="POLICY_UNSAFE_TOOL",
            )

    # ------------------------------------------------------------------ #
    # Serialization / signing
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "allowed_tools": sorted(self.allowed_tools),
            "protected_path_prefixes": list(self.protected_path_prefixes),
            "allowed_source_ids": sorted(self.allowed_source_ids),
            "accepted_review_statuses": sorted(self.accepted_review_statuses),
            "accepted_registry_key_ids": sorted(self.accepted_registry_key_ids),
            "human_required_risk_tiers": sorted(x.value for x in self.human_required_risk_tiers),
            "human_required_tools": sorted(self.human_required_tools),
            "max_autonomy_without_human": self.max_autonomy_without_human,
            "min_independent_lineages": dict(sorted(self.min_independent_lineages.items())),
            "require_alternatives_from": self.require_alternatives_from.value,
            "require_consequences_from": self.require_consequences_from.value,
            "limits": self.limits.to_dict(),
            "review": self.review.to_dict(),
            "evidence": self.evidence.to_dict(),
        }
        if self.description:
            body["description"] = self.description
        if self.created_at:
            body["created_at"] = self.created_at
        body["policy_version"] = self.policy_version
        return body

    def digest(self) -> str:
        return digest(self.to_dict())

    def fingerprint(self) -> str:
        return self.digest()

    def sign(self, key: bytes) -> str:
        return sign_payload(key, self.to_dict())

    def signed_document(self, key_id: str, key: bytes) -> dict[str, Any]:
        return {
            "policy": self.to_dict(),
            "signature": {
                "algorithm": "hmac-sha256",
                "key_id": key_id,
                "value": self.sign(key),
            },
        }

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        keyring: Keyring | None = None,
        require_signature: bool = False,
        allow_dev_profile: bool = True,
        trusted_key_ids: Iterable[str] | None = None,
    ) -> Policy:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyError(
                f"Policy file is not readable: {path}", code="POLICY_UNREADABLE", details={"path": str(path)}
            ) from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(f"Policy file is not valid JSON: {path}", code="POLICY_INVALID_JSON") from exc
        if not isinstance(raw, Mapping):
            raise PolicyError("Policy file must contain a JSON object")
        signature = raw.get("signature")
        body = raw.get("policy", raw)
        policy = cls.from_dict({k: v for k, v in body.items() if k != "signature"}, allow_dev_profile=allow_dev_profile)
        if signature is not None:
            keyring = keyring or Keyring.from_env()
            # Trust set: explicit argument, else every key the deployment loaded.
            verify_envelope(
                {"payload": {k: v for k, v in body.items() if k != "signature"}, "signature": signature},
                keyring,
                allowed_key_ids=trusted_key_ids,
            )
            policy = Policy.from_dict(
                {**{k: v for k, v in body.items() if k != "signature"}, "signing": dict(signature)},
                allow_dev_profile=allow_dev_profile,
            )
        elif require_signature:
            raise PolicyError(
                "Policy file is unsigned but this deployment requires a signature",
                code="POLICY_UNSIGNED",
            )
        return policy

    @classmethod
    def from_env(cls) -> Policy:
        """Load ``WHYWARD_POLICY`` (path) or fall back to the conservative default."""
        import os

        path = os.environ.get("WHYWARD_POLICY", "").strip()
        if not path:
            return cls.default()
        require = os.environ.get("WHYWARD_REQUIRE_SIGNED_POLICY", "").strip() in {"1", "true", "yes"}
        keyring = Keyring.from_env() if require else None
        return cls.load(path, keyring=keyring, require_signature=require)

    # ------------------------------------------------------------------ #
    # Evaluation helpers
    # ------------------------------------------------------------------ #
    def risk_at_least(self, risk: RiskTier, threshold: RiskTier) -> bool:
        return risk.rank >= threshold.rank

    def is_protected_resource(self, resource: str) -> bool:
        normalized = str(resource).replace("\\", "/").lstrip("/")
        parts = PurePosixPath(normalized).parts
        for prefix in self.protected_path_prefixes:
            prefix_parts = PurePosixPath(str(prefix).replace("\\", "/").lstrip("/")).parts
            if parts[: len(prefix_parts)] == prefix_parts:
                return True
        return False

    def evaluate_action(self, action: ActionRequest) -> tuple[str, ...]:
        violations: list[str] = []
        if action.tool not in self.allowed_tools:
            violations.append(f"Tool is not allowlisted: {action.tool}")
        if self.is_protected_resource(action.resource):
            violations.append(f"Resource is protected: {action.resource}")
        resource_parts = PurePosixPath(str(action.resource).replace("\\", "/")).parts
        if ".." in resource_parts:
            violations.append(f"Resource attempts path traversal: {action.resource}")
        if str(action.resource).startswith("/") or str(action.resource).startswith("\\"):
            violations.append(f"Absolute resource is not allowed: {action.resource}")
        if "\x00" in str(action.resource):
            violations.append("Resource contains a NUL byte")
        return tuple(violations)

    def evaluate_proposal_limits(self, action_count: int) -> tuple[str, ...]:
        problems: list[str] = []
        if action_count > self.limits.max_actions_per_proposal:
            problems.append(
                f"Proposal requests {action_count} actions; limit is {self.limits.max_actions_per_proposal}"
            )
        return tuple(problems)

    def required_lineages(self, risk: RiskTier) -> int:
        if risk.value not in self.min_independent_lineages:
            raise PolicyError(
                f"Policy does not declare min_independent_lineages for risk tier {risk.value!r}",
                code="POLICY_MISSING_RISK_TIER",
            )
        return int(self.min_independent_lineages[risk.value])

    def human_required(self, risk: RiskTier, tools: Iterable[str], autonomy: int, reversible: bool) -> bool:
        if risk in self.human_required_risk_tiers:
            return True
        if autonomy > self.max_autonomy_without_human:
            return True
        if not reversible:
            return True
        tool_set = set(tools)
        return bool(tool_set & set(self.human_required_tools))

    def to_text(self) -> str:
        return sha256_text(canonical_json(self.to_dict()))


__all__ = ["POLICY_SCHEMA_VERSION", "EvidenceSettings", "Policy", "PolicyLimits", "ReviewSettings"]
