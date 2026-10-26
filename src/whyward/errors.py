"""Typed error taxonomy.

Every failure that can cross a boundary (CLI, HTTP, library caller) carries a
stable machine-readable ``code``, an HTTP status and a process exit code. This
is what turns "ValueError traceback" into an auditable outcome.
"""

from __future__ import annotations

from typing import Any

# Exit codes are part of the CLI contract (see README).
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_INTEGRITY = 2
EXIT_WITHHELD = 3
EXIT_CONFIGURATION = 4
EXIT_UNAVAILABLE = 5


class WhyWardError(Exception):
    """Base class for expected failures."""

    code = "WHYWARD_ERROR"
    http_status = 500
    exit_code = EXIT_FAILURE
    title = "WhyWard error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        http_status: int | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details or {}
        if http_status is not None:
            self.http_status = http_status
        if exit_code is not None:
            self.exit_code = exit_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
            "http_status": self.http_status,
            "exit_code": self.exit_code,
        }

    def to_problem(self, *, instance: str = "", trace_id: str = "") -> dict[str, Any]:
        """RFC 9457 Problem Details payload."""
        problem: dict[str, Any] = {
            "type": f"https://whyward.dev/problems/{self.code.lower()}",
            "title": self.title,
            "status": self.http_status,
            "detail": self.message,
            "code": self.code,
        }
        if instance:
            problem["instance"] = instance
        if trace_id:
            problem["trace_id"] = trace_id
        if self.details:
            problem["details"] = self.details
        return problem


class ValidationError(WhyWardError):
    code = "INVALID_REQUEST"
    http_status = 400
    exit_code = EXIT_FAILURE
    title = "Invalid request"


class AuthenticationError(WhyWardError):
    code = "UNAUTHENTICATED"
    http_status = 401
    exit_code = EXIT_CONFIGURATION
    title = "Authentication required"


class AuthorizationError(WhyWardError):
    code = "FORBIDDEN"
    http_status = 403
    exit_code = EXIT_CONFIGURATION
    title = "Insufficient scope"


class RateLimitExceeded(WhyWardError):
    code = "RATE_LIMITED"
    http_status = 429
    exit_code = EXIT_UNAVAILABLE
    title = "Rate limit exceeded"


class ConfigurationError(WhyWardError):
    code = "CONFIG_INVALID"
    http_status = 500
    exit_code = EXIT_CONFIGURATION
    title = "Invalid configuration"


class PolicyError(WhyWardError):
    code = "POLICY_INVALID"
    http_status = 500
    exit_code = EXIT_CONFIGURATION
    title = "Invalid policy"


class PolicyViolation(WhyWardError):
    code = "POLICY_VIOLATION"
    http_status = 403
    exit_code = EXIT_CONFIGURATION
    title = "Blocked by policy"


class EvidenceError(WhyWardError):
    code = "EVIDENCE_INVALID"
    http_status = 422
    exit_code = EXIT_WITHHELD
    title = "Evidence rejected"


class IntegrityError(WhyWardError):
    code = "INTEGRITY_FAILURE"
    http_status = 409
    exit_code = EXIT_INTEGRITY
    title = "Integrity failure"


class CapabilityError(WhyWardError):
    code = "CAPABILITY_REJECTED"
    http_status = 403
    exit_code = EXIT_CONFIGURATION
    title = "Capability rejected"


class StateError(WhyWardError):
    code = "INVALID_STATE"
    http_status = 409
    exit_code = EXIT_FAILURE
    title = "Invalid state transition"


class ExecutionError(WhyWardError):
    code = "EXECUTION_FAILED"
    http_status = 502
    exit_code = EXIT_FAILURE
    title = "Execution failed"


class ResourceLimitExceeded(WhyWardError):
    code = "RESOURCE_LIMIT_EXCEEDED"
    http_status = 413
    exit_code = EXIT_FAILURE
    title = "Resource limit exceeded"


class KillSwitchEngaged(WhyWardError):
    code = "KILL_SWITCH_ENGAGED"
    http_status = 503
    exit_code = EXIT_UNAVAILABLE
    title = "Kill switch engaged"
