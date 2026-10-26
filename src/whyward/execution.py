"""Workspace executor with resource limits, pre-image journal and no-follow I/O.

Hardening over 0.1.0 (audit findings W-13, W-14):

* every read/write is size limited and bounded in memory (no more "load 64 MB
  to return 10 characters");
* writes open with ``O_NOFOLLOW`` (blocked symlink TOCTOU) and record a
  pre-image hash/size so a rollback has something to compare against;
* overwrites are explicit: ``overwrite=true`` must be declared in the action;
* ``run_python`` is refused unless the policy explicitly enables it, is bounded
  by wall clock/CPU/address space/file size, and can be delegated to a container
  backend (``isolation.DockerSandboxBackend``) so it does not run as the host UID.

None of this replaces OS-level isolation; see ``SECURITY.md`` and the
``isolation`` module for the container path.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .capability import CapabilityBroker
from .errors import CapabilityError, ExecutionError, ResourceLimitExceeded
from .models import ActionRequest
from .policy import PolicyLimits

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class FilePreImage:
    resource: str
    existed: bool
    sha256: str
    size: int
    readable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "existed": self.existed,
            "sha256": self.sha256,
            "size": self.size,
            "readable": self.readable,
        }


class PythonBackend(Protocol):
    name: str

    def run(self, *, program: Path, args: list[str], workspace: Path, timeout: int,
            max_output_bytes: int) -> dict[str, Any]: ...


class SubprocessBackend:
    """Runs the program with the host interpreter but with rlimits.

    Still not an OS sandbox: the process shares the host UID. Use
    ``DockerSandboxBackend`` (or run WhyWard itself inside a container) for
    production isolation.
    """

    name = "subprocess-rlimit"

    def run(self, *, program: Path, args: list[str], workspace: Path, timeout: int,
            max_output_bytes: int) -> dict[str, Any]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TMPDIR": str(workspace),
            "HOME": str(workspace),
        }
        completed = subprocess.run(
            [sys.executable, "-I", str(program), *args],
            cwd=str(workspace),
            env=env,
            shell=False,
            text=False,
            capture_output=True,
            timeout=timeout,
            check=False,
            preexec_fn=_rlimit_hook(timeout) if os.name == "posix" else None,
        )
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        payload = (stdout + stderr)[:max_output_bytes]
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": stdout[:max_output_bytes].decode("utf-8", errors="replace"),
            "stderr": stderr[:max_output_bytes].decode("utf-8", errors="replace"),
            "output_sha256": hashlib.sha256(payload).hexdigest(),
            "output_truncated": len(stdout) + len(stderr) > max_output_bytes,
            "backend": self.name,
        }


def _rlimit_hook(timeout: int) -> Callable[[], None] | None:
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return None

    def _apply() -> None:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (max(1, timeout), max(1, timeout) + 1))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            _soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            limit = 512 * 1024 * 1024
            if hard == resource.RLIM_INFINITY or hard > limit:
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        except (ValueError, OSError):
            pass

    return _apply


class SandboxExecutor:
    """Executes a tiny allowlisted tool set inside a workspace directory."""

    TOOLS = ("write_text", "read_text", "run_python")

    def __init__(
        self,
        root: str | Path,
        broker: CapabilityBroker,
        *,
        limits: PolicyLimits | None = None,
        allow_python: bool = False,
        blocked: Callable[[], bool] | None = None,
        python_backend: PythonBackend | None = None,
    ):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.broker = broker
        self.limits = limits or PolicyLimits()
        self.allow_python = allow_python
        self._blocked = blocked
        self.backend: PythonBackend = python_backend or SubprocessBackend()

    def set_blocked_hook(self, blocked: Callable[[], bool] | None) -> None:
        """Attach (or clear) the kill-switch predicate consulted before executing."""
        self._blocked = blocked

    # ------------------------------------------------------------------ #
    # Path safety
    # ------------------------------------------------------------------ #
    def _resolve(self, resource: str) -> Path:
        raw = str(resource)
        if not raw or "\x00" in raw:
            raise ExecutionError("Invalid resource name", code="INVALID_RESOURCE")
        if Path(raw).is_absolute() or raw.startswith("\\"):
            raise CapabilityError("Absolute resources are not allowed", code="ABSOLUTE_RESOURCE")
        if ".." in Path(raw.replace("\\", "/")).parts:
            raise CapabilityError("Path traversal is not allowed", code="PATH_TRAVERSAL")
        candidate = (self.root / raw).resolve()
        if self.root != candidate and self.root not in candidate.parents:
            raise CapabilityError(f"Resource escapes sandbox: {raw}", code="SANDBOX_ESCAPE")
        return candidate

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _check_kill_switch(self) -> None:
        if self._blocked is not None and self._blocked():
            raise CapabilityError("Kill switch engaged: execution refused", code="KILL_SWITCH_ENGAGED")

    def _pre_image(self, path: Path, resource: str) -> FilePreImage:
        if not path.exists():
            return FilePreImage(resource=resource, existed=False, sha256="", size=0)
        if path.is_symlink():
            return FilePreImage(resource=resource, existed=True, sha256="", size=0, readable=False)
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(65_536)
                if not chunk:
                    break
                size += len(chunk)
                if size > self.limits.max_resource_bytes:
                    return FilePreImage(resource=resource, existed=True, sha256="", size=size, readable=False)
                digest.update(chunk)
        return FilePreImage(resource=resource, existed=True, sha256=digest.hexdigest(), size=size)

    # ------------------------------------------------------------------ #
    # Execute
    # ------------------------------------------------------------------ #
    def execute(self, action: ActionRequest, capability_token: str) -> dict[str, Any]:
        self._check_kill_switch()
        ledger_binding = self.broker.consume(capability_token, action)
        path = self._resolve(action.resource)

        if action.tool == "write_text":
            return self._write_text(action, path, ledger_binding)
        if action.tool == "read_text":
            return self._read_text(action, path)
        if action.tool == "run_python":
            return self._run_python(action, path)
        raise ExecutionError(f"Unsupported sandbox tool: {action.tool}", code="UNSUPPORTED_TOOL")

    def _write_text(self, action: ActionRequest, path: Path, binding: dict[str, Any]) -> dict[str, Any]:
        content = str(action.parameters.get("content", ""))
        data = content.encode("utf-8")
        if len(data) > self.limits.max_write_bytes:
            raise ResourceLimitExceeded(
                f"write_text payload is {len(data)} bytes; limit is {self.limits.max_write_bytes}",
                code="WRITE_TOO_LARGE",
            )
        pre_image = self._pre_image(path, action.resource)
        if pre_image.existed and not bool(action.parameters.get("overwrite", False)):
            raise ExecutionError(
                f"Resource already exists and overwrite was not declared: {action.resource}",
                code="OVERWRITE_NOT_DECLARED",
                details={"pre_image_sha256": pre_image.sha256},
            )
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ExecutionError(
                f"Cannot prepare parent directory for write: {exc}",
                code="WRITE_FAILED",
                details={"resource": action.resource},
            ) from exc
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ExecutionError(
                f"Cannot open target for writing: {exc}",
                code="WRITE_REFUSED",
                details={"resource": action.resource},
            ) from exc
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise ExecutionError(f"Write failed: {exc}", code="WRITE_FAILED") from exc

        readback = self._read_bytes(path, limit=len(data) + 1)
        readback_hash = self._sha256(readback)
        expected = str(action.parameters.get("expected_sha256", ""))
        ok = readback == data and (not expected or expected == readback_hash)
        return {
            "action_id": action.action_id,
            "tool": action.tool,
            "ok": ok,
            "resource": action.resource,
            "readback_sha256": readback_hash,
            "bytes": len(readback),
            "pre_image": pre_image.to_dict(),
            "capability_id": str(binding.get("capability_id", "")),
            "proposal_digest": str(binding.get("proposal_digest", "")),
        }

    def _read_bytes(self, path: Path, *, limit: int) -> bytes:
        try:
            fd = os.open(path, os.O_RDONLY | O_NOFOLLOW)
        except OSError as exc:
            raise ExecutionError(
                f"Cannot open resource for reading: {exc}", code="READ_REFUSED", details={"resource": str(path)}
            ) from exc
        try:
            with os.fdopen(fd, "rb") as handle:
                return handle.read(limit)
        finally:
            pass

    def _read_text(self, action: ActionRequest, path: Path) -> dict[str, Any]:
        max_chars = min(int(action.parameters.get("max_chars", 4000)), self.limits.max_read_bytes)
        data = self._read_bytes(path, limit=self.limits.max_read_bytes + 1)
        truncated = len(data) > self.limits.max_read_bytes
        payload = data[: self.limits.max_read_bytes]
        return {
            "action_id": action.action_id,
            "tool": action.tool,
            "ok": True,
            "resource": action.resource,
            "readback_sha256": self._sha256(payload),
            "bytes_read": len(payload),
            "truncated": truncated,
            "content": payload.decode("utf-8", errors="replace")[:max_chars],
        }

    def _run_python(self, action: ActionRequest, path: Path) -> dict[str, Any]:
        if not self.allow_python:
            raise CapabilityError(
                "run_python is disabled for this executor; enable it only inside an isolated deployment",
                code="PYTHON_EXECUTION_DISABLED",
            )
        if path.suffix != ".py" or not path.exists() or path.is_symlink():
            raise ExecutionError(
                "run_python requires an existing regular .py file inside the sandbox",
                code="PYTHON_PROGRAM_INVALID",
            )
        args = [str(item) for item in action.parameters.get("args", [])]
        if any("\x00" in item for item in args):
            raise ExecutionError("Argument contains a NUL byte", code="PYTHON_ARGS_INVALID")
        timeout = min(
            int(action.parameters.get("timeout_seconds", 5)),
            self.limits.max_python_timeout_seconds,
        )
        if timeout <= 0:
            raise ExecutionError("timeout_seconds must be positive", code="PYTHON_TIMEOUT_INVALID")
        try:
            result = self.backend.run(
                program=path,
                args=args,
                workspace=self.root,
                timeout=timeout,
                max_output_bytes=self.limits.max_python_output_bytes,
            )
        except subprocess.TimeoutExpired as exc:
            raise ExecutionError(
                f"run_python exceeded its {timeout}s wall-clock limit",
                code="PYTHON_TIMEOUT",
                details={"timeout_seconds": timeout},
            ) from exc
        result.update({"action_id": action.action_id, "tool": action.tool, "resource": action.resource})
        return result


__all__ = ["FilePreImage", "PythonBackend", "SandboxExecutor", "SubprocessBackend"]
