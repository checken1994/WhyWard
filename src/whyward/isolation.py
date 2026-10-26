"""Optional container isolation for the execution domain.

WhyWard's executor is a *boundary* layer. Real isolation needs an OS/container
runtime. This module provides a backend that runs ``run_python`` inside a
container with:

* no network (``--network=none``);
* read-only root filesystem, workspace mounted rw;
* all Linux capabilities dropped, ``no-new-privileges``;
* PID/memory/CPU limits;
* a non-root user inside the container;
* an automatically removed container after each run.

If no container runtime is available the backend refuses to run (fail closed)
instead of silently falling back to host execution.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, ExecutionError

#: tmpfs mounted inside the container only; the host /tmp is never exposed.
CONTAINER_TMPFS_SPEC = "/tmp:rw,noexec,nosuid,size=16m"  # noqa: S108  # nosec B108


@dataclass(frozen=True)
class ContainerPolicy:
    runtime: str = "auto"
    image: str = "python:3.12-slim"
    network: str = "none"
    memory: str = "256m"
    cpus: str = "0.5"
    pids_limit: int = 64
    user: str = "65534:65534"
    read_only_root: bool = True
    extra_args: tuple[str, ...] = field(default_factory=tuple)


def build_container_command(
    runtime: str,
    policy: ContainerPolicy,
    *,
    program_name: str,
    args: list[str],
    workspace: Path,
) -> list[str]:
    """Pure command builder: testable without a container runtime installed."""
    cmd = [
        runtime,
        "run",
        "--rm",
        "--network",
        policy.network,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(policy.pids_limit),
        "--memory",
        policy.memory,
        "--cpus",
        policy.cpus,
        "--user",
        policy.user,
        "--tmpfs",
        CONTAINER_TMPFS_SPEC,
        "-v",
        f"{workspace}:/work:rw",
        "-w",
        "/work",
    ]
    if policy.read_only_root:
        cmd.append("--read-only")
    cmd.extend(policy.extra_args)
    cmd.extend([policy.image, "python", "-I", f"/work/{program_name}", *args])
    return cmd


class DockerSandboxBackend:
    name = "container"

    def __init__(self, policy: ContainerPolicy | None = None, *, runtime: str | None = None) -> None:
        self.policy = policy or ContainerPolicy()
        self._runtime = self._detect(runtime or self.policy.runtime)
        if not self._runtime:
            raise ConfigurationError(
                "No container runtime found (docker/podman). Refusing to fall back to host execution.",
                code="NO_CONTAINER_RUNTIME",
            )

    @staticmethod
    def _detect(preferred: str) -> str:
        if preferred != "auto":
            if os.path.isabs(preferred) and os.access(preferred, os.X_OK):
                return preferred
            found = shutil.which(preferred)
            return found or ""
        for candidate in ("docker", "podman"):
            found = shutil.which(candidate)
            if found:
                return found
        return ""

    @property
    def available(self) -> bool:
        return bool(self._runtime)

    def command(self, *, program: Path, args: list[str], workspace: Path, timeout: int) -> list[str]:
        return build_container_command(
            self._runtime,
            self.policy,
            program_name=program.name,
            args=args,
            workspace=workspace,
        )

    def run(self, *, program: Path, args: list[str], workspace: Path, timeout: int,
            max_output_bytes: int) -> dict[str, Any]:
        cmd = self.command(program=program, args=args, workspace=workspace, timeout=timeout)
        try:
            completed = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                timeout=timeout + 5,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ExecutionError("Container runtime disappeared", code="RUNTIME_MISSING") from exc
        except subprocess.TimeoutExpired as exc:
            raise ExecutionError(
                f"Container run exceeded {timeout}s", code="CONTAINER_TIMEOUT"
            ) from exc
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
            "command_template": " ".join(cmd[:4]) + " ...",
        }

    @classmethod
    def try_create(cls, policy: ContainerPolicy | None = None) -> DockerSandboxBackend | None:
        try:
            return cls(policy)
        except ConfigurationError:
            return None


def isolation_report() -> dict[str, Any]:
    """Machine-readable statement of how isolated the current process is."""
    backend = DockerSandboxBackend.try_create()
    return {
        "container_runtime": backend._runtime if backend else "",
        "recommended_backend": "container" if backend else "subprocess-rlimit",
        "warning": (
            ""
            if backend
            else "No container runtime detected: run_python would execute as the host UID. "
            "Keep run_python disabled or deploy WhyWard inside a container."
        ),
    }
