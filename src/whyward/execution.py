from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .capability import CapabilityBroker
from .models import ActionRequest


class SandboxExecutor:
    """Executes a tiny allowlisted tool set inside a workspace directory.

    This is a boundary and ergonomics layer, not a complete operating-system
    sandbox. Production use still needs separate OS/container identities,
    resource limits and infrastructure-level network policy.
    """

    def __init__(self, root: str | Path, broker: CapabilityBroker):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.broker = broker

    def _resolve(self, resource: str) -> Path:
        if Path(resource).is_absolute():
            raise PermissionError("Absolute resources are not allowed")
        candidate = (self.root / resource).resolve()
        if self.root != candidate and self.root not in candidate.parents:
            raise PermissionError(f"Resource escapes sandbox: {resource}")
        return candidate

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def execute(self, action: ActionRequest, capability_token: str) -> dict[str, Any]:
        self.broker.consume(capability_token, action)
        path = self._resolve(action.resource)

        if action.tool == "write_text":
            content = str(action.parameters.get("content", ""))
            data = content.encode("utf-8")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            readback = path.read_bytes()
            expected = str(action.parameters.get("expected_sha256", ""))
            readback_hash = self._sha256(readback)
            ok = readback == data and (not expected or expected == readback_hash)
            return {
                "action_id": action.action_id,
                "tool": action.tool,
                "ok": ok,
                "resource": action.resource,
                "readback_sha256": readback_hash,
                "bytes": len(readback),
            }

        if action.tool == "read_text":
            data = path.read_bytes()
            max_chars = int(action.parameters.get("max_chars", 4000))
            return {
                "action_id": action.action_id,
                "tool": action.tool,
                "ok": True,
                "resource": action.resource,
                "readback_sha256": self._sha256(data),
                "content": data.decode("utf-8", errors="replace")[:max_chars],
            }

        if action.tool == "run_python":
            if path.suffix != ".py" or not path.exists():
                raise FileNotFoundError("run_python requires an existing .py file inside the sandbox")
            args = [str(item) for item in action.parameters.get("args", [])]
            timeout = min(int(action.parameters.get("timeout_seconds", 5)), 30)
            env = {
                "PATH": os.environ.get("PATH", ""),
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            completed = subprocess.run(
                [sys.executable, str(path), *args],
                cwd=str(self.root),
                env=env,
                shell=False,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            output = (completed.stdout + completed.stderr).encode("utf-8", errors="replace")
            return {
                "action_id": action.action_id,
                "tool": action.tool,
                "ok": completed.returncode == 0,
                "resource": action.resource,
                "returncode": completed.returncode,
                "stdout_sha256": self._sha256(output),
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            }

        raise ValueError(f"Unsupported sandbox tool: {action.tool}")
