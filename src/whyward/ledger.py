from __future__ import annotations

import hashlib
import hmac
import json
import threading
from pathlib import Path
from typing import Any

from .models import now_iso
from .policy import canonical_json


class Ledger:
    """Append-only JSONL hash chain.

    This detects later edits to recorded events. It does not by itself stop a
    host/root attacker from replacing the whole file; checkpoints must be
    copied or anchored outside the worker's write boundary.
    """

    GENESIS = "0" * 64

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index = 0
        self._head = self.GENESIS
        if self.path.exists() and self.path.stat().st_size:
            valid, message = self.verify()
            if not valid:
                raise ValueError(f"Existing ledger is invalid: {message}")
            events = self._read_events()
            self._index = len(events)
            self._head = str(events[-1]["event_hash"])

    def _read_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        for line_no, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at ledger line {line_no}") from exc
        return events

    @staticmethod
    def _hash_event(core: dict[str, Any]) -> str:
        return hashlib.sha256(canonical_json(core).encode("utf-8")).hexdigest()

    def append(self, event_type: str, actor: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._index += 1
            core = {
                "index": self._index,
                "timestamp": now_iso(),
                "event_type": event_type,
                "actor": actor,
                "payload": payload,
                "prev_hash": self._head,
            }
            event_hash = self._hash_event(core)
            event = {**core, "event_hash": event_hash}
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(canonical_json(event) + "\n")
            self._head = event_hash
            return event

    def verify(self) -> tuple[bool, str]:
        try:
            events = self._read_events()
        except ValueError as exc:
            return False, str(exc)
        previous = self.GENESIS
        for expected_index, event in enumerate(events, start=1):
            if event.get("index") != expected_index:
                return False, f"Unexpected index at event {expected_index}"
            if event.get("prev_hash") != previous:
                return False, f"Broken hash link at event {expected_index}"
            core = {
                "index": event.get("index"),
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "actor": event.get("actor"),
                "payload": event.get("payload"),
                "prev_hash": event.get("prev_hash"),
            }
            if self._hash_event(core) != event.get("event_hash"):
                return False, f"Hash mismatch at event {expected_index}"
            previous = str(event["event_hash"])
        return True, "ok"

    def checkpoint(self, *, signing_key: bytes | None = None) -> dict[str, Any]:
        valid, message = self.verify()
        if not valid:
            raise ValueError(f"Cannot checkpoint invalid ledger: {message}")
        events = self._read_events()
        checkpoint = {
            "created_at": now_iso(),
            "event_count": len(events),
            "head_hash": events[-1]["event_hash"] if events else self.GENESIS,
            "ledger_name": self.path.name,
        }
        if signing_key is not None:
            checkpoint["signature"] = hmac.new(
                signing_key,
                canonical_json(checkpoint).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        return checkpoint
