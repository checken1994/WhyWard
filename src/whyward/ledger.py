"""Append-only, tamper-evident audit ledger.

Hardening over 0.1.0 (audit findings W-06, W-09, plus the "no truncation
detection" gap):

* cross-process exclusive lock (``fcntl.flock`` / ``msvcrt.locking``);
* ``flush`` + ``fsync`` before returning from ``append``;
* tail state is re-read under the lock, so concurrent writers cannot fork the
  chain;
* events carry a schema version, a ULID ``event_id`` and a W3C ``trace_id``;
* events can be signed (HMAC) and verification fails closed on unknown keys;
* ``checkpoint`` can be exported to an external anchor file and
  ``verify_against_anchor`` detects whole-file replacement/truncation.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .canonical import canonical_json, sha256_text
from .errors import IntegrityError
from .identity import Keyring, sign_payload, verify_signature
from .models import LEDGER_EVENT_SCHEMA_VERSION, now_iso

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_event_id() -> str:
    """Monotonic-ish ULID (48-bit ms timestamp + 80 random bits)."""
    timestamp = int(time.time() * 1000) & ((1 << 48) - 1)
    randomness = secrets.randbits(80)
    value = (timestamp << 80) | randomness
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


@dataclass(frozen=True)
class LedgerEvent:
    event_id: str
    index: int
    timestamp: str
    event_type: str
    actor: dict[str, Any]
    payload: dict[str, Any]
    prev_hash: str
    event_hash: str
    trace_id: str = ""
    schema_version: int = LEDGER_EVENT_SCHEMA_VERSION
    signature: dict[str, Any] | None = None

    def core(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor": self.actor,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "trace_id": self.trace_id,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.core()
        data["event_hash"] = self.event_hash
        if self.signature:
            data["signature"] = self.signature
        return data


def _hash_core(core: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(core).encode("utf-8")).hexdigest()


class _FileLock:
    """Portable cross-process lock built on atomic exclusive file creation.

    ``fcntl``/``msvcrt`` behave differently across platforms (and quietly fail on
    some filesystems), which is exactly the failure mode an audit trail cannot
    afford. ``O_CREAT | O_EXCL`` is atomic on every supported platform, so the
    lock is a file that either exists or does not.

    A crashed writer can leave the lock behind; locks older than
    ``stale_after`` seconds are broken, and the wait is bounded by ``timeout``
    so a stuck lock degrades into a loud error instead of a silent hang.
    """

    def __init__(self, path: Path, *, timeout: float = 15.0, stale_after: float = 60.0) -> None:
        self.path = Path(f"{path}.lock")
        self.timeout = timeout
        self.stale_after = stale_after
        self._fd: int | None = None

    def __enter__(self) -> _FileLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(self._fd, f"{os.getpid()}\n".encode("ascii"))
                return self
            except (FileExistsError, PermissionError):
                # Windows reports a sharing violation (WinError 32) instead of
                # "file exists" when another process still holds the lock file.
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:  # released between the two calls
                    continue
                if age > self.stale_after:
                    with contextlib.suppress(OSError):
                        self.path.unlink()
                    continue
                if time.monotonic() > deadline:
                    raise IntegrityError(
                        f"Ledger lock is held by another writer: {self.path}",
                        code="LEDGER_LOCKED",
                        details={"path": str(self.path), "timeout_seconds": self.timeout},
                    ) from None
                time.sleep(0.002)

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None
        with contextlib.suppress(FileNotFoundError):
            self.path.unlink()


class Ledger:
    GENESIS = "0" * 64

    def __init__(
        self,
        path: str | Path,
        *,
        signing_key_id: str = "",
        keyring: Keyring | None = None,
        require_signature: bool = False,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._keyring = keyring
        self._signing_key_id = signing_key_id
        self._require_signature = require_signature
        self._index = 0
        self._head = self.GENESIS
        if self.path.exists() and self.path.stat().st_size:
            valid, message = self.verify()
            if not valid:
                raise IntegrityError(
                    f"Existing ledger is invalid: {message}",
                    code="LEDGER_INVALID",
                    details={"path": str(self.path), "reason": message},
                )
            events = self._read_events()
            self._index = len(events)
            self._head = events[-1]["event_hash"]

    # ------------------------------------------------------------------ #
    # Reading
    # ------------------------------------------------------------------ #
    def _read_events(self) -> list[dict[str, Any]]:
        return list(self.iter_events())

    def iter_events(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        def _gen() -> Iterator[dict[str, Any]]:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_no, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        yield cast(dict[str, Any], json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise IntegrityError(
                            f"Invalid JSON at ledger line {line_no}",
                            code="LEDGER_CORRUPT",
                        ) from exc
        return _gen()

    @property
    def head(self) -> str:
        return self._head

    @property
    def event_count(self) -> int:
        return self._index

    def _reload_tail(self) -> None:
        events = self._read_events()
        self._index = len(events)
        self._head = str(events[-1]["event_hash"]) if events else self.GENESIS

    # ------------------------------------------------------------------ #
    # Writing
    # ------------------------------------------------------------------ #
    def _sign(self, core: Mapping[str, Any]) -> dict[str, Any] | None:
        if not (self._keyring and self._signing_key_id):
            return None
        if not self._keyring.has(self._signing_key_id):
            return None
        return {
            "algorithm": "hmac-sha256",
            "key_id": self._signing_key_id,
            "value": sign_payload(self._keyring.get(self._signing_key_id), core),
        }

    def append(
        self,
        event_type: str,
        actor: str | Mapping[str, Any],
        payload: Mapping[str, Any],
        *,
        trace_id: str = "",
    ) -> dict[str, Any]:
        actor_block = dict(actor) if isinstance(actor, Mapping) else {"kind": "name", "name": str(actor)}
        with self._lock, _FileLock(self.path), self.path.open("a+", encoding="utf-8") as handle:
            self._reload_tail()
            core = {
                "schema_version": LEDGER_EVENT_SCHEMA_VERSION,
                "event_id": new_event_id(),
                "index": self._index + 1,
                "timestamp": now_iso(),
                "event_type": event_type,
                "actor": actor_block,
                "payload": dict(payload),
                "prev_hash": self._head,
                "trace_id": trace_id,
            }
            event_hash = _hash_core(core)
            event = {**core, "event_hash": event_hash}
            signature = self._sign(core)
            if signature:
                event["signature"] = signature
            handle.write(canonical_json(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            self._index += 1
            self._head = event_hash
            return event

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self) -> tuple[bool, str]:
        previous = self.GENESIS
        expected_index = 1
        for event in self.iter_events():
            if event.get("index") != expected_index:
                return False, f"Unexpected index at event {expected_index}"
            if event.get("prev_hash") != previous:
                return False, f"Broken hash link at event {expected_index}"
            core = {
                "schema_version": event.get("schema_version", 1),
                "event_id": event.get("event_id", ""),
                "index": event.get("index"),
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "actor": event.get("actor"),
                "payload": event.get("payload"),
                "prev_hash": event.get("prev_hash"),
                "trace_id": event.get("trace_id", ""),
            }
            if _hash_core(core) != event.get("event_hash"):
                return False, f"Hash mismatch at event {expected_index}"
            signature = event.get("signature")
            if signature is not None:
                if not (self._keyring and self._keyring.has(str(signature.get("key_id", "")))):
                    return False, f"Unverifiable signature at event {expected_index}"
                key = self._keyring.get(str(signature["key_id"]))
                if not verify_signature(key, core, str(signature.get("value", ""))):
                    return False, f"Bad signature at event {expected_index}"
            elif self._require_signature:
                return False, f"Unsigned event at index {expected_index}"
            previous = str(event["event_hash"])
            expected_index += 1
        return True, "ok"

    # ------------------------------------------------------------------ #
    # Checkpoints & anchors
    # ------------------------------------------------------------------ #
    def checkpoint(self, *, signing_key_id: str = "") -> dict[str, Any]:
        valid, message = self.verify()
        if not valid:
            raise IntegrityError(f"Cannot checkpoint invalid ledger: {message}", code="LEDGER_INVALID")
        events = self._read_events()
        checkpoint = {
            "schema_version": 2,
            "created_at": now_iso(),
            "event_count": len(events),
            "head_hash": events[-1]["event_hash"] if events else self.GENESIS,
            "ledger_name": self.path.name,
        }
        key_id = signing_key_id or self._signing_key_id
        if self._keyring and key_id:
            checkpoint["signature"] = {
                "algorithm": "hmac-sha256",
                "key_id": key_id,
                "value": sign_payload(self._keyring.get(key_id), checkpoint),
            }
        return checkpoint

    def anchor(self, anchor_path: str | Path, *, signing_key_id: str = "") -> dict[str, Any]:
        """Persist a checkpoint outside the worker's write boundary."""
        destination = Path(anchor_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        checkpoint = self.checkpoint(signing_key_id=signing_key_id)
        payload = {"checkpoint": checkpoint, "ledger": str(self.path.name)}
        destination.write_text(canonical_json(payload) + "\n", encoding="utf-8")
        with destination.open("a", encoding="utf-8") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        return checkpoint

    def verify_against_anchor(self, anchor_path: str | Path) -> tuple[bool, str]:
        """Detect truncation or wholesale replacement relative to an anchor."""
        anchor_file = Path(anchor_path)
        if not anchor_file.exists():
            return False, "anchor file is missing"
        try:
            raw = anchor_file.read_text(encoding="utf-8").strip().splitlines()[0]
            anchor = json.loads(raw)
        except (OSError, json.JSONDecodeError, IndexError) as exc:
            return False, f"anchor file is unreadable: {exc}"
        checkpoint = anchor.get("checkpoint", {}) if isinstance(anchor, Mapping) else {}
        signature = checkpoint.get("signature")
        if signature and self._keyring:
            body = {k: v for k, v in checkpoint.items() if k != "signature"}
            if not self._keyring.has(str(signature.get("key_id", ""))):
                return False, "anchor signed by an unknown key"
            if not verify_signature(self._keyring.get(str(signature["key_id"])), body, str(signature.get("value", ""))):
                return False, "anchor signature is invalid"
        events = self._read_events()
        anchored_count = int(checkpoint.get("event_count", -1))
        anchored_head = str(checkpoint.get("head_hash", ""))
        if anchored_count < 0:
            return False, "anchor has no event_count"
        if len(events) < anchored_count:
            return False, f"ledger has {len(events)} events but anchor recorded {anchored_count} (truncation)"
        if anchored_count and str(events[anchored_count - 1].get("event_hash")) != anchored_head:
            return False, "ledger head at anchored index does not match anchor (rewrite)"
        return True, "ok"

    def require(self, event_type: str) -> list[dict[str, Any]]:
        return [event for event in self.iter_events() if event.get("event_type") == event_type]

    def digest(self) -> str:
        return sha256_text(str(self._head))
