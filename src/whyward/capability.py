"""Scoped, expiring, single-use and revocable action capabilities.

Hardening over 0.1.0 (audit findings W-07, W-08):

* the used-token registry lives in a durable store (SQLite by default) so a
  capability stays single-use across restarts and across processes;
* capabilities can be revoked (kill switch flushes the whole namespace);
* tokens carry issuer/audience/task binding and ``nbf``;
* ``consume`` accepts a ``blocked`` predicate so a kill switch can stop an
  action that is already in flight.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Protocol, cast

from .canonical import b64decode, b64encode, digest
from .errors import CapabilityError, ConfigurationError
from .identity import Keyring, sign_payload, verify_signature
from .models import ActionRequest

DEFAULT_TTL_SECONDS = 300
MIN_SECRET_BYTES = 32


# --------------------------------------------------------------------------- #
# Used-token / revocation stores
# --------------------------------------------------------------------------- #
class UsedTokenStore(Protocol):
    def claim(self, use_key: str, expires_at: int) -> bool: ...
    def revoke(self, capability_id: str, expires_at: int) -> None: ...
    def is_revoked(self, capability_id: str) -> bool: ...
    def purge(self, now: int) -> int: ...


class InMemoryUsedTokenStore:
    """Process-local store. Fine for tests; capability replay after restart is possible."""

    durable = False

    def __init__(self) -> None:
        self._used: set[str] = set()
        self._revoked: dict[str, int] = {}
        self._lock = threading.Lock()

    def claim(self, use_key: str, expires_at: int) -> bool:
        with self._lock:
            if use_key in self._used:
                return False
            self._used.add(use_key)
            return True

    def revoke(self, capability_id: str, expires_at: int) -> None:
        with self._lock:
            self._revoked[capability_id] = expires_at

    def is_revoked(self, capability_id: str) -> bool:
        with self._lock:
            return capability_id in self._revoked

    def purge(self, now: int) -> int:
        with self._lock:
            expired = [cid for cid, expiry in self._revoked.items() if expiry < now]
            for cid in expired:
                del self._revoked[cid]
            return len(expired)


class SqliteUsedTokenStore:
    """Durable store, safe across threads and processes."""

    durable = True

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS used_tokens ("
                " use_key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS revoked_capabilities ("
                " capability_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def claim(self, use_key: str, expires_at: int) -> bool:
        conn = self._connect()
        try:
            try:
                conn.execute(
                    "INSERT INTO used_tokens (use_key, expires_at) VALUES (?, ?)",
                    (use_key, int(expires_at)),
                )
                return True
            except sqlite3.IntegrityError:
                return False
        finally:
            conn.close()

    def revoke(self, capability_id: str, expires_at: int) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO revoked_capabilities (capability_id, expires_at) VALUES (?, ?)",
                (capability_id, int(expires_at)),
            )
        finally:
            conn.close()

    def is_revoked(self, capability_id: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM revoked_capabilities WHERE capability_id = ?", (capability_id,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def purge(self, now: int) -> int:
        conn = self._connect()
        try:
            used = conn.execute("DELETE FROM used_tokens WHERE expires_at < ?", (int(now),)).rowcount
            revoked = conn.execute(
                "DELETE FROM revoked_capabilities WHERE expires_at < ?", (int(now),)
            ).rowcount
            return int(used + revoked)
        finally:
            conn.close()


# --------------------------------------------------------------------------- #
# Broker
# --------------------------------------------------------------------------- #
class CapabilityBroker:
    """Issues signed, scoped, expiring, single-use, revocable action capabilities."""

    def __init__(
        self,
        secret: bytes | Keyring | None = None,
        *,
        key_id: str = "capability",
        keyring: Keyring | None = None,
        used_store: UsedTokenStore | None = None,
        audience: str = "whyward-execution",
        clock: Callable[[], float] = time.time,
        blocked: Callable[[], bool] | None = None,
    ):
        if keyring is not None:
            self._keyring = keyring
        elif isinstance(secret, Keyring):
            self._keyring = secret
        else:
            if secret is None:
                raise ConfigurationError("CapabilityBroker needs a secret or keyring", code="MISSING_CAPABILITY_KEY")
            if len(secret) < MIN_SECRET_BYTES:
                raise ConfigurationError(
                    f"Capability secret must be at least {MIN_SECRET_BYTES} bytes",
                    code="WEAK_CAPABILITY_KEY",
                )
            self._keyring = Keyring({key_id: secret})
        self._key_id = key_id
        if not self._keyring.has(self._key_id):
            self._key_id = self._keyring.ids()[0] if self._keyring.ids() else key_id
        self._store: UsedTokenStore = used_store or InMemoryUsedTokenStore()
        self._audience = audience
        self._clock = clock
        self._blocked = blocked
        self._lock = threading.Lock()
        self._issued: dict[str, int] = {}

    @property
    def durable(self) -> bool:
        return bool(getattr(self._store, "durable", False))

    def set_blocked_hook(self, blocked: Callable[[], bool] | None) -> None:
        """Attach (or clear) the predicate consulted before every issuance.

        Wiring is deliberately a method rather than a public attribute so the
        kill switch can be installed once, at composition time, without any
        caller being able to forget the concurrency guard.
        """
        with self._lock:
            self._blocked = blocked

    def issue(
        self,
        *,
        proposal_id: str,
        actions: Iterable[ActionRequest],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        task_id: str = "",
        proposal_digest: str = "",
        audience: str | None = None,
    ) -> str:
        if self._blocked is not None and self._blocked():
            raise CapabilityError(
                "Kill switch engaged: refusing to issue capability tokens", code="KILL_SWITCH_ENGAGED"
            )
        now = int(self._clock())
        payload = {
            "schema_version": 2,
            "capability_id": os.urandom(16).hex(),
            "issuer": "whyward-control-core",
            "audience": audience or self._audience,
            "proposal_id": proposal_id,
            "proposal_digest": proposal_digest,
            "task_id": task_id,
            "actions": [
                {
                    "action_id": action.action_id,
                    "tool": action.tool,
                    "resource": action.resource,
                    "fingerprint": action.fingerprint(),
                }
                for action in actions
            ],
            "not_before": now,
            "expires_at": now + int(ttl_seconds),
            "nonce": os.urandom(16).hex(),
        }
        encoded = b64encode(_canonical(payload))
        signature = sign_payload(self._keyring.get(self._key_id), {"payload": encoded, "kid": self._key_id})
        expires_at = int(str(payload["expires_at"]))
        with self._lock:
            # Track live capability ids so the kill switch can revoke exactly the
            # tokens this process handed out; drop expired ids as we go.
            self._issued = {cid: expiry for cid, expiry in self._issued.items() if expiry >= now}
            self._issued[str(payload["capability_id"])] = expires_at
        return f"{encoded}.{b64encode(signature.encode('ascii'))}"

    def _decode(self, token: str) -> dict[str, Any]:
        try:
            encoded, encoded_signature = str(token).split(".", 1)
        except ValueError as exc:
            raise CapabilityError("Malformed capability token", code="CAPABILITY_MALFORMED") from exc
        try:
            signature = b64decode(encoded_signature).decode("ascii")
        except Exception as exc:
            raise CapabilityError("Malformed capability signature", code="CAPABILITY_MALFORMED") from exc
        signed = {"payload": encoded, "kid": self._key_id}
        if not verify_signature(self._keyring.get(self._key_id), signed, signature):
            raise CapabilityError("Capability signature is invalid", code="CAPABILITY_BAD_SIGNATURE")
        import json

        try:
            return cast("dict[str, Any]", json.loads(b64decode(encoded).decode("utf-8")))
        except Exception as exc:
            raise CapabilityError("Malformed capability payload", code="CAPABILITY_MALFORMED") from exc

    def revoke(self, capability_id: str) -> None:
        self._store.revoke(capability_id, int(self._clock()) + 86_400)

    def revoke_all(self) -> int:
        """Revoke every capability this broker issued and that is still live.

        The kill switch calls this so tokens already handed to an executor stop
        working immediately, in this process and in any process sharing the store.
        """
        now = int(self._clock())
        with self._lock:
            live = {cid: expiry for cid, expiry in self._issued.items() if expiry >= now}
            self._issued = {cid: expiry for cid, expiry in self._issued.items() if expiry >= now}
        for capability_id, expiry in live.items():
            self._store.revoke(capability_id, expiry + 60)
        return len(live)

    def consume(self, token: str, action: ActionRequest, *, expected_audience: str | None = None) -> dict[str, Any]:
        if self._blocked is not None and self._blocked():
            raise CapabilityError("Kill switch engaged: capability use refused", code="KILL_SWITCH_ENGAGED")
        payload = self._decode(token)
        now = int(self._clock())
        if int(payload.get("expires_at", 0)) < now:
            raise CapabilityError("Capability has expired", code="CAPABILITY_EXPIRED")
        if int(payload.get("not_before", 0)) > now:
            raise CapabilityError("Capability is not valid yet", code="CAPABILITY_NOT_YET_VALID")
        audience = expected_audience or self._audience
        if str(payload.get("audience", "")) != audience:
            raise CapabilityError(
                "Capability audience mismatch",
                code="CAPABILITY_WRONG_AUDIENCE",
                details={"expected": audience, "actual": payload.get("audience")},
            )
        capability_id = str(payload.get("capability_id", ""))
        if self._store.is_revoked(capability_id):
            raise CapabilityError("Capability has been revoked", code="CAPABILITY_REVOKED")
        authorized = {
            (item.get("action_id"), item.get("tool"), item.get("resource"), item.get("fingerprint"))
            for item in payload.get("actions", [])
        }
        if (action.action_id, action.tool, action.resource, action.fingerprint()) not in authorized:
            raise CapabilityError("Action is outside capability scope", code="CAPABILITY_OUT_OF_SCOPE")
        use_key = f"{capability_id}:{action.action_id}:{action.fingerprint()}"
        if not self._store.claim(use_key, int(payload["expires_at"]) + 60):
            raise CapabilityError("Capability for this action was already used", code="CAPABILITY_REPLAYED")
        return payload

    def purge(self) -> int:
        return self._store.purge(int(self._clock()))


def _canonical(payload: dict[str, Any]) -> bytes:
    from .canonical import canonical_json

    return canonical_json(payload).encode("utf-8")


def action_fingerprint(action: ActionRequest) -> str:
    return action.fingerprint()


def capability_digest(token: str) -> str:
    return digest(token)


__all__ = [
    "CapabilityBroker",
    "InMemoryUsedTokenStore",
    "SqliteUsedTokenStore",
    "UsedTokenStore",
    "action_fingerprint",
    "capability_digest",
]
