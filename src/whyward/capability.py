from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import asdict
from typing import Iterable

from .models import ActionRequest
from .policy import canonical_json


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def action_fingerprint(action: ActionRequest) -> str:
    return hashlib.sha256(canonical_json(asdict(action)).encode("utf-8")).hexdigest()


class CapabilityBroker:
    """Issues signed, scoped, expiring, one-use action capabilities.

    In this MVP the used-token registry is in memory. A production deployment
    should keep it in the Control Core's durable state and keep the signing key
    outside every worker identity.
    """

    def __init__(self, secret: bytes):
        if len(secret) < 16:
            raise ValueError("Capability secret must be at least 16 bytes")
        self._secret = secret
        self._used: set[str] = set()
        self._lock = threading.Lock()

    def issue(
        self,
        *,
        proposal_id: str,
        actions: Iterable[ActionRequest],
        ttl_seconds: int = 300,
    ) -> str:
        payload = {
            "capability_id": secrets.token_hex(16),
            "proposal_id": proposal_id,
            "actions": [
                {
                    "action_id": action.action_id,
                    "tool": action.tool,
                    "resource": action.resource,
                    "fingerprint": action_fingerprint(action),
                }
                for action in actions
            ],
            "expires_at": int(time.time()) + int(ttl_seconds),
            "nonce": secrets.token_hex(16),
        }
        encoded = _b64encode(canonical_json(payload).encode("utf-8"))
        signature = hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
        return f"{encoded}.{_b64encode(signature)}"

    def _decode(self, token: str) -> dict:
        try:
            encoded, encoded_signature = token.split(".", 1)
        except ValueError as exc:
            raise PermissionError("Malformed capability token") from exc
        expected = hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
        try:
            provided = _b64decode(encoded_signature)
        except Exception as exc:
            raise PermissionError("Malformed capability signature") from exc
        if not hmac.compare_digest(expected, provided):
            raise PermissionError("Capability signature is invalid")
        try:
            return json.loads(_b64decode(encoded).decode("utf-8"))
        except Exception as exc:
            raise PermissionError("Malformed capability payload") from exc

    def consume(self, token: str, action: ActionRequest) -> dict:
        payload = self._decode(token)
        if int(payload.get("expires_at", 0)) < int(time.time()):
            raise PermissionError("Capability has expired")
        fingerprint = action_fingerprint(action)
        authorized = {
            (item.get("action_id"), item.get("tool"), item.get("resource"), item.get("fingerprint"))
            for item in payload.get("actions", [])
        }
        if (action.action_id, action.tool, action.resource, fingerprint) not in authorized:
            raise PermissionError("Action is outside capability scope")
        use_key = f"{payload.get('capability_id')}:{action.action_id}:{fingerprint}"
        with self._lock:
            if use_key in self._used:
                raise PermissionError("Capability for this action was already used")
            self._used.add(use_key)
        return payload
