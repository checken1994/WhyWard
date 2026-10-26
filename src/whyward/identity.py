"""Signing keys, signed envelopes and API token verification.

WhyWard is deliberately dependency-free, so signatures use HMAC-SHA256 with
per-role keys held in a Keyring. The interface is small enough to swap for
Ed25519/KMS/HSM later without touching call sites: everything that crosses a
trust boundary is a ``SignedEnvelope`` verified through a ``Keyring``.

Trust rule: a signature is only meaningful if the key id is *listed in the policy*
and the key material comes from outside the worker's write boundary. A signature
whose key id is unknown is treated as invalid, never as "legacy unsigned".
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import canonical_json, sha256_text
from .errors import AuthenticationError, ConfigurationError, IntegrityError

SIGNATURE_ALGORITHM = "hmac-sha256"
_MIN_KEY_BYTES = 32
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _coerce_key(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        key = value
    else:
        text = value.strip()
        if text.startswith("hex:"):
            key = bytes.fromhex(text[4:])
        elif text.startswith("b64:"):
            import base64

            key = base64.urlsafe_b64decode(text[4:] + "=" * (-len(text[4:]) % 4))
        else:
            key = text.encode("utf-8")
    if len(key) < _MIN_KEY_BYTES:
        raise ConfigurationError(
            f"Signing key must be at least {_MIN_KEY_BYTES} bytes of entropy",
            code="WEAK_SIGNING_KEY",
        )
    return key


class Keyring:
    """Named signing keys loaded from configuration, never from the workspace."""

    def __init__(self, keys: Mapping[str, str | bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = {}
        for key_id, value in (keys or {}).items():
            self.add(key_id, value)

    def add(self, key_id: str, value: str | bytes) -> None:
        if not _KEY_ID_RE.match(key_id or ""):
            raise ConfigurationError(f"Invalid key id: {key_id!r}", code="INVALID_KEY_ID")
        self._keys[key_id] = _coerce_key(value)

    def get(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise IntegrityError(f"Unknown signing key id: {key_id!r}", code="UNKNOWN_KEY_ID") from exc

    def has(self, key_id: str) -> bool:
        return key_id in self._keys

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    @classmethod
    def from_env(cls, prefix: str = "WHYWARD_KEY_") -> Keyring:
        """Load keys from environment variables ``WHYWARD_KEY_<ID>=<value>``."""
        keys: dict[str, str] = {}
        for name, value in os.environ.items():
            if not name.startswith(prefix) or not value:
                continue
            key_id = name[len(prefix) :].replace("__", "-").lower()
            keys[key_id] = value
        return cls(keys)

    @classmethod
    def from_file(cls, path: str | Path) -> Keyring:
        import json

        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ConfigurationError("Keyring file must contain a JSON object of key_id -> key")
        return cls({str(k): v for k, v in raw.items()})

    @classmethod
    def generate(cls, key_id: str = "whyward-dev") -> Keyring:
        return cls({key_id: secrets.token_hex(32)})

    @classmethod
    def demo(cls) -> Keyring:
        """Keyring for the checked-in demo fixtures. NOT for production."""
        demo_file = Path(__file__).resolve().parents[2] / "examples" / "keys" / "demo.keyring.json"
        if demo_file.exists():
            return cls.from_file(demo_file)
        return cls({"demo-manifest-2026": "whyward-demo-key-not-for-production" * 2})


@dataclass(frozen=True)
class SignedEnvelope:
    """A payload plus the metadata needed to verify who signed it."""

    payload: dict[str, Any]
    key_id: str
    signature: str
    algorithm: str = SIGNATURE_ALGORITHM

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "signature": {
                "algorithm": self.algorithm,
                "key_id": self.key_id,
                "value": self.signature,
            },
        }


def sign_payload(key: bytes, payload: Any) -> str:
    body = canonical_json(payload).encode("utf-8")
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_signature(key: bytes, payload: Any, signature: str) -> bool:
    expected = sign_payload(key, payload)
    return hmac.compare_digest(expected, str(signature or ""))


def verify_envelope(
    envelope: Mapping[str, Any],
    keyring: Keyring,
    *,
    allowed_key_ids: Iterable[str] | None = None,
    payload_key: str = "payload",
    require: bool = True,
) -> bool:
    """Verify a ``{payload, signature:{...}}`` document. Fail closed."""
    signature_block = envelope.get("signature")
    payload = envelope.get(payload_key)
    if not isinstance(signature_block, Mapping) or not isinstance(payload, Mapping):
        if require:
            raise IntegrityError("Missing signature block or payload", code="UNSIGNED_ARTIFACT")
        return False
    algorithm = str(signature_block.get("algorithm", ""))
    if algorithm != SIGNATURE_ALGORITHM:
        raise IntegrityError(f"Unsupported signature algorithm: {algorithm!r}", code="UNSUPPORTED_SIGNATURE")
    key_id = str(signature_block.get("key_id", ""))
    if allowed_key_ids is not None and key_id not in set(allowed_key_ids):
        raise IntegrityError(
            f"Signing key {key_id!r} is not trusted by policy",
            code="UNTRUSTED_SIGNING_KEY",
            details={"key_id": key_id, "allowed": sorted(set(allowed_key_ids))},
        )
    key = keyring.get(key_id)
    if not verify_signature(key, payload, str(signature_block.get("value", ""))):
        raise IntegrityError("Signature verification failed", code="BAD_SIGNATURE")
    return True


def sign_document(payload: Mapping[str, Any], key_id: str, key: bytes) -> dict[str, Any]:
    return {
        "payload": dict(payload),
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "value": sign_payload(key, payload),
        },
    }


API_TOKEN_PREFIX = "ww_"
_TOKEN_RE = re.compile(r"^ww_[A-Za-z0-9_-]{20,200}$")


def hash_token(token: str) -> str:
    return sha256_text(token)


def generate_api_token() -> str:
    return API_TOKEN_PREFIX + secrets.token_urlsafe(32)


@dataclass(frozen=True)
class ApiPrincipal:
    subject: str
    scopes: frozenset[str] = frozenset()
    token_hash: str = ""

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "admin" in self.scopes


@dataclass
class ApiTokenStore:
    """Bearer-token store. Only hashes of tokens are kept in memory/config."""

    principals: dict[str, ApiPrincipal] = field(default_factory=dict)

    def add(self, token: str, subject: str, scopes: Iterable[str]) -> None:
        if not _TOKEN_RE.match(token or ""):
            raise ConfigurationError(
                "API token must be prefixed with 'ww_' and be at least 23 characters",
                code="WEAK_API_TOKEN",
            )
        self.principals[hash_token(token)] = ApiPrincipal(
            subject=subject, scopes=frozenset(scopes), token_hash=hash_token(token)
        )

    def add_hashed(self, token_hash: str, subject: str, scopes: Iterable[str]) -> None:
        self.principals[token_hash] = ApiPrincipal(subject=subject, scopes=frozenset(scopes), token_hash=token_hash)

    def authenticate(self, authorization_header: str | None) -> ApiPrincipal:
        if not authorization_header:
            raise AuthenticationError("Missing Authorization header", code="MISSING_CREDENTIALS")
        scheme, _, credential = authorization_header.partition(" ")
        if scheme.lower() != "bearer" or not credential.strip():
            raise AuthenticationError("Expected 'Authorization: Bearer <token>'", code="UNSUPPORTED_AUTH_SCHEME")
        credential = credential.strip()
        candidate = hash_token(credential)
        # Constant-time scan over stored hashes to avoid a trivial timing oracle.
        match: ApiPrincipal | None = None
        for token_hash, principal in self.principals.items():
            if hmac.compare_digest(token_hash, candidate):
                match = principal
        if match is None:
            raise AuthenticationError("Invalid API token", code="INVALID_CREDENTIALS")
        return match

    @classmethod
    def from_file(cls, path: str | Path) -> ApiTokenStore:
        import json

        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        store = cls()
        entries = raw.get("tokens", raw) if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            raise ConfigurationError("Token file must contain a list of token entries")
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ConfigurationError("Each token entry must be an object")
            if "token" in entry:
                store.add(str(entry["token"]), str(entry["subject"]), entry.get("scopes", []))
            elif "token_sha256" in entry:
                store.add_hashed(str(entry["token_sha256"]), str(entry["subject"]), entry.get("scopes", []))
            else:
                raise ConfigurationError("Token entry needs 'token' or 'token_sha256'")
        return store

    @classmethod
    def from_env(cls, variable: str = "WHYWARD_API_TOKENS") -> ApiTokenStore:
        import json

        raw = os.environ.get(variable, "").strip()
        if not raw:
            raise ConfigurationError(
                "No API tokens configured. Set WHYWARD_API_TOKENS or pass --token-file.",
                code="NO_API_TOKENS",
            )
        store = cls()
        for entry in json.loads(raw):
            if "token" in entry:
                store.add(str(entry["token"]), str(entry["subject"]), entry.get("scopes", []))
            else:
                store.add_hashed(str(entry["token_sha256"]), str(entry["subject"]), entry.get("scopes", []))
        return store
