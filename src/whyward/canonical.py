"""Canonical serialization and hashing used by every signed/audited boundary.

Why this module exists: signatures, capability fingerprints, proposal digests and
ledger hashes must all agree byte-for-byte across processes and platforms. A
single canonical implementation prevents the classic bug where two components
serialize the "same" object differently and silently stop verifying.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from collections.abc import Mapping
from enum import Enum
from typing import Any


def jsonable(value: Any) -> Any:
    """Convert dataclasses/enums/tuples/sets into deterministic JSON values."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: jsonable(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((jsonable(item) for item in value), key=lambda item: canonical_json(item))
    if isinstance(value, bytes):
        return _b64encode(value)
    return value


def canonical_json(data: Any) -> str:
    return json.dumps(jsonable(data), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64encode(data: bytes) -> str:
    return _b64encode(data)


def b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))
