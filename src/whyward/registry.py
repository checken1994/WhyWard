"""Signed evidence registry — the only place evidence review status is decided.

Audit finding W-02: previously any caller could hand the control plane an
``EvidenceRef`` claiming ``review_status="verified"`` and it was believed. Now:

* only this registry can write evidence records (workers hold no write path);
* every record is signed with a manifest/ingestion key held outside the worker;
* review status, freshness and lineage are *derived* here, never asserted by
  the proposal;
* an unknown or unsigned record is rejected with a typed error, not ignored.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json, digest, sha256_bytes
from .errors import ConfigurationError, EvidenceError
from .identity import Keyring, sign_payload, verify_signature
from .models import EvidenceRef, FreshnessState, now_iso, parse_iso

EVIDENCE_SCHEMA_VERSION = 2

REQUIRED_EVIDENCE_FIELDS = (
    "evidence_id",
    "source_id",
    "lineage_id",
    "retrieved_at",
    "observed_fields",
    "blind_spots",
    "review_status",
)

SIGNATURE_FIELDS = ("registry_signature", "registry_key_id")


def _signed_body(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in SIGNATURE_FIELDS}


def stable_body(record: Mapping[str, Any]) -> dict[str, Any]:
    """Fields that identify *what was observed*, excluding ingestion timestamps.

    Re-ingesting the same observation must be idempotent, otherwise a restart
    would produce a conflict with the record it wrote a second ago.
    """
    body = _signed_body(record)
    body.pop("registered_at", None)
    body.pop("content_hash", None)
    return body


def _coerce_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    source_id: str
    lineage_id: str
    title: str = ""
    source_url: str = ""
    retrieved_at: str = ""
    observed_fields: tuple[str, ...] = ()
    blind_spots: tuple[str, ...] = ()
    observation_method: str = ""
    review_status: str = "unverified"
    content_hash: str = ""
    source_record_id: str = ""
    freshness: dict[str, Any] = field(default_factory=dict)
    registry_key_id: str = ""
    registry_signature: str = ""
    schema_version: int = EVIDENCE_SCHEMA_VERSION
    registered_at: str = ""

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> EvidenceRecord:
        return cls(
            evidence_id=str(data.get("evidence_id", "")),
            source_id=str(data.get("source_id", "")),
            lineage_id=str(data.get("lineage_id", "")),
            title=str(data.get("title", "")),
            source_url=str(data.get("source_url", "")),
            retrieved_at=str(data.get("retrieved_at", "")),
            observed_fields=tuple(_coerce_list(data.get("observed_fields"))),
            blind_spots=tuple(_coerce_list(data.get("blind_spots"))),
            observation_method=str(data.get("observation_method", "")),
            review_status=str(data.get("review_status", "unverified")),
            content_hash=str(data.get("content_hash", "")),
            source_record_id=str(data.get("source_record_id", "")),
            freshness=dict(data.get("freshness") or {}),
            registry_key_id=str(data.get("registry_key_id", "")),
            registry_signature=str(data.get("registry_signature", "")),
            schema_version=int(data.get("schema_version", EVIDENCE_SCHEMA_VERSION)),
            registered_at=str(data.get("registered_at", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "source_record_id": self.source_record_id,
            "lineage_id": self.lineage_id,
            "title": self.title,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "observed_fields": list(self.observed_fields),
            "blind_spots": list(self.blind_spots),
            "observation_method": self.observation_method,
            "review_status": self.review_status,
            "content_hash": self.content_hash,
            "freshness": dict(self.freshness),
            "registry_key_id": self.registry_key_id,
            "registry_signature": self.registry_signature,
            "registered_at": self.registered_at,
        }

    def to_ref(self) -> EvidenceRef:
        return EvidenceRef(
            evidence_id=self.evidence_id,
            source_id=self.source_id,
            lineage_id=self.lineage_id,
            title=self.title,
            source_url=self.source_url,
            observed_fields=self.observed_fields,
            blind_spots=self.blind_spots,
            retrieved_at=self.retrieved_at,
            content_hash=self.content_hash,
            observation_method=self.observation_method,
            registry_key_id=self.registry_key_id,
            registry_signature=self.registry_signature,
            review_status=self.review_status,
        )

    def freshness_state(
        self,
        *,
        now: datetime | None = None,
        max_age_seconds_by_class: Mapping[str, int] | None = None,
    ) -> FreshnessState:
        now = now or datetime.now(UTC)
        freshness = self.freshness or {}
        for key in ("valid_until", "review_after"):
            raw = str(freshness.get(key) or "").strip()
            if raw:
                try:
                    if now > parse_iso(raw):
                        return FreshnessState.EXPIRED if key == "valid_until" else FreshnessState.REVIEW_OVERDUE
                except ValueError:
                    return FreshnessState.UNKNOWN
        age_class = str(freshness.get("class") or "").strip()
        max_age = (max_age_seconds_by_class or {}).get(age_class)
        if max_age and self.retrieved_at:
            try:
                age = (now - parse_iso(self.retrieved_at)).total_seconds()
            except ValueError:
                return FreshnessState.UNKNOWN
            if age > max_age:
                return FreshnessState.REVIEW_OVERDUE
            return FreshnessState.CURRENT
        if age_class:
            return FreshnessState.CURRENT
        return FreshnessState.UNKNOWN


class EvidenceRegistry:
    """Append-only, signed evidence store.

    ``path=None`` keeps records in memory (tests, single-process demo). With a
    path, records persist as JSONL and are re-verified on access.
    """

    def __init__(
        self,
        *,
        keyring: Keyring,
        signing_key_id: str,
        path: str | Path | None = None,
    ) -> None:
        self._keyring = keyring
        self._signing_key_id = signing_key_id
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._records: dict[str, EvidenceRecord] = {}
        if self._path and self._path.exists():
            self._load()

    # ------------------------------------------------------------------ #
    # Read path
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if self._path is None:  # pragma: no cover - guarded by the caller
            raise ConfigurationError("Evidence registry has no persistence path to load from")
        for line_no, line in enumerate(self._path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = EvidenceRecord.from_mapping(json.loads(line))
            except json.JSONDecodeError as exc:
                raise EvidenceError(f"Invalid evidence JSON at line {line_no}", code="EVIDENCE_CORRUPT") from exc
            self._records[record.evidence_id] = record

    @property
    def signing_key_id(self) -> str:
        return self._signing_key_id

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._records

    def get(self, evidence_id: str, *, verify: bool = True) -> EvidenceRecord:
        record = self._records.get(evidence_id)
        if record is None:
            raise EvidenceError(
                f"Evidence is not registered: {evidence_id}",
                code="UNKNOWN_EVIDENCE",
                details={"evidence_id": evidence_id},
            )
        if verify:
            self.verify_record(record)
        return record

    def verify_record(self, record: EvidenceRecord) -> None:
        if not record.registry_signature or not record.registry_key_id:
            raise EvidenceError(
                f"Evidence {record.evidence_id} is unsigned",
                code="UNSIGNED_EVIDENCE",
                details={"evidence_id": record.evidence_id},
            )
        try:
            key = self._keyring.get(record.registry_key_id)
        except Exception as exc:  # unknown key id -> fail closed
            raise EvidenceError(
                f"Evidence {record.evidence_id} is signed by an unknown key",
                code="UNTRUSTED_SIGNING_KEY",
                details={"evidence_id": record.evidence_id, "key_id": record.registry_key_id},
            ) from exc
        if not verify_signature(key, _signed_body(record.to_dict()), record.registry_signature):
            raise EvidenceError(
                f"Evidence {record.evidence_id} failed signature verification",
                code="BAD_SIGNATURE",
                details={"evidence_id": record.evidence_id},
            )

    def resolve(self, evidence_ids: Iterable[str]) -> dict[str, EvidenceRecord]:
        return {evidence_id: self.get(evidence_id) for evidence_id in evidence_ids}

    def all_records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records.values())

    def digest(self) -> str:
        return digest([record.to_dict() for record in sorted(self._records.values(), key=lambda r: r.evidence_id)])

    # ------------------------------------------------------------------ #
    # Write path (control-core / ingestion only)
    # ------------------------------------------------------------------ #
    def register(self, data: Mapping[str, Any]) -> EvidenceRecord:
        """Register a reviewed evidence record and sign it.

        Callers must hold a control-core/ingestion capability; workers never do.
        """
        missing = [key for key in REQUIRED_EVIDENCE_FIELDS if not str(data.get(key, "")).strip()]
        if missing:
            raise EvidenceError(
                "Evidence record is missing required fields",
                code="EVIDENCE_INCOMPLETE",
                details={"missing": missing},
            )
        body = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "evidence_id": str(data["evidence_id"]),
            "source_id": str(data["source_id"]),
            "source_record_id": str(data.get("source_record_id", "")),
            "lineage_id": str(data["lineage_id"]),
            "title": str(data.get("title", "")),
            "source_url": str(data.get("source_url", "")),
            "retrieved_at": str(data["retrieved_at"]),
            "observed_fields": _coerce_list(data.get("observed_fields")),
            "blind_spots": _coerce_list(data.get("blind_spots")),
            "observation_method": str(data.get("observation_method", "")),
            "review_status": str(data["review_status"]),
            "content_hash": str(data.get("content_hash", "")),
            "freshness": dict(data.get("freshness") or {}),
        }
        body["content_hash"] = str(data.get("content_hash") or "") or sha256_bytes(
            canonical_json(stable_body(body)).encode("utf-8")
        )
        record = EvidenceRecord.from_mapping(body)
        body["registered_at"] = now_iso()
        signature = sign_payload(self._keyring.get(self._signing_key_id), _signed_body(body))
        record = EvidenceRecord.from_mapping(
            {**body, "registry_key_id": self._signing_key_id, "registry_signature": signature}
        )
        with self._lock:
            existing = self._records.get(record.evidence_id)
            if existing is not None:
                if digest(stable_body(existing.to_dict())) == digest(stable_body(record.to_dict())):
                    return existing
                raise EvidenceError(
                    f"Evidence id already registered with different content: {record.evidence_id}",
                    code="EVIDENCE_CONFLICT",
                    details={"evidence_id": record.evidence_id, "existing_hash": existing.content_hash},
                )
            self._records[record.evidence_id] = record
            if self._path is not None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
        return record

    # ------------------------------------------------------------------ #
    # Import bridge from the knowledge catalog
    # ------------------------------------------------------------------ #
    def register_from_catalog(
        self,
        *,
        catalog_record: Mapping[str, Any],
        review_status: str = "verified",
        freshness: Mapping[str, Any] | None = None,
    ) -> EvidenceRecord:
        evidence = catalog_record.get("evidence", {}) if isinstance(catalog_record.get("evidence"), Mapping) else {}
        entity = catalog_record.get("entity", {}) if isinstance(catalog_record.get("entity"), Mapping) else {}
        record_id = str(catalog_record.get("record_id", ""))
        payload = {
            "evidence_id": f"catalog:{record_id}",
            "source_id": str(evidence.get("source_id", "unknown")),
            "source_record_id": str(evidence.get("source_record_id", record_id)),
            "lineage_id": str(evidence.get("lineage_id", evidence.get("source_id", "unknown"))),
            "title": str(entity.get("canonical_name", record_id)),
            "source_url": str(evidence.get("source_url", "")),
            "retrieved_at": str(evidence.get("retrieved_at", "")) or now_iso(),
            "observed_fields": evidence.get("observed_fields", []) or [],
            "blind_spots": evidence.get("blind_spots", []) or [],
            "observation_method": str(evidence.get("observation_method", "")),
            "review_status": review_status,
            "content_hash": str(evidence.get("content_hash", "")),
            "freshness": dict(freshness or catalog_record.get("freshness") or {}),
        }
        return self.register(payload)


__all__ = ["EVIDENCE_SCHEMA_VERSION", "REQUIRED_EVIDENCE_FIELDS", "EvidenceRecord", "EvidenceRegistry"]
