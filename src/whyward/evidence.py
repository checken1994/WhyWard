from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from .canonical import digest
from .errors import IntegrityError
from .identity import Keyring, verify_envelope
from .models import EvidenceRef, FreshnessState

CATALOG_SCHEMA_VERSION = 2


def normalize_text(text: str) -> str:
    lowered = text.lower().replace("đ", "d").replace("Đ", "d")
    decomposed = unicodedata.normalize("NFD", lowered)
    without_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    cleaned = re.sub(r"[^a-z0-9.]+", " ", without_marks)
    return re.sub(r"\s+", " ", cleaned).strip()


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({str(k): _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class LookupResult:
    status: str
    dataset_version: str
    record: Mapping[str, Any] | None = None
    attribute: str = ""
    value: Any = None
    reasons: tuple[str, ...] = ()
    candidates: tuple[str, ...] = ()
    freshness: str = ""
    dataset_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        record = _thaw(self.record) if self.record is not None else None
        return {
            "status": self.status,
            "dataset_version": self.dataset_version,
            "dataset_digest": self.dataset_digest,
            "record": record,
            "attribute": self.attribute,
            "value": self.value,
            "reasons": list(self.reasons),
            "candidates": list(self.candidates),
            "freshness": self.freshness,
        }


class KnowledgeStore:
    """Immutable, versioned snapshot of reviewed static facts.

    Loading is fail-closed (audit findings W-03/W-04):

    * the manifest must declare ``schema_version`` and may be signed;
    * every shard must declare ``sha256`` (``require_checksum``);
    * ``record_count`` must match the shard contents (``require_record_count``);
    * freshness is evaluated on every query, not stored as decoration.
    """

    def __init__(
        self,
        manifest: Mapping[str, Any],
        records: tuple[Mapping[str, Any], ...],
        *,
        manifest_signature: Mapping[str, Any] | None = None,
    ):
        self._manifest = _freeze(dict(manifest))
        self._records = records
        self._manifest_signature = dict(manifest_signature or {})
        self.dataset_version = str(manifest.get("dataset_version", "unknown"))
        self._by_id = {str(record["record_id"]): record for record in records}
        self._completeness = dict(manifest.get("completeness", {}))
        self.dataset_digest = digest(
            {
                "dataset_version": self.dataset_version,
                "records": [_thaw(record) for record in records],
            }
        )
        self.signed = bool(self._manifest_signature)

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    @classmethod
    def load(
        cls,
        catalog_dir: str | Path,
        *,
        require_checksum: bool = True,
        require_record_count: bool = True,
        keyring: Keyring | None = None,
        require_signature: bool = False,
        trust_key_ids: Iterable[str] | None = None,
    ) -> KnowledgeStore:
        root = Path(catalog_dir).resolve()
        manifest_path = root / "manifest.json"
        if not manifest_path.exists():
            raise IntegrityError(f"Catalog manifest not found: {manifest_path}", code="CATALOG_MISSING")
        raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(raw_manifest, Mapping):
            raise IntegrityError("Catalog manifest must be a JSON object", code="CATALOG_INVALID")

        signature = raw_manifest.get("signature")
        manifest_body = {k: v for k, v in raw_manifest.items() if k != "signature"}
        if signature is not None:
            verify_envelope(
                {"payload": manifest_body, "signature": signature},
                keyring or Keyring.from_env(),
                allowed_key_ids=trust_key_ids,
            )
        elif require_signature:
            raise IntegrityError(
                "Catalog manifest is unsigned but this deployment requires a signed catalog",
                code="CATALOG_UNSIGNED",
            )

        schema_version = int(manifest_body.get("schema_version", 0))
        if schema_version < 1 or schema_version > CATALOG_SCHEMA_VERSION:
            raise IntegrityError(
                f"Unsupported catalog schema_version: {schema_version}",
                code="CATALOG_SCHEMA_UNSUPPORTED",
            )
        shards = manifest_body.get("shards")
        if not isinstance(shards, list) or not shards:
            raise IntegrityError("Catalog manifest declares no shards", code="CATALOG_INVALID")

        records: list[Mapping[str, Any]] = []
        seen_ids: set[str] = set()
        for shard in shards:
            if not isinstance(shard, Mapping) or "path" not in shard:
                raise IntegrityError("Each shard needs a 'path'", code="CATALOG_INVALID")
            relative = str(shard["path"])
            shard_path = (root / relative).resolve()
            if root not in shard_path.parents and shard_path != root:
                raise IntegrityError(f"Catalog shard escapes catalog directory: {relative}", code="CATALOG_PATH_ESCAPE")
            if not shard_path.exists():
                raise IntegrityError(f"Catalog shard is missing: {relative}", code="CATALOG_SHARD_MISSING")
            raw = shard_path.read_bytes()
            actual = hashlib.sha256(raw).hexdigest()
            expected = str(shard.get("sha256", "")).strip()
            if not expected:
                if require_checksum:
                    raise IntegrityError(
                        f"Catalog shard {relative} has no sha256 and checksums are required",
                        code="CATALOG_UNCHECKED_SHARD",
                    )
            elif actual != expected:
                raise IntegrityError(
                    f"Checksum mismatch for shard {relative}",
                    code="CATALOG_CHECKSUM_MISMATCH",
                    details={"expected": expected, "actual": actual},
                )
            shard_records = 0
            for line_no, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                record = json.loads(line)
                record_id = str(record.get("record_id", ""))
                if not record_id:
                    raise IntegrityError(f"Missing record_id at {relative}:{line_no}", code="CATALOG_INVALID")
                if record_id in seen_ids:
                    raise IntegrityError(f"Duplicate record_id: {record_id}", code="CATALOG_DUPLICATE_RECORD")
                seen_ids.add(record_id)
                shard_records += 1
                records.append(_freeze(record))
            declared = shard.get("record_count")
            if require_record_count:
                if declared is None:
                    raise IntegrityError(
                        f"Shard {relative} does not declare record_count",
                        code="CATALOG_COUNT_MISSING",
                    )
                if int(declared) != shard_records:
                    raise IntegrityError(
                        f"Shard {relative} declares {declared} records but contains {shard_records}",
                        code="CATALOG_COUNT_MISMATCH",
                        details={"declared": int(declared), "actual": shard_records},
                    )
            elif declared is not None and int(declared) != shard_records:
                raise IntegrityError(
                    f"Shard {relative} declares {declared} records but contains {shard_records}",
                    code="CATALOG_COUNT_MISMATCH",
                )
        return cls(
            manifest_body,
            tuple(records),
            manifest_signature=signature if isinstance(signature, Mapping) else None,
        )

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #
    @property
    def records(self) -> tuple[Mapping[str, Any], ...]:
        return self._records

    @property
    def manifest(self) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], self._manifest)

    @property
    def completeness(self) -> Mapping[str, Any]:
        return MappingProxyType(self._completeness)

    def get_by_id(self, record_id: str) -> Mapping[str, Any] | None:
        return self._by_id.get(record_id)

    def is_complete_for(self, domain: str) -> bool:
        return self._completeness.get(domain) == "complete_for_declared_scope"

    # ------------------------------------------------------------------ #
    # Matching
    # ------------------------------------------------------------------ #
    @staticmethod
    def _contains_phrase(normalized_query: str, phrase: str) -> bool:
        phrase_norm = normalize_text(phrase)
        return bool(phrase_norm) and f" {phrase_norm} " in f" {normalized_query} "

    @staticmethod
    def _detect_attribute(query_norm: str) -> str:
        if any(x in query_norm for x in ("do lon", "magnitude", "manh bao nhieu", "manh co nao", "muc do")):
            return "magnitude"
        if any(x in query_norm for x in ("o dau", "where", "dia diem", "place")):
            return "place"
        if any(x in query_norm for x in ("nam nao", "when", "ngay nao", "date")):
            return "event_date"
        return ""

    @staticmethod
    def _attribute_value(record: Mapping[str, Any], attribute: str) -> Any:
        entity = record.get("entity", {})
        facts = record.get("facts", {})
        if attribute == "place":
            return entity.get("place", "")
        if attribute == "event_date":
            return entity.get("event_date", entity.get("year", ""))
        fact = facts.get(attribute, {}) if isinstance(facts, Mapping) else {}
        if isinstance(fact, Mapping):
            return fact.get("value")
        return fact

    @staticmethod
    def _freshness_of(record: Mapping[str, Any], now: datetime) -> FreshnessState:
        freshness = record.get("freshness", {})
        if not isinstance(freshness, Mapping):
            return FreshnessState.UNKNOWN
        from .models import parse_iso

        for key, state in (("valid_until", FreshnessState.EXPIRED), ("review_after", FreshnessState.REVIEW_OVERDUE)):
            raw = str(freshness.get(key) or "").strip()
            if raw:
                try:
                    if now > parse_iso(raw):
                        return state
                except ValueError:
                    return FreshnessState.UNKNOWN
        if freshness.get("class"):
            return FreshnessState.CURRENT
        return FreshnessState.UNKNOWN

    def answer_query(
        self,
        query: str,
        *,
        domain: str | None = None,
        accepted_review_statuses: frozenset[str] | set[str] | None = None,
        now: datetime | None = None,
        reject_stale: bool = True,
    ) -> LookupResult:
        accepted = accepted_review_statuses or {"verified"}
        now = now or datetime.now(UTC)
        query_norm = normalize_text(query)
        year_match = re.search(r"\b(1[0-9]{3}|20[0-9]{2})\b", query_norm)
        query_year = int(year_match.group(1)) if year_match else None
        attribute = self._detect_attribute(query_norm)
        superlative = any(
            phrase in query_norm
            for phrase in ("manh nhat", "lon nhat", "strongest", "largest", "biggest")
        )

        eligible: list[Mapping[str, Any]] = []
        rejected_review = False
        stale_rejected = 0
        stale_kept = 0
        for record in self._records:
            if domain and str(record.get("domain", "")) != domain:
                continue
            review = record.get("review", {})
            status = str(review.get("status", "")) if isinstance(review, Mapping) else ""
            if status not in accepted:
                rejected_review = True
                continue
            freshness = self._freshness_of(record, now)
            if reject_stale and freshness is FreshnessState.EXPIRED:
                stale_rejected += 1
                continue
            if freshness is FreshnessState.REVIEW_OVERDUE:
                stale_kept += 1
            eligible.append(record)

        if stale_rejected and not eligible:
            return LookupResult(
                status="INSUFFICIENT_EVIDENCE",
                dataset_version=self.dataset_version,
                dataset_digest=self.dataset_digest,
                attribute=attribute,
                reasons=(
                    f"{stale_rejected} matching record(s) are past valid_until and were withheld (STALE_AFTER).",
                ),
            )

        def _finish(result: LookupResult) -> LookupResult:
            if stale_kept and result.record is not None:
                return LookupResult(
                    status="FOUND_STALE" if result.status.startswith("FOUND") else result.status,
                    dataset_version=result.dataset_version,
                    dataset_digest=result.dataset_digest or self.dataset_digest,
                    record=result.record,
                    attribute=result.attribute,
                    value=result.value,
                    reasons=(*result.reasons, "Record is past review_after; treat as stale evidence."),
                    candidates=result.candidates,
                    freshness=FreshnessState.REVIEW_OVERDUE.value,
                )
            return result

        if superlative and eligible:
            numeric: list[tuple[float, Mapping[str, Any]]] = []
            for record in eligible:
                value = self._attribute_value(record, "magnitude")
                if isinstance(value, (int, float)):
                    numeric.append((float(value), record))
            if numeric:
                numeric.sort(key=lambda item: item[0], reverse=True)
                best_value, best = numeric[0]
                winners = [r for v, r in numeric if v == best_value]
                if len(winners) != 1:
                    return LookupResult(
                        status="AMBIGUOUS",
                        dataset_version=self.dataset_version,
                        dataset_digest=self.dataset_digest,
                        attribute="magnitude",
                        reasons=("Superlative has no unique winner in the catalog.",),
                        candidates=tuple(str(r["record_id"]) for r in winners),
                    )
                domain_name = str(best.get("domain", domain or ""))
                complete = self.is_complete_for(domain_name)
                reason = (
                    "Computed from a catalog declared complete for its scope."
                    if complete
                    else "Computed only within the current catalog; the catalog is not declared globally complete."
                )
                return _finish(
                    LookupResult(
                        status="FOUND_SCOPED" if not complete else "FOUND",
                        dataset_version=self.dataset_version,
                        dataset_digest=self.dataset_digest,
                        record=best,
                        attribute="magnitude",
                        value=best_value,
                        reasons=(reason,),
                        candidates=(str(best["record_id"]),),
                    )
                )

        scored: list[tuple[int, Mapping[str, Any], list[str]]] = []
        for record in eligible:
            entity = record.get("entity", {})
            names: list[str] = []
            if isinstance(entity, Mapping):
                names.extend(str(x) for x in entity.get("names", ()))
                names.extend(str(x) for x in entity.get("aliases", ()))
                if entity.get("canonical_name"):
                    names.append(str(entity["canonical_name"]))
            reasons: list[str] = []
            score = 0
            if any(self._contains_phrase(query_norm, name) for name in names):
                score += 50
                reasons.append("entity_name_matched")
            entity_year = entity.get("year") if isinstance(entity, Mapping) else None
            if query_year is not None and entity_year == query_year:
                score += 20
                reasons.append("year_matched")
            place = str(entity.get("place", "")) if isinstance(entity, Mapping) else ""
            if place and self._contains_phrase(query_norm, place):
                score += 10
                reasons.append("place_matched")
            magnitude = self._attribute_value(record, "magnitude")
            if magnitude is not None and str(magnitude) in query_norm:
                # The answer may corroborate a claim or support a reverse lookup;
                # it is never required when name/year identify the entity.
                score += 35
                reasons.append("attribute_value_matched")
            if attribute:
                score += 5
            if score:
                scored.append((score, record, reasons))

        if not scored:
            reason = (
                "Matching data exists only in records whose review status is not accepted."
                if rejected_review
                else "No reviewed catalog record was identified."
            )
            return LookupResult(
                status="INSUFFICIENT_EVIDENCE",
                dataset_version=self.dataset_version,
                dataset_digest=self.dataset_digest,
                attribute=attribute,
                reasons=(reason,),
            )

        scored.sort(key=lambda item: item[0], reverse=True)
        best_score, best, best_reasons = scored[0]
        tied = [item for item in scored if item[0] == best_score]
        strong_entity = "entity_name_matched" in best_reasons or "attribute_value_matched" in best_reasons
        if not strong_entity:
            return LookupResult(
                status="INSUFFICIENT_EVIDENCE",
                dataset_version=self.dataset_version,
                dataset_digest=self.dataset_digest,
                attribute=attribute,
                reasons=("The query does not identify a unique entity; year or place alone is insufficient.",),
                candidates=tuple(str(item[1]["record_id"]) for item in scored[:5]),
            )
        if len(tied) != 1:
            return LookupResult(
                status="AMBIGUOUS",
                dataset_version=self.dataset_version,
                dataset_digest=self.dataset_digest,
                attribute=attribute,
                reasons=("More than one record matches with the same strength.",),
                candidates=tuple(str(item[1]["record_id"]) for item in tied),
            )
        if len(scored) > 1 and best_score - scored[1][0] < 15:
            return LookupResult(
                status="AMBIGUOUS",
                dataset_version=self.dataset_version,
                dataset_digest=self.dataset_digest,
                attribute=attribute,
                reasons=("The best record does not win by a safe margin.",),
                candidates=tuple(str(item[1]["record_id"]) for item in scored[:5]),
            )

        value = self._attribute_value(best, attribute) if attribute else None
        return _finish(
            LookupResult(
                status="FOUND",
                dataset_version=self.dataset_version,
                dataset_digest=self.dataset_digest,
                record=best,
                attribute=attribute,
                value=value,
                reasons=tuple(best_reasons),
                candidates=(str(best["record_id"]),),
                freshness=self._freshness_of(best, now).value,
            )
        )

    # ------------------------------------------------------------------ #
    # Evidence bridge
    # ------------------------------------------------------------------ #
    def evidence_for_record(self, record: Mapping[str, Any]) -> EvidenceRef:
        """Catalog-derived reference.

        Deliberately unsigned and without a review status: the ControlPlane must
        resolve it through the signed EvidenceRegistry before trusting it.
        """
        evidence = record.get("evidence", {})
        if not isinstance(evidence, Mapping):
            evidence = {}
        entity = record.get("entity", {})
        return EvidenceRef(
            evidence_id=f"catalog:{record.get('record_id', 'unknown')}",
            source_id=str(evidence.get("source_id", "unknown")),
            lineage_id=str(evidence.get("lineage_id", evidence.get("source_id", "unknown"))),
            title=str(entity.get("canonical_name", "")) if isinstance(entity, Mapping) else "",
            source_url=str(evidence.get("source_url", "")),
            observed_fields=tuple(str(x) for x in evidence.get("observed_fields", ())),
            blind_spots=tuple(str(x) for x in evidence.get("blind_spots", ())),
            retrieved_at=str(evidence.get("retrieved_at", "")),
            content_hash=str(evidence.get("content_hash", "")),
            observation_method=str(evidence.get("observation_method", "")),
        )

    def index_for_registry(self) -> tuple[Mapping[str, Any], ...]:
        return self._records


__all__ = ["CATALOG_SCHEMA_VERSION", "KnowledgeStore", "LookupResult", "normalize_text"]
