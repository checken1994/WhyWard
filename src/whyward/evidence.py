from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .models import EvidenceRef


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

    def to_dict(self) -> dict[str, Any]:
        record = _thaw(self.record) if self.record is not None else None
        return {
            "status": self.status,
            "dataset_version": self.dataset_version,
            "record": record,
            "attribute": self.attribute,
            "value": self.value,
            "reasons": list(self.reasons),
            "candidates": list(self.candidates),
        }


class KnowledgeStore:
    """Immutable, versioned snapshot of reviewed static facts.

    JSONL shards plus a manifest are the canonical small-catalog format. A
    search warehouse may help find evidence later, but it must not silently
    replace this reviewed catalog as the source of truth.
    """

    def __init__(self, manifest: dict[str, Any], records: tuple[Mapping[str, Any], ...]):
        self._manifest = _freeze(manifest)
        self._records = records
        self.dataset_version = str(manifest.get("dataset_version", "unknown"))
        self._by_id = {str(record["record_id"]): record for record in records}
        self._completeness = dict(manifest.get("completeness", {}))

    @classmethod
    def load(cls, catalog_dir: str | Path) -> "KnowledgeStore":
        root = Path(catalog_dir)
        manifest_path = root / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Catalog manifest not found: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        records: list[Mapping[str, Any]] = []
        seen_ids: set[str] = set()
        for shard in manifest.get("shards", []):
            relative = str(shard["path"])
            shard_path = (root / relative).resolve()
            if root.resolve() not in shard_path.parents and shard_path != root.resolve():
                raise ValueError(f"Catalog shard escapes catalog directory: {relative}")
            raw = shard_path.read_bytes()
            actual = hashlib.sha256(raw).hexdigest()
            expected = str(shard.get("sha256", ""))
            if expected and actual != expected:
                raise ValueError(f"Checksum mismatch for shard {relative}")
            for line_no, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                record = json.loads(line)
                record_id = str(record.get("record_id", ""))
                if not record_id:
                    raise ValueError(f"Missing record_id at {relative}:{line_no}")
                if record_id in seen_ids:
                    raise ValueError(f"Duplicate record_id: {record_id}")
                seen_ids.add(record_id)
                records.append(_freeze(record))
        return cls(manifest, tuple(records))

    @property
    def records(self) -> tuple[Mapping[str, Any], ...]:
        return self._records

    def get_by_id(self, record_id: str) -> Mapping[str, Any] | None:
        return self._by_id.get(record_id)

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

    def answer_query(
        self,
        query: str,
        *,
        domain: str | None = None,
        accepted_review_statuses: frozenset[str] | set[str] | None = None,
    ) -> LookupResult:
        accepted = accepted_review_statuses or {"verified", "demo_verified"}
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
        for record in self._records:
            if domain and str(record.get("domain", "")) != domain:
                continue
            review = record.get("review", {})
            status = str(review.get("status", "")) if isinstance(review, Mapping) else ""
            if status not in accepted:
                rejected_review = True
                continue
            eligible.append(record)

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
                        attribute="magnitude",
                        reasons=("Superlative has no unique winner in the catalog.",),
                        candidates=tuple(str(r["record_id"]) for r in winners),
                    )
                domain_name = str(best.get("domain", domain or ""))
                complete = self._completeness.get(domain_name) == "complete_for_declared_scope"
                reason = (
                    "Computed from a catalog declared complete for its scope."
                    if complete
                    else "Computed only within the current catalog; the catalog is not declared globally complete."
                )
                return LookupResult(
                    status="FOUND_SCOPED" if not complete else "FOUND",
                    dataset_version=self.dataset_version,
                    record=best,
                    attribute="magnitude",
                    value=best_value,
                    reasons=(reason,),
                    candidates=(str(best["record_id"]),),
                )

        scored: list[tuple[int, Mapping[str, Any], list[str]]] = []
        for record in eligible:
            entity = record.get("entity", {})
            names = []
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
                attribute=attribute,
                reasons=("The query does not identify a unique entity; year or place alone is insufficient.",),
                candidates=tuple(str(item[1]["record_id"]) for item in scored[:5]),
            )
        if len(tied) != 1:
            return LookupResult(
                status="AMBIGUOUS",
                dataset_version=self.dataset_version,
                attribute=attribute,
                reasons=("More than one record matches with the same strength.",),
                candidates=tuple(str(item[1]["record_id"]) for item in tied),
            )
        if len(scored) > 1 and best_score - scored[1][0] < 15:
            return LookupResult(
                status="AMBIGUOUS",
                dataset_version=self.dataset_version,
                attribute=attribute,
                reasons=("The best record does not win by a safe margin.",),
                candidates=tuple(str(item[1]["record_id"]) for item in scored[:5]),
            )

        value = self._attribute_value(best, attribute) if attribute else None
        return LookupResult(
            status="FOUND",
            dataset_version=self.dataset_version,
            record=best,
            attribute=attribute,
            value=value,
            reasons=tuple(best_reasons),
            candidates=(str(best["record_id"]),),
        )

    def evidence_for_record(self, record: Mapping[str, Any]) -> EvidenceRef:
        evidence = record.get("evidence", {})
        review = record.get("review", {})
        if not isinstance(evidence, Mapping):
            evidence = {}
        if not isinstance(review, Mapping):
            review = {}
        return EvidenceRef(
            evidence_id=f"catalog:{record.get('record_id', 'unknown')}",
            source_id=str(evidence.get("source_id", "unknown")),
            lineage_id=str(evidence.get("lineage_id", evidence.get("source_id", "unknown"))),
            title=str(record.get("entity", {}).get("canonical_name", "")) if isinstance(record.get("entity"), Mapping) else "",
            source_url=str(evidence.get("source_url", "")),
            observed_fields=tuple(str(x) for x in evidence.get("observed_fields", ())),
            blind_spots=tuple(str(x) for x in evidence.get("blind_spots", ())),
            retrieved_at=str(evidence.get("retrieved_at", "")),
            content_hash=str(evidence.get("content_hash", "")),
            review_status=str(review.get("status", "unverified")),
            observation_method=str(evidence.get("observation_method", "")),
        )
