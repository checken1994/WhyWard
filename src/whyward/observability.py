"""Minimal, dependency-free observability: metrics, structured logs, trace ids.

The control plane must be able to answer "what happened, for which request, how
long did it take, and how often did we withhold?" without shipping a vendor SDK.
This module provides Prometheus-compatible text output and JSON logs with a W3C
compatible trace id so an OpenTelemetry collector can be added later without
changing call sites.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, TextIO

_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")

DEFAULT_HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def new_trace_id() -> str:
    return uuid.uuid4().hex


def new_span_id() -> str:
    return uuid.uuid4().hex[:16]


def valid_trace_id(value: str) -> bool:
    return bool(_TRACE_ID_RE.match(value or ""))


def parse_traceparent(header: str | None) -> tuple[str, str]:
    """Return (trace_id, span_id) from a W3C traceparent header, generating if absent."""
    if header:
        parts = header.strip().split("-")
        if len(parts) == 4 and valid_trace_id(parts[1]) and _SPAN_ID_RE.match(parts[2]):
            return parts[1], parts[2]
    return new_trace_id(), new_span_id()


def format_traceparent(trace_id: str, span_id: str) -> str:
    return f"00-{trace_id}-{span_id}-01"


def _escape_label(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    """Thread-safe counters, gauges and histograms with Prometheus exposition."""

    def __init__(self, namespace: str = "whyward") -> None:
        self.namespace = namespace
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = {}
        self._help: dict[str, str] = {}

    @staticmethod
    def _key(labels: dict[str, str] | None) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))

    def counter(
        self,
        name: str,
        amount: float = 1.0,
        *,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None:
        with self._lock:
            key = (name, self._key(labels))
            self._counters[key] = self._counters.get(key, 0.0) + float(amount)
            if help_text:
                self._help.setdefault(name, help_text)

    def gauge(self, name: str, value: float, *, labels: dict[str, str] | None = None, help_text: str = "") -> None:
        with self._lock:
            self._gauges[(name, self._key(labels))] = float(value)
            if help_text:
                self._help.setdefault(name, help_text)

    def observe(self, name: str, value: float, *, labels: dict[str, str] | None = None, help_text: str = "") -> None:
        with self._lock:
            self._histograms.setdefault((name, self._key(labels)), []).append(float(value))
            if help_text:
                self._help.setdefault(name, help_text)

    @contextmanager
    def timer(self, name: str, *, labels: dict[str, str] | None = None) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.observe(name, time.perf_counter() - started, labels=labels)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": {f"{name}{dict(labels)}": value for (name, labels), value in self._counters.items()},
                "gauges": {f"{name}{dict(labels)}": value for (name, labels), value in self._gauges.items()},
                "histograms": {
                    f"{name}{dict(labels)}": {"count": len(values), "sum": sum(values)}
                    for (name, labels), values in self._histograms.items()
                },
            }

    def prometheus_text(self) -> str:
        lines: list[str] = []
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            histograms = {key: list(values) for key, values in self._histograms.items()}
        emitted: set[str] = set()
        for (name, labels), value in sorted(counters.items()):
            full = f"{self.namespace}_{name}" if name.endswith("_total") else f"{self.namespace}_{name}_total"
            if full not in emitted:
                if name in self._help:
                    lines.append(f"# HELP {full} {self._help[name]}")
                lines.append(f"# TYPE {full} counter")
                emitted.add(full)
            lines.append(f"{full}{self._format_labels(labels)} {value:g}")
        for (name, labels), value in sorted(gauges.items()):
            full = f"{self.namespace}_{name}"
            if full not in emitted:
                if name in self._help:
                    lines.append(f"# HELP {full} {self._help[name]}")
                lines.append(f"# TYPE {full} gauge")
                emitted.add(full)
            lines.append(f"{full}{self._format_labels(labels)} {value:g}")
        for (name, labels), values in sorted(histograms.items()):
            full = f"{self.namespace}_{name}_seconds"
            if full not in emitted:
                if name in self._help:
                    lines.append(f"# HELP {full} {self._help[name]}")
                lines.append(f"# TYPE {full} histogram")
                emitted.add(full)
            total = len(values)
            for boundary in DEFAULT_HISTOGRAM_BUCKETS:
                count = sum(1 for value in values if value <= boundary)
                bucket_labels = (*labels, ("le", f"{boundary:g}"))
                lines.append(f"{full}_bucket{self._format_labels(bucket_labels)} {count}")
            lines.append(f"{full}_bucket{self._format_labels((*labels, ('le', '+Inf')))} {total}")
            lines.append(f"{full}_sum{self._format_labels(labels)} {sum(values):g}")
            lines.append(f"{full}_count{self._format_labels(labels)} {total}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
        if not labels:
            return ""
        body = ",".join(f'{key}="{_escape_label(value)}"' for key, value in labels)
        return "{" + body + "}"


class StructuredLogger:
    """JSON-lines logger writing to stderr (stdout stays machine-parseable JSON)."""

    def __init__(
        self,
        *,
        service: str = "whyward",
        level: str | None = None,
        stream: TextIO | None = None,
    ) -> None:
        self.service = service
        self.level = (level or os.environ.get("WHYWARD_LOG_LEVEL", "info")).lower()
        self._stream = stream or sys.stderr
        self._levels = {"debug": 10, "info": 20, "warning": 30, "error": 40, "critical": 50}

    def _emit(self, level: str, event: str, fields: dict[str, Any], trace_id: str = "") -> None:
        if self._levels.get(level, 20) < self._levels.get(self.level, 20):
            return
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "service": self.service,
            "event": event,
        }
        if trace_id:
            record["trace_id"] = trace_id
        record.update(fields)
        self._stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self._stream.flush()

    def debug(self, event: str, **fields: Any) -> None:
        trace_id = str(fields.pop("trace_id", ""))
        self._emit("debug", event, fields, trace_id)

    def info(self, event: str, **fields: Any) -> None:
        trace_id = str(fields.pop("trace_id", ""))
        self._emit("info", event, fields, trace_id)

    def warning(self, event: str, **fields: Any) -> None:
        trace_id = str(fields.pop("trace_id", ""))
        self._emit("warning", event, fields, trace_id)

    def error(self, event: str, **fields: Any) -> None:
        trace_id = str(fields.pop("trace_id", ""))
        self._emit("error", event, fields, trace_id)
