"""HTTP boundary for WhyWard.

Hardening over 0.1.0 (audit findings W-12, A1-A6):

* bearer-token authentication with per-scope authorization (no anonymous data);
* mandatory ``Authorization`` for every data endpoint; health endpoints are the
  only anonymous ones and expose no tenant data;
* W3C ``traceparent`` propagation plus a returned ``X-Request-Id``;
* RFC 9457 ``application/problem+json`` errors with stable codes;
* token-bucket rate limiting per subject;
* request size, header count and socket timeouts; HTTP/1.1 with keep-alive;
* security headers, no ``Server``/``Python`` version banner;
* ``/metrics`` in Prometheus text format and operator endpoints for kill switch.

This server is suitable for a trusted network segment behind a TLS-terminating
gateway. It does not implement TLS itself; see SECURITY.md.
"""

from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .control import ControlPlane
from .errors import (
    AuthenticationError,
    AuthorizationError,
    RateLimitExceeded,
    ValidationError,
    WhyWardError,
)
from .identity import ApiPrincipal, ApiTokenStore
from .observability import Metrics, parse_traceparent
from .version import __version__

MAX_BODY = 64 * 1024
MAX_HEADER_LINES = 100
SOCKET_TIMEOUT_SECONDS = 15

SCOPE_ASK = "ask"
SCOPE_READ = "read"
SCOPE_AUDIT = "audit"
SCOPE_ADMIN = "admin"
SCOPE_METRICS = "metrics"


class TokenBucket:
    """Simple per-key token bucket; deterministic and dependency-free."""

    def __init__(self, rate_per_second: float, burst: int) -> None:
        self.rate = rate_per_second
        self.burst = burst
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, updated = self._buckets.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - updated) * self.rate)
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - cost, now)
            return True


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "WhyWard"
    sys_version = ""

    # Injected by make_server
    control: ControlPlane
    tokens: ApiTokenStore
    limiter: TokenBucket
    metrics: Metrics
    require_auth: bool = True

    # ------------------------------------------------------------------ #
    # Plumbing
    # ------------------------------------------------------------------ #
    def log_message(self, format: str, *args: Any) -> None:
        return

    def _trace(self) -> tuple[str, str]:
        return parse_traceparent(self.headers.get("traceparent"))

    def _send_json(
        self,
        status: int,
        payload: dict[str, Any],
        *,
        trace_id: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self._security_headers(trace_id)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_text(
        self,
        status: int,
        body: str,
        *,
        trace_id: str = "",
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self._security_headers(trace_id)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_problem(self, error: WhyWardError, *, instance: str, trace_id: str) -> None:
        payload = error.to_problem(instance=instance, trace_id=trace_id)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(int(error.http_status))
        self.send_header("Content-Type", "application/problem+json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if int(error.http_status) == 401:
            # RFC 7235: a 401 must advertise the challenge scheme.
            self.send_header("WWW-Authenticate", 'Bearer realm="whyward", charset="UTF-8"')
        self._security_headers(trace_id)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _security_headers(self, trace_id: str) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if trace_id:
            self.send_header("X-Request-Id", trace_id)
        self.send_header("Connection", "keep-alive")

    def _authenticate(self, scope: str) -> ApiPrincipal:
        if not self.require_auth:
            return ApiPrincipal(subject="anonymous-dev", scopes=frozenset({SCOPE_ADMIN}))
        principal = self.tokens.authenticate(self.headers.get("Authorization"))
        if not principal.has_scope(scope):
            raise AuthorizationError(
                f"Token for {principal.subject!r} lacks scope {scope!r}",
                details={"required": scope, "granted": sorted(principal.scopes)},
            )
        return principal

    def _path(self) -> str:
        return urlsplit(self.path).path.rstrip("/") or "/"

    # ------------------------------------------------------------------ #
    # GET
    # ------------------------------------------------------------------ #
    def do_GET(self) -> None:
        trace_id, _ = self._trace()
        path = self._path()
        started = time.perf_counter()
        try:
            if path in {"/healthz", "/health", "/livez"}:
                self._send_json(
                    HTTPStatus.OK,
                    {"status": "ok", "system": "WhyWard", "version": __version__},
                    trace_id=trace_id,
                )
                return
            if path == "/readyz":
                status = self.control.status()
                ready = status["ledger"]["valid"] and not status["kill_switch_engaged"]
                self._send_json(
                    HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                    {
                        "ready": ready,
                        "checks": {
                            "ledger": status["ledger"]["valid"],
                            "kill_switch": not status["kill_switch_engaged"],
                        },
                    },
                    trace_id=trace_id,
                )
                return
            if path == "/version":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "system": "WhyWard",
                        "version": __version__,
                        "policy_digest": self.control.policy.digest(),
                        "dataset_digest": self.control.knowledge_store.dataset_digest
                        if self.control.knowledge_store
                        else None,
                    },
                    trace_id=trace_id,
                )
                return
            if path == "/status":
                self._authenticate(SCOPE_READ)
                self._send_json(
                    HTTPStatus.OK, self.control.status(), trace_id=trace_id
                )
                return
            if path == "/metrics":
                self._authenticate(SCOPE_METRICS)
                self._send_text(
                    HTTPStatus.OK,
                    self.control.metrics.prometheus_text(),
                    trace_id=trace_id,
                    content_type="text/plain; version=0.0.4; charset=utf-8",
                )
                return
            if path == "/ledger/verify":
                self._authenticate(SCOPE_AUDIT)
                valid, message = self.control.ledger.verify()
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "valid": valid,
                        "message": message,
                        "events": self.control.ledger.event_count,
                    },
                    trace_id=trace_id,
                )
                return
            if path == "/ledger/checkpoint":
                self._authenticate(SCOPE_AUDIT)
                try:
                    self._send_json(HTTPStatus.OK, self.control.ledger.checkpoint(), trace_id=trace_id)
                except WhyWardError as exc:
                    self._send_problem(exc, instance=path, trace_id=trace_id)
                return
            raise ValidationError(f"No route for {path}", code="NOT_FOUND", http_status=404)
        except WhyWardError as exc:
            self._send_problem(exc, instance=path, trace_id=trace_id)
        except Exception as exc:
            self.metrics.counter("http_errors_total", labels={"route": path})
            self._send_problem(
                WhyWardError(f"Unhandled server error: {type(exc).__name__}", code="INTERNAL_ERROR"),
                instance=path,
                trace_id=trace_id,
            )
        finally:
            self.metrics.observe("http_request_duration_seconds", time.perf_counter() - started)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        trace_id, _ = self._trace()
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self._security_headers(trace_id)
        self.end_headers()

    # ------------------------------------------------------------------ #
    # POST
    # ------------------------------------------------------------------ #
    def do_POST(self) -> None:
        trace_id, _span_id = self._trace()
        path = self._path()
        try:
            if path == "/ask":
                principal = self._authenticate(SCOPE_ASK)
                if not self.limiter.allow(f"ask:{principal.subject}"):
                    raise RateLimitExceeded("Query rate limit exceeded", details={"subject": principal.subject})
                payload = self._read_json()
                question = str(payload.get("question", "")).strip()
                if not question:
                    raise ValidationError("'question' is required", code="QUESTION_REQUIRED")
                if len(question) > 2_000:
                    raise ValidationError("Question is too long (max 2000 characters)", code="QUESTION_TOO_LONG")
                result = self.control.answer_question(
                    question, actor=principal.subject, trace_id=trace_id, domain=payload.get("domain") or None
                )
                self.metrics.counter(
                    "api_requests_total", labels={"route": "/ask", "verdict": result.get("verdict", "unknown")}
                )
                self._send_json(
                    HTTPStatus.OK,
                    result,
                    trace_id=trace_id,
                    extra_headers={"WhyWard-Verdict": str(result.get("verdict", "unknown"))},
                )
                return
            if path == "/admin/kill-switch":
                principal = self._authenticate(SCOPE_ADMIN)
                payload = self._read_json()
                action = str(payload.get("action", "")).strip()
                if action == "engage":
                    event = self.control.engage_kill_switch(
                        str(payload.get("reason", "operator request"))[:200], actor=principal.subject
                    )
                elif action == "release":
                    event = self.control.release_kill_switch(actor=principal.subject)
                else:
                    raise ValidationError("'action' must be 'engage' or 'release'", code="ACTION_INVALID")
                self.metrics.counter("admin_actions_total", labels={"action": f"kill_switch_{action}"})
                self._send_json(HTTPStatus.OK, {"ok": True, "event_id": event.get("event_id")}, trace_id=trace_id)
                return
            raise ValidationError(f"No route for {path}", code="NOT_FOUND", http_status=404)
        except WhyWardError as exc:
            self._send_problem(exc, instance=path, trace_id=trace_id)
        except Exception as exc:
            self.metrics.counter("http_errors_total", labels={"route": path})
            self._send_problem(
                WhyWardError(f"Unhandled server error: {type(exc).__name__}", code="INTERNAL_ERROR"),
                instance=path,
                trace_id=trace_id,
            )

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValidationError("Invalid Content-Length", code="INVALID_CONTENT_LENGTH") from exc
        if length <= 0:
            raise ValidationError("Request body is required", code="EMPTY_BODY")
        if length > MAX_BODY:
            raise ValidationError(
                f"Body exceeds {MAX_BODY} bytes", code="BODY_TOO_LARGE", http_status=413
            )
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Body must be valid UTF-8 JSON", code="INVALID_JSON") from exc
        if not isinstance(payload, dict):
            raise ValidationError("Body must be a JSON object", code="INVALID_JSON")
        return payload


def make_server(
    control: ControlPlane,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    tokens: ApiTokenStore | None = None,
    metrics: Metrics | None = None,
    rate_limit_per_second: float = 20.0,
    burst: int = 40,
    require_auth: bool = True,
) -> ThreadingHTTPServer:
    if require_auth and tokens is None:
        raise AuthenticationError(
            "Refusing to start without an API token store; pass tokens or set require_auth=False for local dev",
            code="NO_API_TOKENS",
        )
    handler = type(
        "WhyWardHandler",
        (_Handler,),
        {
            "control": control,
            "tokens": tokens or ApiTokenStore(),
            "limiter": TokenBucket(rate_limit_per_second, burst),
            "metrics": metrics or control.metrics,
            "require_auth": require_auth,
        },
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def run_server(
    control: ControlPlane,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    tokens: ApiTokenStore | None = None,
    require_auth: bool = True,
) -> None:
    server = make_server(control, host=host, port=port, tokens=tokens, require_auth=require_auth)
    scheme = "http"
    auth_state = "on" if require_auth else "OFF"
    print(f"WhyWard API listening on {scheme}://{host}:{server.server_address[1]} (auth={auth_state})")
    control.logger.warning(
        "api_started",
        host=host,
        port=server.server_address[1],
        auth=require_auth,
        detail="No TLS in this process: terminate TLS at a gateway." if require_auth else "AUTH DISABLED",
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


__all__ = ["SCOPE_ADMIN", "SCOPE_ASK", "SCOPE_AUDIT", "SCOPE_READ", "TokenBucket", "make_server", "run_server"]
