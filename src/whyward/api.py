from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from . import __version__
from .control import ControlPlane

MAX_BODY = 64 * 1024


def run_server(control: ControlPlane, host: str = "127.0.0.1", port: int = 8765) -> None:
    """Run a small local development API.

    This stdlib server intentionally exposes only health, lookup and ledger
    verification. It has no production authentication/TLS and must not be
    exposed directly to an untrusted network.
    """

    class Handler(BaseHTTPRequestHandler):
        server_version = f"WhyWard/{__version__}"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "system": "WhyWard",
                        "version": __version__,
                        "kill_switch_engaged": control.kill_switch_engaged(),
                        "dataset_version": (
                            control.knowledge_store.dataset_version if control.knowledge_store else None
                        ),
                    },
                )
                return
            if self.path == "/ledger/verify":
                valid, message = control.ledger.verify()
                self._send_json(HTTPStatus.OK, {"valid": valid, "message": message})
                return
            if self.path == "/checkpoint":
                try:
                    self._send_json(HTTPStatus.OK, control.ledger.checkpoint())
                except ValueError as exc:
                    self._send_json(HTTPStatus.CONFLICT, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/ask":
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "invalid body size"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                question = str(payload.get("question", "")).strip()
            except Exception:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
                return
            if not question:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "question is required"})
                return
            self._send_json(HTTPStatus.OK, control.answer_question(question, actor="api"))

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"WhyWard local API listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
