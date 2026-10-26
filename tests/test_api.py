"""HTTP boundary tests: authentication, authorization, errors, limits, headers."""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from typing import Any

from support import build_control

from whyward.api import SCOPE_ADMIN, SCOPE_ASK, SCOPE_AUDIT, SCOPE_READ, TokenBucket, make_server
from whyward.identity import ApiTokenStore, generate_api_token


class ApiTestBase(unittest.TestCase):
    rate_limit = 50.0

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.control = build_control(self._tmp.name)
        self.tokens = ApiTokenStore()
        self.ask_token = generate_api_token()
        self.admin_token = generate_api_token()
        self.audit_token = generate_api_token()
        self.tokens.add(self.ask_token, "client-a", [SCOPE_ASK])
        self.tokens.add(self.admin_token, "operator", [SCOPE_ADMIN, SCOPE_READ])
        self.tokens.add(self.audit_token, "auditor", [SCOPE_AUDIT])
        self.server = make_server(
            self.control,
            host="127.0.0.1",
            port=0,
            tokens=self.tokens,
            rate_limit_per_second=self.rate_limit,
            burst=10,
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self._tmp.cleanup()

    # ------------------------------------------------------------------ #
    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        data = raw_body
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        # http.client, not urllib: urllib reads proxy settings (including the
        # Windows registry) and would route a localhost request through a proxy.
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        request_headers = {"Content-Type": "application/json"}
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        request_headers.update(headers or {})
        try:
            connection.request(method, path, body=data, headers=request_headers)
            response = connection.getresponse()
            payload = response.read()
            response_headers: dict[str, str] = dict(response.getheaders())
            return response.status, response_headers, payload
        finally:
            connection.close()

    def json_of(self, payload: bytes) -> dict[str, Any]:
        return json.loads(payload.decode("utf-8"))


class AuthenticationTests(ApiTestBase):
    def test_health_is_anonymous_but_exposes_no_data(self) -> None:
        status, headers, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        body = self.json_of(payload)
        self.assertEqual(body["status"], "ok")
        self.assertNotIn("dataset_digest", body)
        self.assertNotIn("Python/", headers.get("Server", ""))

    def test_ask_requires_a_token(self) -> None:
        status, headers, payload = self.request("POST", "/ask", body={"question": "Valdivia?"})
        self.assertEqual(status, 401)
        self.assertIn("application/problem+json", headers.get("Content-Type", ""))
        problem = self.json_of(payload)
        self.assertEqual(problem["code"], "MISSING_CREDENTIALS")
        self.assertEqual(problem["status"], 401)
        self.assertTrue(problem["trace_id"])
        self.assertIn("Bearer", headers.get("WWW-Authenticate", ""))

    def test_invalid_token_is_rejected(self) -> None:
        status, _, payload = self.request(
            "POST", "/ask", token="ww_" + "a" * 40, body={"question": "Valdivia?"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(self.json_of(payload)["code"], "INVALID_CREDENTIALS")

    def test_wrong_scheme_is_rejected(self) -> None:
        status, _, payload = self.request(
            "POST", "/ask", headers={"Authorization": "Basic Zm9vOmJhcg=="}, body={"question": "x"}
        )
        self.assertEqual(status, 401)
        self.assertEqual(self.json_of(payload)["code"], "UNSUPPORTED_AUTH_SCHEME")

    def test_scope_is_enforced(self) -> None:
        status, _, payload = self.request("GET", "/status", token=self.ask_token)
        self.assertEqual(status, 403)
        self.assertEqual(self.json_of(payload)["code"], "FORBIDDEN")

    def test_anonymous_status_is_rejected(self) -> None:
        status, _, _ = self.request("GET", "/status")
        self.assertEqual(status, 401)


class AskEndpointTests(ApiTestBase):
    def test_ask_returns_answer_with_verdict_header(self) -> None:
        status, headers, payload = self.request(
            "POST",
            "/ask",
            token=self.ask_token,
            body={"question": "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?"},
        )
        self.assertEqual(status, 200)
        body = self.json_of(payload)
        self.assertEqual(body["verdict"], "PASS_WITHIN_SCOPE")
        self.assertEqual(headers.get("WhyWard-Verdict"), "PASS_WITHIN_SCOPE")
        self.assertIn("9.5", body["answer"])
        self.assertTrue(body["dataset_digest"])
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_withheld_answer_is_marked(self) -> None:
        status, headers, payload = self.request(
            "POST",
            "/ask",
            token=self.ask_token,
            body={"question": "Động đất năm 2004 tại California có độ lớn bao nhiêu?"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.json_of(payload)["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(headers.get("WhyWard-Verdict"), "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(self.json_of(payload)["answer"])

    def test_missing_question_is_a_problem(self) -> None:
        status, _, payload = self.request("POST", "/ask", token=self.ask_token, body={})
        self.assertEqual(status, 400)
        self.assertEqual(self.json_of(payload)["code"], "QUESTION_REQUIRED")

    def test_invalid_json_is_a_problem(self) -> None:
        status, _, payload = self.request("POST", "/ask", token=self.ask_token, raw_body=b"{not json")
        self.assertEqual(status, 400)
        self.assertEqual(self.json_of(payload)["code"], "INVALID_JSON")

    def test_oversized_body_is_rejected(self) -> None:
        big = json.dumps({"question": "a" * 70_000}).encode("utf-8")
        status, _, payload = self.request("POST", "/ask", token=self.ask_token, raw_body=big)
        self.assertEqual(status, 413)
        self.assertEqual(self.json_of(payload)["code"], "BODY_TOO_LARGE")

    def test_traceparent_is_propagated(self) -> None:
        trace_id = "b" * 32
        status, headers, payload = self.request(
            "POST",
            "/ask",
            token=self.ask_token,
            body={"question": "Valdivia 1960 magnitude?"},
            headers={"traceparent": f"00-{trace_id}-{'c' * 16}-01"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Request-Id"), trace_id)
        self.assertEqual(self.json_of(payload)["trace_id"], trace_id)
        events = list(self.control.ledger.iter_events())
        self.assertTrue(any(event.get("trace_id") == trace_id for event in events))

    def test_rate_limit_is_enforced(self) -> None:
        limiter_server = make_server(
            self.control,
            host="127.0.0.1",
            port=0,
            tokens=self.tokens,
            rate_limit_per_second=0.001,
            burst=1,
        )
        port = limiter_server.server_address[1]
        thread = threading.Thread(target=limiter_server.serve_forever, daemon=True)
        thread.start()
        try:
            statuses = []
            for _ in range(3):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                try:
                    connection.request(
                        "POST",
                        "/ask",
                        body=json.dumps({"question": "Valdivia 1960?"}).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {self.ask_token}",
                        },
                    )
                    statuses.append(connection.getresponse().status)
                finally:
                    connection.close()
            self.assertIn(429, statuses)
        finally:
            limiter_server.shutdown()
            limiter_server.server_close()
            thread.join(timeout=5)


class OperatorEndpointTests(ApiTestBase):
    def test_audit_scope_can_verify_ledger(self) -> None:
        status, _, payload = self.request("GET", "/ledger/verify", token=self.audit_token)
        self.assertEqual(status, 200)
        self.assertTrue(self.json_of(payload)["valid"])

    def test_metrics_requires_metrics_scope(self) -> None:
        status, _, _ = self.request("GET", "/metrics", token=self.ask_token)
        self.assertIn(status, {401, 403})

    def test_status_reports_enforced_controls(self) -> None:
        status, _, payload = self.request("GET", "/status", token=self.admin_token)
        self.assertEqual(status, 200)
        body = self.json_of(payload)
        self.assertEqual(body["policy"]["profile"], "dev")
        self.assertTrue(body["evidence"]["registry_configured"])
        self.assertGreaterEqual(body["evidence"]["registry_records"], 2)
        self.assertTrue(body["ledger"]["valid"])

    def test_kill_switch_endpoint(self) -> None:
        status, _, payload = self.request(
            "POST",
            "/admin/kill-switch",
            token=self.admin_token,
            body={"action": "engage", "reason": "drill"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(self.json_of(payload)["ok"])
        status, _, payload = self.request("GET", "/readyz")
        self.assertEqual(status, 503)
        status, _, payload = self.request(
            "POST", "/ask", token=self.ask_token, body={"question": "Valdivia 1960?"}
        )
        self.assertEqual(self.json_of(payload)["verdict"], "BLOCKED_BY_POLICY")
        status, _, _ = self.request(
            "POST", "/admin/kill-switch", token=self.admin_token, body={"action": "release"}
        )
        self.assertEqual(status, 200)

    def test_unknown_route_is_a_problem(self) -> None:
        status, _, payload = self.request("GET", "/does-not-exist", token=self.admin_token)
        self.assertEqual(status, 404)
        self.assertEqual(self.json_of(payload)["code"], "NOT_FOUND")

    def test_query_string_does_not_break_routing(self) -> None:
        status, _, _ = self.request("GET", "/healthz?probe=1")
        self.assertEqual(status, 200)

    def test_head_and_options_are_supported(self) -> None:
        status, headers, _ = self.request("HEAD", "/healthz")
        self.assertEqual(status, 200)
        self.assertTrue(int(headers.get("Content-Length", "0")) > 0)
        status, headers, _ = self.request("OPTIONS", "/ask")
        self.assertEqual(status, 204)
        self.assertIn("POST", headers.get("Allow", ""))

    def test_unsupported_method_is_501(self) -> None:
        status, _, _ = self.request("PUT", "/ask", token=self.admin_token, raw_body=b"{}")
        self.assertEqual(status, 501)


class ServerConfigurationTests(unittest.TestCase):
    def test_server_refuses_to_start_without_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = build_control(tmp)
            from whyward.errors import AuthenticationError

            with self.assertRaises(AuthenticationError):
                make_server(control, port=0, tokens=None, require_auth=True)
            server = make_server(control, port=0, tokens=None, require_auth=False)
            self.assertIsNotNone(server)
            server.server_close()

    def test_token_bucket_is_deterministic(self) -> None:
        bucket = TokenBucket(rate_per_second=0.0, burst=2)
        self.assertTrue(bucket.allow("a"))
        self.assertTrue(bucket.allow("a"))
        self.assertFalse(bucket.allow("a"))
        self.assertTrue(bucket.allow("b"))


if __name__ == "__main__":
    unittest.main()
