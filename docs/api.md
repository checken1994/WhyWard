# HTTP API (WhyWard 0.2.0)

The API is a thin, authenticated surface over the control plane. It is not a
general-purpose agent gateway: it can ask the reviewed catalog and let an
operator engage the kill switch. It cannot execute actions — execution is only
reachable through the control plane's own gate.

## Running it

```bash
whyward token --subject ci --scopes ask,read,metrics,audit --token-store ./tokens.json
whyward serve --catalog examples/catalog --port 8765 --token-store ./tokens.json
```

`serve` refuses to start without a token store (`exit 4`, `NO_API_TOKENS`). The
token file stores only `token_sha256`; the plaintext token is printed once.
There is no in-process TLS: terminate TLS at a gateway and keep the process on a
private interface.

## Authentication

```
Authorization: Bearer ww_<token>
```

| Scope | Grants |
| --- | --- |
| `ask` | `POST /ask` |
| `read` | `GET /status` |
| `metrics` | `GET /metrics` |
| `audit` | `GET /ledger/verify`, `GET /ledger/checkpoint` |
| `admin` | `POST /admin/kill-switch` |

- Unknown or malformed tokens → `401` with a `WWW-Authenticate: Bearer` header.
- Valid token, wrong scope → `403`.
- Per-subject token bucket → `429` with `Retry-After`.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/healthz` (also `/health`, `/livez`) | none | liveness only; no state |
| GET | `/readyz` | none | readiness: ledger valid and kill switch released; `503` otherwise |
| GET | `/version` | none | version, policy digest, dataset digest |
| GET | `/status` | `read` | full enforcement status |
| GET | `/metrics` | `metrics` | Prometheus text format |
| GET | `/ledger/verify` | `audit` | recompute the hash chain |
| GET | `/ledger/checkpoint` | `audit` | current checkpoint (sign if configured) |
| POST | `/ask` | `ask` | answer a question from the reviewed catalog |
| POST | `/admin/kill-switch` | `admin` | `{"action": "engage"\|"release", "reason": "…"}` |

### `POST /ask`

```json
{ "question": "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?", "domain": "geology.earthquake" }
```

Response is always `200` with the verdict in the body **and** in the
`WhyWard-Verdict` header, so proxies and clients can route without parsing:

```json
{
  "verdict": "PASS_WITHIN_SCOPE",
  "answer": "Valdivia 1960: magnitude = 9.5.",
  "evidence": { "evidence_id": "catalog:…", "source_id": "usgs", "lineage_id": "…", "signed": true },
  "reasons": ["entity_name_matched", "year_matched"],
  "policy_digest": "…",
  "dataset_digest": "…",
  "trace_id": "…"
}
```

Withheld answers use `verdict: INSUFFICIENT_EVIDENCE` (or `BLOCKED_BY_POLICY`,
`FOUND_STALE`) with `answer: null` and an explanatory `reasons` list. A withheld
answer is a *successful* HTTP request describing a refusal — the CLI maps it to
exit code 3.

Errors follow `application/problem+json`:

```json
{ "type": "about:blank", "title": "…", "status": 401, "code": "UNAUTHENTICATED",
  "detail": "…", "instance": "/ask", "trace_id": "…" }
```

## Limits and headers

- Request bodies: 64 KiB (`413` above).
- Questions: 2 000 characters (`422`).
- Responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` and a request id.
- Every request is counted in `/metrics` with route and verdict labels; no
  question text is ever logged, only a sha256 of it.

## Operational contract

- `/readyz` returns `503` while the kill switch is engaged or the ledger fails
  verification. Use it as the load-balancer probe.
- Engaging the kill switch revokes live capability tokens and refuses execution
  immediately, in every process that shares the token store.
- `GET /ledger/verify` is cheap; run it on a schedule and compare the head hash
  with your external anchor.
