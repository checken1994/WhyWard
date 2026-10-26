# Architecture — WhyWard 0.2.0

WhyWard is a small control plane with one job: make it impossible for a
proposing model to grant itself permission, certify its own evidence, or hide
what actually happened. Everything else is deliberately outside the core.

## 1. Component map

```text
                       ┌──────────────────────────────────────────┐
 external root of      │              ControlPlane                │
 trust                 │                                          │
 ┌────────────────┐    │  policy ──▶ review ──▶ approval gate     │      ┌───────────────┐
 │ signing keys   │───▶│     │                       │            │─────▶│ Ledger        │
 │ approver ID    │    │     ▼                       ▼            │      │ hash chain    │
 │ log anchor     │    │  evidence registry     capability broker │      │ + anchors     │
 └────────────────┘    │     │                       │            │      └───────────────┘
                       │     ▼                       ▼            │
                       │  KnowledgeStore       SandboxExecutor     │
                       └─────▲───────────────────────▲─────────────┘
                             │                       │
                    evidence │              scoped   │ results, read-back hash
                             │            capability │
                        ┌────┴────┐           ┌───────┴───────┐
                        │ Worker  │──────────▶│  Workspace    │
                        │ (model) │ proposal  │  (sandboxed)  │
                        └─────────┘           └───────────────┘
```

| Module | Responsibility | Trust level |
| --- | --- | --- |
| `canonical.py` | Canonical JSON, digests, timestamp helpers | pure |
| `identity.py` | Keyring, HMAC envelopes, API tokens | root of trust |
| `policy.py` | Profile, allowlists, limits, freshness classes, signing | root of trust |
| `evidence.py` | Catalog loading, manifest verification, matching, freshness | semi-trusted |
| `registry.py` | Signed evidence records, review status, lineage | semi-trusted |
| `review.py` | Deterministic findings and verdicts | core |
| `capability.py` | Token issuance/consumption, durable used-token store | core |
| `execution.py` | Bounded actions, read-back verification | core |
| `isolation.py` | Container command construction, runtime detection | core |
| `control.py` | State machine, gate decisions, approvals, kill switch | core |
| `ledger.py` | Append-only hash chain, checkpoints, anchors | core |
| `api.py`, `cli.py` | Untrusted input surfaces | edge |
| `observability.py` | Structured logs, metrics | edge |

A worker only ever sees `Worker`, `Proposal`, `TaskRecord` and the executor's
result dictionaries. It never holds a capability, a policy object, a ledger
handle or an approval object.

## 2. Decision flow

```
1  task received            → TASK_RECEIVED event
2  proposal received        → typed validation (W-15) → PROPOSAL_RECEIVED
3  policy gate              → tool/resource/protected path, action count
4  evidence gate            → registry lookup, signature, review status,
                              freshness, independent lineage count
5  review                   → deterministic findings per role
6  human gate (if required) → approval package → bound, expiring, signed,
                              non-replayable decision
7  capability               → per-action token, fingerprint-bound, single use
8  execution                → bounded action, kill-switch check, read-back hash
9  verification             → compare read-back to intent
10 completion               → COMPLETED / FAIL / FAILED_ROLLBACK_REQUIRED
```

Every step writes a ledger event containing the trace id, the policy digest, the
dataset digest and the relevant artefact digest. Reconstructing "why did this
happen?" is a filter over the ledger, not a log hunt.

### Verdicts

`PASS_WITHIN_SCOPE`, `FOUND_STALE`, `INSUFFICIENT_EVIDENCE`,
`BLOCKED_BY_POLICY`, `AWAITING_HUMAN`, `INSUFFICIENT_OBSERVABILITY`, `FAIL`,
`FAILED_ROLLBACK_REQUIRED`, `REJECTED_STATE`.

`PASS_WITHIN_SCOPE` is scoped by construction: it names the policy digest and the
dataset digest it was evaluated against.

## 3. Evidence model

A catalog record (what a source said) and an evidence record (what the control
core vouches for) are separate objects.

```json
{
  "evidence_id": "catalog:geology.earthquake:valdivia-1960",
  "source_id": "usgs",
  "lineage_id": "usgs-comcat",
  "retrieved_at": "2026-10-26T00:00:00Z",
  "observed_fields": ["magnitude"],
  "blind_spots": ["no independent refetch"],
  "review_status": "verified",
  "content_hash": "…",
  "registry_signature": {"algorithm": "hmac-sha256", "key_id": "evidence-ingest", "value": "…"}
}
```

Rules:

- A caller-provided `review_status` is never trusted; `register_evidence()`
  forces `unverified`, and `submit_proposal(evidence=…)` is ignored.
- Lookup requires a registry record; missing → withheld with `UNKNOWN_EVIDENCE`.
- `valid_until` in the past → withheld. `review_after` in the past → `FOUND_STALE`
  with the staleness visible in the answer and the ledger.
- Risk tiers require a minimum number of independent lineages (`lineage_id`).

## 4. Capability model

```text
payload = {schema, capability_id, issuer, audience, proposal_id, proposal_digest,
           task_id, actions[{action_id, tool, resource, fingerprint}],
           not_before, expires_at, nonce}
token   = base64(canonical_json(payload)) + "." + base64(hmac(key, payload))
```

- The executor verifies the signature, the audience, the expiry, the action
  fingerprint and then claims the token in a **durable** used-token store.
- Two concurrent claims → exactly one wins (SQLite primary key on the token).
- `revoke_all()` marks every live capability revoked; the kill switch calls it,
  so tokens already issued stop working.

## 5. Ledger model

```
event = {schema_version, seq, previous_hash, event_hash, event_type,
         ts, trace_id, actor, payload, signature?}
event_hash = sha256(canonical_json({…event without event_hash…}))
```

- Appends take an exclusive file lock, re-read the tail, then fsync.
- `verify()` recomputes the chain and checks every signature it can resolve.
- A checkpoint `{event_count, head_hash, created_at, signature}` is written to an
  **external** anchor; `verify_against_anchor()` detects truncation and rewrite.
- Deleting the whole ledger file is only detectable against a previously stored
  anchor, which is why anchoring is part of the operational contract.

## 6. Execution model

| Tool | Bound |
| --- | --- |
| `read_text` | reads at most `max_read_bytes + 1`, truncates, refuses symlinks |
| `write_text` | rejects payloads over `max_write_bytes`, refuses to write through symlinks, verifies the read-back hash, records the pre-image |
| `run_python` | disabled unless `allow_python` **and** the policy allows the tool; human approval is mandatory; container backend preferred; rlimits + minimal env otherwise; wall-clock and output caps |

The executor never accepts an absolute path, a `..` component or a NUL byte, and
resolves every path to confirm it stays under the workspace root.

## 7. Failure philosophy

The control plane is designed to fail **closed and typed**:

- unknown key id → refuse (never "trust anyway");
- unreadable policy/catalog/manifest → `POLICY_*` / `CATALOG_*` error, exit 2/4;
- missing token store → the API refuses to start;
- kill switch → 503 on `/readyz`, `BLOCKED_BY_POLICY` on `/ask`;
- no container runtime → warn (stderr) and keep `run_python` unavailable unless
  the operator explicitly enabled it.

## 8. Extension points

- `Worker` protocol: adapters for external models belong here and stay
  proposal-only.
- `PythonBackend`: the container backend can be replaced by any isolated runtime.
- `UsedTokenStore`: swap SQLite for a shared store in multi-host deployments.
- `Keyring`: HMAC today; the envelope format has `algorithm` and `key_id` fields
  so asymmetric signing can be added without a data migration.
