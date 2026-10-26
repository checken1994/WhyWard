# Changelog

## 0.2.0 — 2026-10-26

Security release: every finding of the 2026-10-26 audit is closed and guarded by
a regression test plus an adversarial probe.

### Fixed

- **W-01** approvals are bound to the proposal, task and package digests, expire,
  require a signed envelope in production, and cannot be replayed.
- **W-02** evidence trust is registry-only: caller-asserted `review_status` is
  downgraded, and evidence passed at submit time is ignored.
- **W-03** freshness (`valid_until`, `review_after`, volatility classes) is
  enforced on every answer.
- **W-04** manifest `sha256` and `record_count` are mandatory and verified.
- **W-05** `min_independent_lineages` is enforced per risk tier.
- **W-06** the ledger takes a cross-process lock, re-reads the tail, fsyncs, and
  keeps the chain valid under concurrent writers.
- **W-07** capability tokens are single-use across restarts (SQLite store).
- **W-08** the kill switch blocks issuance, revokes live capabilities and refuses
  execution.
- **W-09** `verify-ledger` reports typed JSON errors with exit code 2 instead of
  raising tracebacks.
- **W-10** withheld answers exit 3; the verdict is always in the payload.
- **W-11** the production profile rejects `demo_verified` evidence.
- **W-12** the API refuses to start without a token store; tokens are
  `ww_`-prefixed, sha256-stored, scoped, rate-limited, and body-capped.
- **W-13** read/write byte caps, symlink refusal, read-back verification.
- **W-14** `run_python` is disabled by default, human-gated in every profile, and
  runs in a container when available (rlimits otherwise).
- **W-15** malformed input raises typed `WhyWardError` codes on every public path.

### Added

- `whyward` CLI: `ask|demo|verify-ledger|checkpoint|serve|status|keygen|sign|token|doctor|report`
  with stable exit codes 0/1/2/3/4/5.
- `EvidenceRegistry` with signed records, lineage and freshness.
- Approval packages, signed decisions and replay protection.
- Durable capability store, revocation and kill switch.
- Structured logs, metrics (`/metrics`), `/healthz`, `/readyz`, `/status`,
  `/ledger/verify`, `/ledger/checkpoint`, `/admin/kill-switch`.
- Container command builder with runtime detection; isolation report in `doctor`.
- 232 stdlib tests, ruff/mypy-strict/bandit clean, 88% branch coverage gate.
- `docs/acceptance/` clean-room harness and independence protocol.

### Changed

- `EvidenceRef.review_status` is no longer a trust signal.
- `submit_proposal()` rejects non-`Proposal` objects instead of failing deep in
  the pipeline.
- CLI `--keyring` is honoured for policy verification (previously only with
  `--require-signed-policy`).
- Python 3.11+ required; no runtime dependencies.

### Removed

- The unsigned `examples/policy.json`; replaced by signed
  `examples/policy.dev.json` and `examples/policy.production.json`.

## 0.1.0

- Initial boundary MVP extracted from Vietnam-Lab: control plane, policy gate,
  capability tokens, sandbox executor, hash-chained ledger, human comprehension
  gate, catalog store and CLI/API.

## 0.0.x

- Prototype exploration inside the Vietnam-Lab monolith.
