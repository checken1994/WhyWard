# Roadmap

Rule: capability is not added because an argument sounds convincing. Each step
needs running evidence, negative tests and a rollback path.

## 0.1 — Boundary MVP (released, superseded)

- [x] ControlPlane with a deterministic task state machine.
- [x] Policy/capability/read-back baseline.
- [x] Hash-chained ledger and checkpoints.
- [x] Human comprehension recorded as data.
- [x] JSONL catalog with manifest checksum.
- [x] Valdivia/Sumatra matching regression.
- [x] CLI and local API.

The 2026-10-26 audit showed these guarantees were **stated but not enforced**:
approvals were not bound to proposals, self-declared evidence was trusted,
capabilities survived restarts, concurrent ledger writes corrupted the chain, and
freshness was ignored. That audit is the entry criterion for 0.2.

## 0.2 — Enforced boundary (this release)

- [x] 15/15 probes in `docs/audit/reproduce_findings.py` report `OK` and run in CI.
- [x] Approvals bound to proposal + task + package digests, expiring, signed,
      non-replayable.
- [x] Evidence trust moved into a signed registry; caller assertions downgraded.
- [x] Freshness, manifest checksum/record count and lineage minimums enforced.
- [x] Ledger: cross-process lock, fsync, anchor verification, typed failures.
- [x] Durable single-use capability tokens; kill switch revokes live tokens.
- [x] Authenticated API with scopes, rate limits and body caps.
- [x] Bounded execution; `run_python` disabled by default and human-gated.
- [x] Typed errors and stable exit codes on every CLI path.
- [x] Quality gates: ruff, mypy strict, bandit, 85% branch coverage, probes.
- [x] Independent acceptance harness and protocol (`docs/acceptance/`).

## 0.3 — Real source ingestion

- [ ] Source registry per domain (owner, licence, endpoint, rate limit).
- [ ] USGS ingestion that stores the raw source record plus field-level
      provenance and `retrieved_at`.
- [ ] Staging/quarantine, re-fetch checks, and promotion workflow with review.
- [ ] Freshness and completeness policy per domain, with alerting.
- [ ] `demo_verified` removed from production acceptance (already rejected by the
      production profile; remove the fixture path entirely).
- [ ] Catalog signatures produced by an ingestion key that never sits next to
      the ingestion code.

## 0.4 — Worker adapters

- [ ] At least one external model adapter (proposal-only, no tools).
- [ ] One coding-agent adapter in proposal-only mode.
- [ ] Record provider, model, version and context lineage in every proposal.
- [ ] Contract tests: a hostile adapter cannot escalate beyond the gate.

## 0.5 — Operational hardening

- [ ] Asymmetric signing (Ed25519) for policies, evidence and ledger events.
- [ ] Shared used-token store and shared kill-switch state across hosts.
- [ ] Mandatory container backend with a pinned image digest; `run_python`
      impossible without it in production.
- [ ] mTLS or gateway-terminated TLS profile, with `Strict-Transport-Security`.
- [ ] Ledger shipping to an append-only external sink on every commit point.
- [ ] Load and chaos tests on the gate path.
- [ ] External security review of the threat model and the crypto envelope.

## Definition of done for every future phase

1. A negative test that fails on the previous commit and passes on the new one.
2. A probe in `docs/audit/reproduce_findings.py` that demonstrates the boundary.
3. Documentation updated in the same commit (README, SECURITY, ARCHITECTURE).
4. The independent acceptance harness run by someone who did not write the code.
5. No claim in documentation that exceeds what the tests demonstrate.
