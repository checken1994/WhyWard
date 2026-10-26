# Security Policy & Threat Model — WhyWard 0.2.0

## Status

WhyWard 0.2.0 closes the fifteen findings of the 2026-10-26 audit and enforces
them with regression tests plus an adversarial probe harness. It is still **not**
a certified security product, and this document lists exactly where the boundary
ends so that nobody has to guess.

What this release does claim:

- every gate in the request path is enforced by code, not by convention;
- every claim below has a test that fails if the behaviour regresses;
- nothing in the repository asserts a capability the code cannot demonstrate.

## Assets

- Policy, policy signing keys, capability signing secret.
- The approved evidence registry and the reviewed catalog.
- The audit ledger and its external anchors.
- Approver identity and approval artefacts.
- Worker workspaces and the systems an action may touch.

## Adversaries in scope

1. A hallucinating or over-confident model.
2. A prompt-injected worker asking for out-of-scope actions.
3. A poisoned, stale or unreviewed evidence source.
4. A tool reporting success while the real state did not change.
5. A worker trying to widen its own permissions or replay a capability.
6. An operator approving mechanically without understanding consequences.
7. A caller sending malformed input to the control plane or the API.

## Out of scope (cannot be defended from inside WhyWard)

- Full host/root/cloud-account compromise.
- Theft of a signing key **and** the approver identity at the same time.
- Hardware or hypervisor tampering.
- A single authoritative source being wrong with no independent lineage.
- An authorised human deliberately approving destructive behaviour.

Those require IAM, MFA, admin separation, HSM/secret manager, immutable backups,
independent monitoring and an organisational process.

## Controls, mapped to findings

| ID | Finding (2026-10-26) | Control now enforced | Test |
| --- | --- | --- | --- |
| W-01 | Approval replay across proposals | Decision carries `proposal_digest`, `task_id`, `package_digest`, `expires_at`, `nonce`; the core recomputes and rejects mismatches and replays | `test_boundaries.DecisionBindingTests` |
| W-02 | Caller self-certifies evidence | Evidence trust is registry-only; `register_evidence()` downgrades to `unverified`; `submit_proposal(evidence=...)` is ignored with a warning | `test_boundaries.EvidenceTrustTests` |
| W-03 | Freshness ignored | `valid_until`, `review_after`, volatility classes; stale lookups return `INSUFFICIENT_EVIDENCE` | `test_boundaries.EvidenceTrustTests.test_expired_evidence_is_withheld` |
| W-04 | Manifest `sha256`/`record_count` unenforced | Both are mandatory and verified at load; mismatch is a hard `IntegrityError` | `test_boundaries.CatalogIntegrityTests` |
| W-05 | No lineage minimum | `min_independent_lineages` per risk tier, enforced in review | `test_boundaries.ReviewGateTests` |
| W-06 | Concurrent ledger writes corrupt the chain | Cross-platform file lock, tail reload, fsync, hash chain | `test_boundaries.LedgerTests.test_concurrent_appends_keep_chain_valid` |
| W-07 | Capability survives a restart | Used-token store is SQLite-backed and durable; replay after restart fails | `test_boundaries.CapabilityTests` |
| W-08 | Kill switch does not revoke | Engage blocks issuance, revokes live capabilities and refuses execution | `test_api`, `test_edge_cases.BoundaryHardeningTests` |
| W-09 | `verify-ledger` traceback | Typed errors, JSON problem output, exit code 2 | `test_cli_inprocess`, probe W-09 |
| W-10 | `ask` exits 0 when withheld | Withheld → exit 3; the verdict is always in the payload | `test_cli_e2e`, probe W-10 |
| W-11 | `demo_verified` accepted in production | Review status acceptance comes from the profile; production accepts `verified` only | `test_boundaries.ReviewGateTests` |
| W-12 | Unauthenticated API | Server refuses to start without a token store; bearer tokens, scopes, rate limits, body caps, security headers | `test_api` |
| W-13 | Unbounded read/write | `max_read_bytes` (truncating), `max_write_bytes` (refusing), no symlink writes, read-back verification | `test_boundaries.ExecutionLimitsTests` |
| W-14 | `run_python` reaches the host | Disabled by default; human-required tool in every profile; container backend preferred; rlimits and a minimal environment otherwise | `test_boundaries.ExecutionLimitsTests`, `test_edge_cases.ExecutionEdgeTests` |
| W-15 | Raw `ValueError` from bad input | Typed `WhyWardError` subclasses with codes for every public entry point | `test_edge_cases.BoundaryHardeningTests` |

## Known limits after 0.2.0

- **`run_python` is not OS-level isolation by default.** The container backend is
  the only real isolation story; the subprocess backend uses rlimits and a
  restricted environment. If no container runtime is available the CLI prints a
  warning, and the default policy still disallows `run_python`.
- **No TLS in-process.** Terminate TLS at a gateway; the server logs that fact at
  startup.
- **Token store durability.** `SqliteUsedTokenStore` is durable across restarts
  for a single host. Multi-host deployments need a shared store (see roadmap).
- **Ledger deletion.** The hash chain detects modification and truncation only
  against an anchor stored outside the workspace. Anchor frequently.
- **Policy signatures are HMAC.** Symmetric: whoever can verify can also sign.
  Asymmetric signing (Ed25519) is the next step.
- **The demo catalog is a fixture.** `demo_verified` records are accepted only by
  the `dev` profile.
- **Denial of service.** Rate limits and body caps exist; a hostile authenticated
  client can still spend CPU on expensive queries.

## Vulnerability reporting

Do not open a public issue with an exploit. Report privately to the maintainers
with a minimal reproduction, affected commit and expected vs actual behaviour.
Reports about the probe harness itself are welcome: it is intended to be the
honest, adversarial part of this repository.

## Reproducing the security claims

```bash
PYTHONPATH=src python docs/audit/reproduce_findings.py     # 15 adversarial probes
PYTHONPATH=src python -m unittest discover -s tests -t tests
bandit -q -r src -ll
```
