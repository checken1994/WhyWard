# WhyWard

**WhyWard is an evidence-gated boundary control plane for AI workers.**
It sits between a proposing model and the real world: the model may reason,
propose and explain — it may not certify its own evidence, mint its own
permissions, execute unbounded actions or write the audit trail.

```
worker proposes ──▶ evidence + policy gate ──▶ human approval (when required)
                            │                            │
                            ▼                            ▼
                   scoped capability token ──▶ bounded execution ──▶ read-back
                            │                            │
                            └──────── hash-chained ledger ─────────┘
```

## Principles

1. **Reality > model.** A report from a model never outranks what the system
   actually executed and read back.
2. **PASS ≠ correct.** `PASS_WITHIN_SCOPE` means "no blocking finding inside the
   declared scope and evidence window", nothing more.
3. **AI proposes, a human authorises, the core decides.** Approval is bound to a
   specific proposal, task and review package; it expires and cannot be replayed.
4. **Capability lives outside the worker's workspace.** Tokens are single-use,
   bound to an action fingerprint, and revocable by a kill switch.
5. **No unreviewed evidence.** Trust comes from a signed evidence registry, not
   from a field a caller filled in.
6. **Withhold rather than fabricate.** Missing, stale, unsigned or unregistered
   evidence produces an explicit withheld verdict, never a plausible guess.
7. **Actions are small, bounded, observable and reversible.**
8. **WhyWard is not a source of truth.** It is a mechanism that forces a system
   to face its own evidence and its own limits.

## What is in 0.2.0

| Area | Implemented behaviour |
| --- | --- |
| Control plane | Deterministic task state machine, typed `GateDecision`, stable exit codes, Vietnamese/English verdict reasons |
| Evidence | Signed `EvidenceRegistry` (HMAC envelope), freshness (`valid_until`, `review_after`, volatility class), manifest `sha256` + `record_count` enforcement, lineage counting |
| Review | Deterministic roles (missing piece, meta/alternatives, consequence, security, observability, independence); blocking vs advisory findings |
| Approvals | Approval package (what/why/alternatives/consequences/unknowns/rollback), expiry, signed decisions, proposal+task+package digest binding, non-replayable nonces |
| Capability | HMAC tokens, per-action fingerprint binding, single use, SQLite-backed durable used-token store, revocable kill switch |
| Execution | Sandboxed workspace, `read_text` / `write_text` with byte caps, read-back hash verification, symlink and traversal refusal; `run_python` disabled by default, human-gated, container backend or rlimits |
| Ledger | JSONL hash chain, file locking for concurrent writers, fsync, checkpoints and external anchors, signature verification, signed-export report |
| API | Local HTTP server requiring bearer tokens (sha256-stored), scopes, rate limits, body caps, security headers, `WhyWard-Verdict` header on `/ask` |
| CLI | `ask`, `demo`, `verify-ledger`, `checkpoint`, `serve`, `status`, `keygen`, `sign`, `token`, `doctor`, `report` |
| Observability | Structured JSON logs, counters, request IDs, `--trace-id`, OpenAPI document in `docs/api.md` |

Not claimed: production hardening of the container backend (it is optional and
optional in CI), FIPS-grade key management, multi-tenant isolation, semantic
matching beyond the deterministic catalog matcher. See
[`SECURITY.md`](SECURITY.md) for the explicit non-goals and
[`ROADMAP.md`](ROADMAP.md) for what is next.

## Install

Python 3.11+ and no runtime dependencies.

```bash
python -m pip install -e .
whyward --help
```

From source:

```bash
PYTHONPATH=src python -m whyward --help
```

## Quick start

```bash
# 1. governed demo: proposal → review → human-gated write → read-back → ledger
whyward demo --workdir .whyward-demo --catalog examples/catalog

# 2. verify the chain, then anchor it outside the workspace
whyward verify-ledger .whyward-demo/ledger.jsonl \
  --keyring examples/keys/demo.keyring.json --require-signature
whyward checkpoint .whyward-demo/ledger.jsonl --anchor .whyward-demo/anchor.json \
  --keyring examples/keys/demo.keyring.json
whyward verify-ledger .whyward-demo/ledger.jsonl --anchor .whyward-demo/anchor.json \
  --keyring examples/keys/demo.keyring.json

# 3. ask the reviewed catalog
whyward ask --catalog examples/catalog \
  "Trận động đất Valdivia năm 1960 có độ lớn bao nhiêu?"

# 4. an unanswerable question must withhold (exit 3), not guess
whyward ask --catalog examples/catalog "Động đất năm 2004 tại California có độ lớn bao nhiêu?"
echo $?   # 3

# 5. run the authenticated API
whyward token --subject ci --scopes ask,read,metrics --token-store .whyward-demo/tokens.json
whyward serve --catalog examples/catalog --port 8765 --token-store .whyward-demo/tokens.json
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success / answered within scope |
| 1 | refusal or failure (task failed, execution refused) |
| 2 | integrity failure (ledger, manifest, signature, malformed input) |
| 3 | withheld (insufficient evidence, blocked by policy, awaiting human) |
| 4 | configuration error (missing policy, keys, tokens, no container runtime) |
| 5 | unavailable (kill switch engaged, dependency missing) |

These are part of the contract: `set -e` scripts can distinguish "I don't know"
from "it broke".

## Tests and quality gates

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -t tests   # 232 tests, stdlib only
ruff check src tests                                                 # lint
mypy                                                                 # strict, 20 modules
bandit -q -r src -ll                                                 # security scan, medium+
coverage run --source=src/whyward -m pytest -q && coverage report    # gate: 85% branch
PYTHONPATH=src python docs/audit/reproduce_findings.py               # 15 adversarial probes
```

Current results (243 tests, 88% branch coverage, 15/15 probes, 8/8 acceptance
checks on a clean clone) are recorded in
[`docs/audit/2026-10-26-bao-cao-trien-khai.md`](docs/audit/2026-10-26-bao-cao-trien-khai.md)
and [`docs/acceptance/2026-10-26-nghiem-thu-tu-chay.md`](docs/acceptance/2026-10-26-nghiem-thu-tu-chay.md).
The self-run report is explicitly **not** an acceptance verdict — see
[`docs/acceptance/INDEPENDENCE.md`](docs/acceptance/INDEPENDENCE.md).

## Independent acceptance

`docs/acceptance/` contains a clean-room harness plus an independence protocol.
The rule is simple: the author of the change is not the acceptor. An independent
reviewer (a different model or a different human) clones the repo at a pinned
commit, runs the harness from a scratch directory, and publishes its own report
with raw command output attached. The harness refuses to accept a run where the
worktree is dirty, the commit is not recorded, or any probe/test fails.

```bash
python3 docs/acceptance/acceptance_runner.py --report /tmp/acceptance-report.md
```

## Architecture in one screen

```text
External root of trust
  OS identity | signing keys | external log anchor | human authority
                        │
                   Control core
         policy | capability | evidence gate | ledger
                   ▲                  │
       proposal/claim                │ scoped capability
                   │                  ▼
             AI workers          Execution sandbox
                   │                  │
                   └──── evidence ────┘
                             │
                   Evidence & knowledge
             sources | lineage | reviewed catalog
```

Details: [`ARCHITECTURE.md`](ARCHITECTURE.md). API: [`docs/api.md`](docs/api.md).

## Demo data status

`examples/catalog` is a **demo fixture** used to exercise matching, provenance and
freshness mechanics. Its two records are marked `demo_verified` and are only
accepted by the `dev` profile. Producing a real catalog requires an ingestion
pipeline with field-level provenance and human review, as described in the
roadmap. Nothing in this repository claims a fresh production ingestion of
third-party data.

## License

MIT.
