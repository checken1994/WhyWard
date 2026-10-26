# Clean-room acceptance

This directory exists so that WhyWard can be judged by someone who did not
build it.

| File | Purpose |
| --- | --- |
| `acceptance_runner.py` | One command that decides whether the checkout behaves as documented. Black-box first: subprocesses, exit codes, files, HTTP. |
| `INDEPENDENCE.md` | Who counts as independent, what to run, what to publish, when to reject. |
| `2026-10-26-nghiem-thu-tu-chay.md` | A self-run of the harness by the implementing agent — explicitly labelled **provisional**, not acceptance. |

## What the harness checks

| ID | Check | Why it matters |
| --- | --- | --- |
| A-01 | Clean worktree + recorded commit | A verdict on an unknown tree is meaningless |
| A-02 | Package imports only the standard library | No hidden dependency or supply-chain surprise |
| A-03 | Repository test suite passes | Baseline correctness |
| A-04 | 15 adversarial probes all `OK` | The security claims, tested adversarially |
| A-05 | Operator journey end to end | The product actually works, not just the tests |
| A-06 | Tampering is detected (ledger edit, truncation, catalog edit) | The audit trail is trustworthy |
| A-07 | API refuses anonymous access; kill switch flips readiness | The operational surface fails closed |
| A-08 | Security doc names only controls that exist | No documentation theatre |

## Usage

```bash
python3 docs/acceptance/acceptance_runner.py \
    --report acceptance-report.md --json acceptance-report.json
```

- Exit code 0 only if all checks pass; 2 if the tree is dirty and `--allow-dirty`
  was not given.
- `--allow-dirty` produces a **PROVISIONAL** report, useful during development and
  never valid as acceptance.
- The harness writes nothing into the repository: every artefact goes to a
  temporary directory and to the paths you pass explicitly.

## What this harness does not check

- Container-isolation behaviour (`run_python` inside Docker/Podman) — needs a
  runtime; a reviewer with one should report it as a separate scoped result.
- Multi-host deployment, TLS termination, backup/restore, load behaviour.
- Whether the *policy* is sensible (TTLs, tiers, allowed tools) — a governance
  question, not a code question.
- Cryptographic review of the HMAC envelope.
