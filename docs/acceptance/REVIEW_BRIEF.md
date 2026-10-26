# Independent review brief — WhyWard

> Hand this file, and only this file, to the reviewer. Do not send the
> implementing agent's transcript, notes, or expected numbers. Independence is
> about information, not identity.

---

## Your role

You are the **independent acceptor** for this repository. You did not write the
code in it, and nobody has told you what is supposed to pass. Your job is to
decide whether the repository, as checked out, behaves the way its documentation
claims — and to say so in writing, with evidence.

You are not here to be polite, and you are not here to find something to
complain about. A verdict of REJECTED with two concrete findings is more useful
than ACCEPTED with none.

## Ground rules

1. **Do not modify any file** in the repository. Do not fix anything you find;
   report it.
2. **Do not trust the project's own tests alone.** They were written by the same
   person as the code. Re-derive the key behaviours yourself (step 4).
3. **A dirty worktree, an unknown commit, or a modified test file invalidates the
   run.** Stop and say so.
4. **No network is required.** Python 3.11+ and nothing else.
5. If a claim in `README.md`, `SECURITY.md` or `ARCHITECTURE.md` cannot be
   demonstrated by running code, that is a finding — even if every test passes.

## Step 1 — clean room

```bash
git clone https://github.com/checken1994/WhyWard
cd WhyWard
git checkout <commit-under-review>
git status --porcelain          # must print nothing
git rev-parse HEAD              # record this hash in your report
```

## Step 2 — run the acceptance harness

```bash
python3 docs/acceptance/acceptance_runner.py \
    --report acceptance-report.md \
    --json acceptance-report.json
```

It prints one line per check and exits 0 only when all nine pass. Expected shape
(check the actual output, not this description):

| ID | What it proves |
| --- | --- |
| A-01 | The tree is clean and the commit is recorded |
| A-02 | The package imports only the standard library |
| A-03 | The repository's own test suite passes |
| A-04 | Every adversarial probe in `docs/audit/reproduce_findings.py` reports `OK` |
| A-05 | Operator journey works end to end (demo → verify → anchor → ask → withhold → report → doctor) |
| A-06 | Tampering is detected (ledger edit, ledger truncation vs. anchor, catalog edit) |
| A-07 | The API fails closed (no token store, anonymous 401, kill switch → 503) |
| A-08 | The security document names only controls that exist in the code |
| A-09 | Removing any single control is detected (mutation check) |

## Step 3 — run the mutation check yourself

```bash
python3 docs/acceptance/falsification_check.py
```

This disables one security control at a time in a throwaway copy and requires the
probes to notice. If any mutation survives, the "green" result means nothing —
report it as an evidence hole.

## Step 4 — re-derive the four critical behaviours by hand

Do not skip this step. Use your own commands; the exact syntax is in
`README.md` and `--help`.

| # | Do this | Required result |
| --- | --- | --- |
| 4.1 | Ask a question the supplied catalog cannot answer | Exit code **3**, verdict withholds, no fabricated answer |
| 4.2 | Edit one line of a demo ledger, then verify it | Non-zero exit, `"valid": false` |
| 4.3 | Start the HTTP server without a token store | Refuses to start, exit **4**, code `NO_API_TOKENS` |
| 4.4 | Run the probe harness | `15 probes: 15 OK, 0 VULNERABLE` |

Then pick **two** controls of your own choosing (for example: replay an approval,
reuse a capability token, write past the size cap, run `run_python`, feed the API
a 100 KB body) and try to break them. Report what you tried and what happened.

## Step 5 — verdict

Publish exactly one of:

- **ACCEPTED** — steps 2–4 all pass, tree was clean, and you found no
  documentation claim that the code does not support.
- **REJECTED** — any check fails, or any claim overstates what the code does.
- **PROVISIONAL** — the run was valid but not acceptance-grade (dirty tree,
  different commit, missing artefact). Say why.

### Decision rules

A commit is acceptable only if **all** of these hold:

1. The harness prints `ACCEPTED — 9 checks passed` and exits 0.
2. `dirty=False` in the JSON report, and it matches `git status`.
3. The commit hash in the report equals the commit you checked out.
4. Your own step-4 checks agree with the harness.
5. **No overclaiming.** If the docs promise something the code cannot show, the
   verdict is REJECTED, regardless of the test results.

## Step 6 — what to publish

- `acceptance-report.md` and `acceptance-report.json` **unmodified**.
- The mutation-check output.
- Commit hash, Python version, OS, timestamp.
- Your name/model and a statement that you did **not** read the implementing
  agent's transcript.
- A short list of what you tried to break and what happened.
- Every discrepancy between documentation and observed behaviour, including
  minor wording problems.

A review that says "looks good" without these artefacts is not acceptance.

## Things the project says it does **not** have

Do not mark these as failures — they are declared limits. If you find the
documentation claiming any of them, that *is* a failure.

- Production security certification, penetration test, or cryptographic review.
- OS-level isolation for `run_python` without a container runtime.
- TLS in-process, multi-host deployment, load or chaos testing.
- A real data-ingestion pipeline; the catalog is a demo fixture.
- Any guarantee against a compromised host or a malicious authorised approver.

## If something fails

Do not fix it. Record the check, the raw output and the commit, and hand the
report back. A new commit requires a **new** clean-room run.
