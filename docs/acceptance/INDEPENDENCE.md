# Independence protocol

WhyWard's premise is that a system must not certify itself. The same rule applies
to this repository: the agent that wrote the code cannot be the one that declares
it acceptable. This document defines what "independent" means here, exactly what
the reviewer must run, and what evidence makes a verdict valid.

## 1. Who counts as independent

| Reviewer | Independent? | Why |
| --- | --- | --- |
| The implementing agent, in the same session | **No** | Same context, same blind spots, knowledge of what was intended |
| Same model, fresh session, repo URL only | **Conditional** | Acceptable if the transcript is not shared and the run starts from a clean clone |
| A different model / vendor with no transcript | **Yes** | Preferred |
| A human who did not write the change, with shell access | **Yes** | Preferred |
| CI on the merge commit | **No** | It runs whatever the author configured, and can be shaped by the author |

Independence is about *information*, not identity: the reviewer must not be told
what was changed, what fails, or what the expected numbers are. Hand them the
repository and this protocol, nothing else.

## 2. What the reviewer does

```bash
# 1. Clean room: a fresh clone at a pinned commit, nothing reused from the author
git clone https://github.com/checken1994/WhyWard
cd WhyWard
git checkout <commit-to-accept>          # the exact commit under review

# 2. Confirm the tree is clean; the harness refuses dirty trees by default
git status --porcelain

# 3. Run the acceptance harness (includes the mutation check)
python3 docs/acceptance/acceptance_runner.py \
  --report acceptance-report.md \
  --json acceptance-report.json

# 4. Independently re-derive the decision (do not trust the harness blindly)
cat acceptance-report.md
PYTHONPATH=src python3 docs/audit/reproduce_findings.py
PYTHONPATH=src python3 -m unittest discover -s tests -t tests
```

Requirements: Python ≥ 3.11, no network, no third-party packages. Total runtime
is about 20 seconds on a laptop-class machine.

## 3. Decision rule

Accept the commit **only if all of the following hold**:

1. The harness prints `ACCEPTED — 9 checks passed` and exits 0 (which includes
   the mutation check: every single-control removal must be detected).
2. The working tree was clean at run time (`dirty=False` in the JSON report).
3. The commit hash in the report equals the commit under review.
4. The reviewer's own spot checks agree — at minimum:
   - `whyward ask` with an unanswerable question exits **3**, not 0;
   - editing a ledger line makes `verify-ledger` exit non-zero;
   - `serve` without a token store refuses to start;
   - the probe harness reports `15 probes: 15 OK, 0 VULNERABLE`.
5. No claim in `README.md` / `SECURITY.md` was found to be unsupported by running
   code. If a claim is found that cannot be demonstrated, the verdict is
   **REJECTED (overclaim)**, regardless of test results.

A pass on a dirty tree, on a different commit, or with modified test files is
**PROVISIONAL** and must not be recorded as acceptance.

## 4. What the reviewer must publish

- The markdown report produced by the harness (unmodified).
- The JSON report (machine-readable evidence).
- The commit hash, python version, OS and run timestamp.
- The reviewer's model name / human identity and the fact that no transcript from
  the implementing agent was consulted.
- Any discrepancy between the documentation and observed behaviour, even if the
  harness passed.

Reviews that only say "looks good" without the artefacts above are not
acceptance. The point of this repository is that assertions are cheap and
evidence is not.

## 5. If a check fails

Do not fix the code as part of the acceptance review. Instead:

1. record the failing check, the raw output, and the commit;
2. open an issue with the reproduction;
3. the implementer fixes it, publishes a new commit, and a **new** clean-room run
   is performed (a re-run on the same commit after an ad-hoc fix is invalid).

## 6. Known limits of this protocol

- The harness and the tests were written by the same agent that wrote the code;
  they can share blind spots. That is why the reviewer is asked to re-derive the
  spot checks in step 4 independently, and why `docs/audit/reproduce_findings.py`
  is written as an adversary rather than as a feature test.
- Coverage and lint thresholds are quality signals, not security evidence.
- The container backend is not exercised in CI (no runtime available); a reviewer
  with Docker/Podman should additionally run the `run_python` path and report it
  as a separate, explicitly-scoped result.
- Nothing here evaluates the *quality* of the policy itself (thresholds, TTLs,
  which tools are permitted). That is a governance decision, reviewed separately.

## 7. Copy-paste brief for the independent reviewer

> You are the independent acceptor for the WhyWard repository. You did not write
> this code and no transcript from its author has been shared with you.
> Clone https://github.com/checken1994/WhyWard at commit `<commit>`, keep the tree
> clean, and follow `docs/acceptance/INDEPENDENCE.md` exactly. Run
> `python3 docs/acceptance/acceptance_runner.py --report acceptance-report.md
> --json acceptance-report.json`, then verify the five decision rules yourself
> with your own commands. Publish the verdict (ACCEPTED / REJECTED /
> PROVISIONAL), the artefacts, and every place where the documentation claims
> more than the code demonstrates. Do not modify any file in the repository.
