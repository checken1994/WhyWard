## What changed

<!-- One paragraph. Link the finding/issue it addresses. -->

## Evidence

- [ ] `PYTHONPATH=src python -m unittest discover -s tests -t tests` passes
- [ ] `ruff check src tests` and `mypy` are clean
- [ ] `coverage report` is at or above the gate
- [ ] `PYTHONPATH=src python docs/audit/reproduce_findings.py` reports 15/15 OK
- [ ] `python docs/acceptance/falsification_check.py` detects every mutation

## Claims

<!-- What does this PR assert that is now true? Each claim needs a test. -->

## Not claimed

<!-- What does this PR deliberately NOT do? Honesty here is a feature. -->

## Acceptance

Security-relevant changes require a clean-room run by someone who did not write
them: `docs/acceptance/REVIEW_BRIEF.md`. A green CI run on the author's own branch
is not acceptance.
