# Audit artefacts

| File | What it is |
| --- | --- |
| `2026-10-26-danh-gia-he-thong.md` | The original Vietnamese assessment of WhyWard 0.1.0: rubric, 15 findings, scorecard and roadmap. Kept unchanged as the historical record; a status banner at the top links to the implementation report. |
| `2026-10-26-bao-cao-trien-khai.md` | Vietnamese implementation report for 0.2.0: what was built for each finding, the evidence, the honest limits, and the re-scored rubric. |
| `reproduce_findings.py` | The 15 adversarial probes (W-01 … W-15). Each probe performs the unsafe action the finding described and prints `OK` only if the system refuses or degrades correctly. |

## Running the probes

```bash
PYTHONPATH=src python3 docs/audit/reproduce_findings.py            # all 15
PYTHONPATH=src python3 docs/audit/reproduce_findings.py --only W-14 # one
PYTHONPATH=src python3 docs/audit/reproduce_findings.py --json /tmp/probes.json
```

Exit code 0 means no probe reported `VULNERABLE`. A probe that crashes is
reported as `VULNERABLE`, never silently skipped.

## Probe → regression test map

Every probe has a corresponding negative test in the normal suite, so a
regression is caught even if nobody runs the probes:

| Probe | Regression test |
| --- | --- |
| W-01 approval replay | `tests/test_boundaries.py::DecisionBindingTests` |
| W-02 self-declared evidence | `tests/test_boundaries.py::EvidenceTrustTests` |
| W-03 freshness | `tests/test_boundaries.py::EvidenceTrustTests::test_expired_evidence_is_withheld` |
| W-04 manifest integrity | `tests/test_boundaries.py::CatalogIntegrityTests` |
| W-05 lineage minimum | `tests/test_boundaries.py::ReviewGateTests` |
| W-06 concurrent ledger | `tests/test_boundaries.py::LedgerTests::test_concurrent_appends_keep_chain_valid` |
| W-07 capability restart | `tests/test_boundaries.py::CapabilityTests` |
| W-08 kill switch | `tests/test_api.py`, `tests/test_edge_cases.py::BoundaryHardeningTests` |
| W-09 verify-ledger traceback | `tests/test_cli_inprocess.py` |
| W-10 withheld exit code | `tests/test_cli_e2e.py::WithheldExitCodeTests` |
| W-11 demo_verified in production | `tests/test_boundaries.py::ReviewGateTests` |
| W-12 unauthenticated API | `tests/test_api.py::AuthenticationTests` |
| W-13 unbounded read/write | `tests/test_boundaries.py::ExecutionLimitsTests` |
| W-14 run_python on the host | `tests/test_boundaries.py::ExecutionLimitsTests` |
| W-15 raw ValueError | `tests/test_edge_cases.py::BoundaryHardeningTests` |

## Ground rules for adding a probe

1. It must be **reproducible**: no network, no wall-clock dependence, temporary
   directories only.
2. It must be **adversarial**: attempt the unsafe action, do not assert that a
   function exists.
3. It must be **honest**: a crash or an unexpected error is a finding, not a skip.
4. It must come with a regression test in `tests/` in the same commit.
