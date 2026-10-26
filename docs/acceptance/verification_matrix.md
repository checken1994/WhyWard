# Verification matrix

How each claim in `README.md`, `SECURITY.md` and `ARCHITECTURE.md` is verified.
"Claim" means an assertion a reader could act on; if a row is missing, the claim
is not verified and should be treated as a design intention.

| Capability | Claim source | Evidence | Command |
| --- | --- | --- | --- |
| Approvals bound to proposal/task/package | SECURITY W-01 | `test_boundaries.DecisionBindingTests`, probe W-01 | `python docs/audit/reproduce_findings.py --only W-01` |
| Caller cannot self-certify evidence | SECURITY W-02 | `test_boundaries.EvidenceTrustTests`, probe W-02 | `--only W-02` |
| Freshness enforced | SECURITY W-03 | `test_boundaries.EvidenceTrustTests`, probe W-03 | `--only W-03` |
| Manifest checksum + record count | SECURITY W-04 | `test_boundaries.CatalogIntegrityTests`, probe W-04 | `--only W-04` |
| Independent lineage minimum | SECURITY W-05 | `test_boundaries.ReviewGateTests`, probe W-05 | `--only W-05` |
| Ledger survives concurrent writers | SECURITY W-06 | `test_boundaries.LedgerTests`, probe W-06 | `--only W-06` |
| Capabilities are single-use across restarts | SECURITY W-07 | `test_boundaries.CapabilityTests`, probe W-07 | `--only W-07` |
| Kill switch revokes and blocks | SECURITY W-08 | `test_api`, probe W-08, acceptance A-07 | `--only W-08` |
| CLI fails with typed errors and stable exit codes | README exit table | `test_cli_e2e`, `test_cli_inprocess`, probe W-09/W-10 | `python -m unittest test_cli_e2e` |
| Production rejects demo evidence | SECURITY W-11 | `test_boundaries.ReviewGateTests`, probe W-11 | `--only W-11` |
| API requires authentication | SECURITY W-12 | `test_api.AuthenticationTests`, probe W-12, acceptance A-07 | `--only W-12` |
| Execution is bounded | SECURITY W-13 | `test_boundaries.ExecutionLimitsTests`, probe W-13 | `--only W-13` |
| `run_python` is off and human-gated | SECURITY W-14 | `test_boundaries.ExecutionLimitsTests`, probe W-14 | `--only W-14` |
| Malformed input raises typed errors | SECURITY W-15 | `test_edge_cases.BoundaryHardeningTests`, probe W-15 | `--only W-15` |
| No third-party runtime dependency | README install | acceptance A-02 | `python docs/acceptance/acceptance_runner.py` |
| Tampering is detectable | SECURITY limits | acceptance A-06 | same |
| Documentation does not overclaim | INDEPENDENCE rule 5 | acceptance A-08 + reviewer spot checks | same |

## Claims intentionally *not* made

- "Production-ready", "secure", "certified", "unbypassable".
- OS-level isolation without a container runtime.
- Correctness or freshness of the demo catalog content.
- Any guarantee against a compromised host or a malicious authorised approver.
