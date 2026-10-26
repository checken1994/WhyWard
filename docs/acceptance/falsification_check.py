#!/usr/bin/env python3
"""Falsification check: do the tests and probes actually have teeth?

A green test suite means nothing if it stays green when the security property is
removed. This script copies the repository into a scratch directory, applies a
small "mutation" that disables exactly one control, and re-runs the black-box
probe harness. A mutation that goes **undetected** is a coverage hole in the
evidence, and is reported as such.

Usage
    python3 docs/acceptance/falsification_check.py
    python3 docs/acceptance/falsification_check.py --json /tmp/mutations.json --only M-03

Exit code 0 only when every mutation is detected. Mutations are applied to a
throwaway copy; the working tree is never modified.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Mutation:
    mutation_id: str
    control: str
    file: str
    old: str
    new: str
    probe: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        "M-01",
        "approval binding",
        "src/whyward/control.py",
        '        if decision.proposal_digest != proposal.digest():\n            problems.append(',
        '        if False:\n            problems.append(',
        "W-01",
    ),
    Mutation(
        "M-02",
        "caller evidence downgrade",
        "src/whyward/control.py",
        '        data["review_status"] = "unverified"',
        '        data.setdefault("review_status", "unverified")',
        "W-02",
    ),
    Mutation(
        "M-03",
        "freshness enforcement",
        "src/whyward/evidence.py",
        '        freshness = self._freshness_of(record, now)',
        '        freshness = self._freshness_of(record, now)\n        reject_stale = False', 
        "W-03",
    ),
    Mutation(
        "M-04",
        "manifest checksum",
        "src/whyward/evidence.py",
        "            elif actual != expected:",
        "            elif False:", 
        "W-04",
    ),
    Mutation(
        "M-05",
        "independent lineage minimum",
        "src/whyward/review.py",
        "    if proposal.claims and actual < required:",
        "    if False and proposal.claims and actual < required:", 
        "W-05",
    ),
    Mutation(
        "M-06",
        "single-use capability",
        "src/whyward/capability.py",
        "        if not self._store.claim(",
        "        if False and not self._store.claim(",
        "W-07",
    ),
    Mutation(
        "M-07",
        "kill switch enforcement",
        "src/whyward/control.py",
        "    def kill_switch_engaged(self) -> bool:\n        if self._engaged:\n            return True",
        "    def kill_switch_engaged(self) -> bool:\n        if False:\n            return True",
        "W-08",
    ),
    Mutation(
        "M-08",
        "production rejects demo evidence",
        "src/whyward/policy.py",
        '    accepted_review_statuses: frozenset[str] = frozenset({"verified"})',
        '    accepted_review_statuses: frozenset[str] = frozenset({"verified", "demo_verified"})',
        "W-11",
    ),
    Mutation(
        "M-09",
        "write size limit",
        "src/whyward/execution.py",
        "        if len(data) > self.limits.max_write_bytes:",
        "        if False:",
        "W-13",
    ),
    Mutation(
        "M-10",
        "run_python disabled by default",
        "src/whyward/execution.py",
        '            raise CapabilityError(\n                "run_python is disabled for this executor; enable it only inside an isolated deployment",\n                code="PYTHON_EXECUTION_DISABLED",\n            )',
        '            return self._run_python(action, path)',
        "W-14",
    ),
)


def run_probe(scratch: Path, probe_id: str) -> tuple[bool, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(scratch / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(scratch / "docs" / "audit" / "reproduce_findings.py"), "--only", probe_id],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(scratch),
        timeout=300,
        check=False,
    )
    detected = result.returncode != 0 or "VULNERABLE" in result.stdout
    return detected, (result.stdout + result.stderr).strip()


def realise(mutation: Mutation) -> Path:
    scratch = Path(tempfile.mkdtemp(prefix=f"whyward-mutation-{mutation.mutation_id}-"))
    for name in ("src", "docs", "examples"):
        shutil.copytree(ROOT / name, scratch / name, ignore=shutil.ignore_patterns("__pycache__"))
    target = scratch / mutation.file
    text = target.read_text(encoding="utf-8")
    if mutation.old not in text:
        raise RuntimeError(
            f"{mutation.mutation_id}: pattern not found in {mutation.file}; the mutation is stale "
            "(that itself is a finding: the control moved)"
        )
    target.write_text(text.replace(mutation.old, mutation.new, 1), encoding="utf-8")
    return scratch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mutation check for WhyWard's evidence")
    parser.add_argument("--only", default="", help="comma-separated mutation ids")
    parser.add_argument("--json", default="", help="write results as JSON to this path")
    args = parser.parse_args(argv)

    selected = [item.strip() for item in args.only.split(",") if item.strip()]
    mutations = [m for m in MUTATIONS if not selected or m.mutation_id in selected]
    if selected and len(mutations) != len(selected):
        known = {m.mutation_id for m in MUTATIONS}
        missing = sorted(set(selected) - known)
        print(f"unknown mutation ids: {missing}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    undetected: list[str] = []
    for mutation in mutations:
        started = time.time()
        print(f"[RUN ] {mutation.mutation_id} disabling {mutation.control} → probe {mutation.probe}")
        try:
            scratch = realise(mutation)
        except RuntimeError as exc:
            print(f"[WARN] {exc}")
            results.append(
                {
                    "id": mutation.mutation_id,
                    "control": mutation.control,
                    "probe": mutation.probe,
                    "detected": False,
                    "note": str(exc),
                }
            )
            undetected.append(mutation.mutation_id)
            continue
        try:
            detected, output = run_probe(scratch, mutation.probe)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        state = "DETECTED" if detected else "UNDETECTED"
        print(f"[{state:<10}] {mutation.mutation_id} {mutation.control} ({time.time() - started:.1f}s)")
        if not detected:
            undetected.append(mutation.mutation_id)
            print("             the probe stayed green after the control was removed:")
            print("             " + output.replace("\n", "\n             ")[:800])
        results.append(
            {
                "id": mutation.mutation_id,
                "control": mutation.control,
                "probe": mutation.probe,
                "detected": detected,
                "duration_seconds": round(time.time() - started, 2),
            }
        )

    if args.json:
        Path(args.json).write_text(
            json.dumps({"mutations": results, "undetected": undetected}, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.json}")

    print("-" * 70)
    print(f"{len(results)} mutations: {len(results) - len(undetected)} detected, {len(undetected)} undetected")
    if undetected:
        print("evidence holes: " + ", ".join(undetected))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
