"""
Data-driven recall corpus tests.

Parametrized strictly over locally defined target manifests in targets_local/.
When no manifests exist (e.g. in CI or on a clean clone), all tests skip cleanly.
"""

from __future__ import annotations

import pytest

from tests.corpus.harness import (
    assert_detects,
    load_local_targets,
    requires_target,
    run_fuzz,
    run_scan,
)

TARGETS = load_local_targets()

if not TARGETS:
    pytestmark = pytest.mark.skip(
        reason="No local corpus targets found in tests/corpus/targets_local/"
    )

    def test_corpus_skipped():
        """Clean skip when no local targets exist."""
        pass

else:

    @pytest.mark.parametrize(
        "target",
        TARGETS,
        ids=[t.get("ref", f"target-{i}") for i, t in enumerate(TARGETS)],
    )
    def test_corpus_target(target: dict):
        ref = target.get("ref", "unknown-target")
        launch_cmd = target.get("launch")
        assert launch_cmd, f"[{ref}] Target manifest missing required 'launch' command"

        requires_target(launch_cmd)

        expectations = target.get("expect", [])
        scan_expects = [e for e in expectations if "scanner" in e]
        fuzz_expects = [
            e for e in expectations if e.get("kind") == "fuzz-crash" or "path" in e
        ]

        failures: list[str] = []

        # 1. Run scanner assertions
        if scan_expects:
            requested_scanners = list({e["scanner"] for e in scan_expects})
            findings = run_scan(target=launch_cmd, scanners=requested_scanners)

            for exp in scan_expects:
                try:
                    assert_detects(
                        findings=findings,
                        scanner=exp["scanner"],
                        tool=exp.get("tool", ""),
                        attack_type=exp.get("attack_type"),
                        min_confidence=exp.get("confidence", "suspected"),
                    )
                except AssertionError as err:
                    failures.append(f"[{ref}] Scanner expectation missed: {err}")

        # 2. Run fuzz assertions
        if fuzz_expects:
            fuzz_report = run_fuzz(target=launch_cmd)

            for exp in fuzz_expects:
                expected_real = exp.get("real", True)
                expected_path = exp.get("path")

                matching = [
                    c
                    for c in fuzz_report.crashes
                    if (not expected_real or c.real)
                    and (
                        not expected_path
                        or expected_path in c.generator
                        or expected_path in c.case_name
                        or expected_path in c.error_message
                    )
                ]

                if not matching:
                    failures.append(
                        f"[{ref}] Expected fuzz crash with real={expected_real}, "
                        f"path={expected_path} not found. "
                        f"Total crashes: {len(fuzz_report.crashes)} "
                        f"(real: {len(fuzz_report.real_crashes)})"
                    )

        if failures:
            raise AssertionError("\n".join(failures))
