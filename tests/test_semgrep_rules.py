"""Tests for Semgrep rule validity."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

RULES_DIR = Path(__file__).parent.parent / "mcpsec" / "rules"


def test_rules_directory_exists():
    """Rules directory should exist and contain ≥5 .yml files."""
    assert RULES_DIR.exists(), f"Rules directory not found: {RULES_DIR}"
    yml_files = list(RULES_DIR.glob("*.yml"))
    assert len(yml_files) >= 5, f"Only {len(yml_files)} rules found"


def test_rules_are_valid_yaml():
    """All rule files should be parseable as YAML."""
    import yaml  # stdlib-compatible via PyYAML

    for rule_file in RULES_DIR.glob("*.yml"):
        with open(rule_file, encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
                assert data is not None, f"Empty rule: {rule_file.name}"
                assert "rules" in data, f"Missing 'rules' key in {rule_file.name}"
            except yaml.YAMLError as e:
                pytest.fail(f"Invalid YAML in {rule_file.name}: {e}")


@pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="Semgrep not installed",
)
def test_semgrep_rules_validate():
    """Rules should pass `semgrep --validate`; skip when the registry is unreachable."""
    result = subprocess.run(
        ["semgrep", "--validate", "--config", str(RULES_DIR), "--metrics=off"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"},
    )
    if result.returncode != 0:
        blob = (result.stderr + result.stdout).lower()
        net_markers = (
            "tunnel connection failed",
            "proxyerror",
            "max retries",
            "failed to establish a new connection",
            "temporary failure in name resolution",
            "connection refused",
            "semgrep.dev",
            "network error",
        )
        if any(m in blob for m in net_markers):
            pytest.skip(
                f"semgrep registry unreachable (offline/allowlisted env): {result.stderr[:200]}"
            )
    assert result.returncode == 0, f"Semgrep validation failed:\n{result.stderr}"
