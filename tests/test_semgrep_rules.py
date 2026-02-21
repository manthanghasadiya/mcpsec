"""Tests for Semgrep rule validity."""
import subprocess
import shutil
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
    """All Semgrep rules should pass semgrep --validate."""
    result = subprocess.run(
        ["semgrep", "--validate", "--config", str(RULES_DIR)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, f"Semgrep validation failed:\n{result.stderr}"
