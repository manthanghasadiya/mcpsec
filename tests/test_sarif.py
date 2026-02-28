"""Tests for SARIF 2.1.0 report generation."""
import json
import tempfile
import os
import pytest

from mcpsec.models import Finding, Severity, ScanResult, TransportType


# ─── Helper ──────────────────────────────────────────────────────────────────

def _make_finding(**kwargs) -> Finding:
    defaults = dict(severity=Severity.HIGH, scanner="command-injection", title="Test Finding")
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_scan_result(findings=None, **kwargs) -> ScanResult:
    defaults = dict(target="python my_server.py", scanners_run=["command-injection"])
    defaults.update(kwargs)
    sr = ScanResult(**defaults)
    if findings:
        sr.findings = findings
    return sr


# ─── SARIF structure tests ───────────────────────────────────────────────────

def test_sarif_top_level_structure():
    """SARIF report must have $schema, version, and runs."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    sr = _make_scan_result(findings=[_make_finding()])
    sarif = generate_sarif_report(sr)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert "sarif-schema-2.1.0" in sarif["$schema"]
    assert len(sarif["runs"]) == 1


def test_sarif_tool_driver():
    """Tool driver must include name, version, and rules."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    sr = _make_scan_result(findings=[_make_finding()])
    sarif = generate_sarif_report(sr)
    driver = sarif["runs"][0]["tool"]["driver"]

    assert driver["name"] == "mcpsec"
    assert driver["version"]  # non-empty
    assert isinstance(driver["rules"], list)
    assert len(driver["rules"]) >= 1


def test_sarif_results_count_matches_findings():
    """One SARIF result per finding."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    findings = [
        _make_finding(title="Finding A", scanner="command-injection"),
        _make_finding(title="Finding B", scanner="sql-injection"),
        _make_finding(title="Finding C", scanner="command-injection"),
    ]
    sr = _make_scan_result(findings=findings)
    sarif = generate_sarif_report(sr)
    results = sarif["runs"][0]["results"]

    assert len(results) == 3


def test_sarif_empty_findings():
    """SARIF with no findings should have empty rules and results."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    sr = _make_scan_result(findings=[])
    sarif = generate_sarif_report(sr)

    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
    assert sarif["runs"][0]["results"] == []


# ─── Rule ID tests ──────────────────────────────────────────────────────────

def test_rule_id_stable():
    """Same scanner type should produce the same rule ID."""
    from mcpsec.reporters.sarif_report import generate_rule_id

    f1 = _make_finding(scanner="command-injection", title="A")
    f2 = _make_finding(scanner="command-injection", title="B")

    assert generate_rule_id(f1) == generate_rule_id(f2)
    assert generate_rule_id(f1) == "MCPSEC-COMMAND_INJECTION"


def test_rule_id_unique_per_scanner():
    """Different scanners should produce different rule IDs."""
    from mcpsec.reporters.sarif_report import generate_rule_id

    f1 = _make_finding(scanner="command-injection")
    f2 = _make_finding(scanner="sql-injection")

    assert generate_rule_id(f1) != generate_rule_id(f2)


def test_rules_deduplicated():
    """Multiple findings with same scanner should produce one rule."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    findings = [
        _make_finding(scanner="sqli", title="A"),
        _make_finding(scanner="sqli", title="B"),
    ]
    sarif = generate_sarif_report(_make_scan_result(findings=findings))
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1


# ─── Fingerprint tests ──────────────────────────────────────────────────────

def test_fingerprint_deterministic():
    """Same finding inputs should produce same fingerprint."""
    from mcpsec.reporters.sarif_report import generate_finding_fingerprint

    f1 = _make_finding(scanner="sqli", tool_name="query", parameter="sql", title="SQL Injection")
    f2 = _make_finding(scanner="sqli", tool_name="query", parameter="sql", title="SQL Injection")

    assert generate_finding_fingerprint(f1) == generate_finding_fingerprint(f2)


def test_fingerprint_different_for_different_findings():
    """Different findings should produce different fingerprints."""
    from mcpsec.reporters.sarif_report import generate_finding_fingerprint

    f1 = _make_finding(scanner="sqli", tool_name="query", title="SQL Injection")
    f2 = _make_finding(scanner="xss", tool_name="render", title="Cross-Site Scripting")

    assert generate_finding_fingerprint(f1) != generate_finding_fingerprint(f2)


# ─── Severity mapping tests ─────────────────────────────────────────────────

def test_severity_to_sarif_level():
    """Severity levels should map to correct SARIF levels."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    findings = [
        _make_finding(severity=Severity.CRITICAL, scanner="a", title="Critical"),
        _make_finding(severity=Severity.HIGH, scanner="b", title="High"),
        _make_finding(severity=Severity.MEDIUM, scanner="c", title="Medium"),
        _make_finding(severity=Severity.LOW, scanner="d", title="Low"),
        _make_finding(severity=Severity.INFO, scanner="e", title="Info"),
    ]
    sarif = generate_sarif_report(_make_scan_result(findings=findings))
    results = sarif["runs"][0]["results"]

    assert results[0]["level"] == "error"    # CRITICAL
    assert results[1]["level"] == "error"    # HIGH
    assert results[2]["level"] == "warning"  # MEDIUM
    assert results[3]["level"] == "note"     # LOW
    assert results[4]["level"] == "note"     # INFO


def test_security_severity_scores():
    """Rules should have security-severity property for GitHub."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    sr = _make_scan_result(findings=[_make_finding(severity=Severity.CRITICAL)])
    sarif = generate_sarif_report(sr)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    score = float(rule["properties"]["security-severity"])
    assert score == 9.5


# ─── Location tests ─────────────────────────────────────────────────────────

def test_static_finding_has_physical_location():
    """Static analysis findings should have file-based physical location."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    f = _make_finding(file_path="src/server.py", line_number=42)
    sarif = generate_sarif_report(_make_scan_result(findings=[f]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]

    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "src/server.py"
    assert loc["physicalLocation"]["region"]["startLine"] == 42


def test_runtime_finding_has_mcp_location():
    """Runtime findings should have MCP tool-based logical location."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    f = _make_finding(tool_name="run_command", parameter="cmd")
    sarif = generate_sarif_report(_make_scan_result(findings=[f]))
    loc = sarif["runs"][0]["results"][0]["locations"][0]

    assert "mcp://tool/run_command" in loc["physicalLocation"]["artifactLocation"]["uri"]
    assert loc["logicalLocations"][0]["name"] == "run_command"


# ─── Code flow tests ────────────────────────────────────────────────────────

def test_taint_finding_has_code_flow():
    """Findings with code snippets should have codeFlows."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    f = _make_finding(
        file_path="src/handler.py",
        line_number=10,
        code_snippet="user_input = request.params['query']",
    )
    sarif = generate_sarif_report(_make_scan_result(findings=[f]))
    result = sarif["runs"][0]["results"][0]

    assert "codeFlows" in result
    assert len(result["codeFlows"]) == 1


def test_taint_metadata():
    """Findings with taint info should include taintFlow in properties."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    f = _make_finding(
        taint_source="request.params",
        taint_sink="subprocess.run",
        taint_flow="request.params → handler → subprocess.run",
    )
    sarif = generate_sarif_report(_make_scan_result(findings=[f]))
    props = sarif["runs"][0]["results"][0]["properties"]

    assert props["taintFlow"]["source"] == "request.params"
    assert props["taintFlow"]["sink"] == "subprocess.run"


# ─── CWE mapping tests ──────────────────────────────────────────────────────

def test_cwe_mapping():
    """Known scanners should get correct CWE relationships."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    f = _make_finding(scanner="command-injection")
    sarif = generate_sarif_report(_make_scan_result(findings=[f]))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["relationships"][0]["target"]["id"] == "CWE-78"


# ─── File save tests ────────────────────────────────────────────────────────

def test_save_sarif_report():
    """save_sarif_report should write valid JSON to disk."""
    from mcpsec.reporters.sarif_report import save_sarif_report

    sr = _make_scan_result(findings=[_make_finding()])

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        tmp = f.name

    try:
        assert save_sarif_report(sr, tmp) is True

        with open(tmp, "r") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
    finally:
        os.unlink(tmp)


# ─── Fuzz SARIF tests ───────────────────────────────────────────────────────

def test_fuzz_sarif_structure():
    """Fuzz SARIF should have correct top-level structure."""
    from mcpsec.reporters.sarif_report import generate_sarif_from_fuzz

    summary = {
        "total_tests": 100,
        "crashes": 2,
        "timeouts": 1,
        "interesting": 3,
        "interesting_cases": [
            {"case_name": "test_crash", "description": "Buffer overflow", "crashed": True, "timeout": False, "generator": "core", "error": "segfault"},
            {"case_name": "test_timeout", "description": "Infinite loop", "crashed": False, "timeout": True, "generator": "core", "error": ""},
            {"case_name": "test_anomaly", "description": "Unexpected 500", "crashed": False, "timeout": False, "generator": "core", "error": "500"},
        ],
    }
    sarif = generate_sarif_from_fuzz(summary, "python server.py")

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 3
    assert sarif["runs"][0]["results"][0]["level"] == "error"
    assert sarif["runs"][0]["results"][1]["level"] == "warning"
    assert sarif["runs"][0]["results"][2]["level"] == "note"


def test_fuzz_sarif_empty():
    """Fuzz SARIF with no issues should have empty results."""
    from mcpsec.reporters.sarif_report import generate_sarif_from_fuzz

    summary = {"total_tests": 50, "crashes": 0, "timeouts": 0, "interesting": 0, "interesting_cases": []}
    sarif = generate_sarif_from_fuzz(summary, "server")

    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_save_fuzz_sarif():
    """save_sarif_from_fuzz should write valid JSON to disk."""
    from mcpsec.reporters.sarif_report import save_sarif_from_fuzz

    summary = {"total_tests": 10, "crashes": 1, "timeouts": 0, "interesting": 1, "interesting_cases": [
        {"case_name": "crash1", "description": "crash", "crashed": True, "timeout": False, "generator": "g", "error": "err"}
    ]}

    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        tmp = f.name

    try:
        assert save_sarif_from_fuzz(summary, "server", tmp) is True

        with open(tmp, "r") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"
    finally:
        os.unlink(tmp)


# ─── Invocation metadata tests ──────────────────────────────────────────────

def test_invocation_metadata():
    """SARIF invocation should include timing and command line."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    sr = _make_scan_result(findings=[_make_finding()])
    sr.mark_complete()
    sarif = generate_sarif_report(sr)
    inv = sarif["runs"][0]["invocations"][0]

    assert inv["executionSuccessful"] is True
    assert "startTimeUtc" in inv
    assert "endTimeUtc" in inv
    assert "mcpsec" in inv["commandLine"]


def test_invocation_with_errors():
    """SARIF invocation should report execution failure if errors exist."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    sr = _make_scan_result(findings=[], errors=["Connection timed out"])
    sarif = generate_sarif_report(sr)
    inv = sarif["runs"][0]["invocations"][0]

    assert inv["executionSuccessful"] is False
    assert len(inv["toolExecutionNotifications"]) == 1


# ─── Summary properties test ────────────────────────────────────────────────

def test_run_properties_summary():
    """SARIF run properties should include finding summary counts."""
    from mcpsec.reporters.sarif_report import generate_sarif_report

    findings = [
        _make_finding(severity=Severity.CRITICAL, scanner="a", title="C"),
        _make_finding(severity=Severity.HIGH, scanner="b", title="H"),
        _make_finding(severity=Severity.MEDIUM, scanner="c", title="M"),
    ]
    sr = _make_scan_result(findings=findings)
    sarif = generate_sarif_report(sr)
    summary = sarif["runs"][0]["properties"]["summary"]

    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["total"] == 3
