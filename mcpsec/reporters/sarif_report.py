"""
SARIF Reporter — generates SARIF 2.1.0 reports for CI/CD integration.

Supports:
- GitHub Code Scanning
- GitLab SAST
- Azure DevOps
- Any SARIF-compatible tool

SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from mcpsec import __version__ as MCPSEC_VERSION
from mcpsec.models import ScanResult, Finding, Severity

# CWE mappings for each scanner type
SCANNER_CWE_MAP = {
    "command-injection": "CWE-78",
    "sql-injection": "CWE-89",
    "sql-rce": "CWE-89",
    "path-traversal": "CWE-22",
    "ssrf": "CWE-918",
    "prompt-injection": "CWE-94",
    "description-injection": "CWE-94",
    "description-prompt-injection": "CWE-94",
    "secrets-exposure": "CWE-200",
    "auth-audit": "CWE-306",
    "capability-escalation": "CWE-269",
    "annotation-integrity": "CWE-345",
    "resource-ssrf": "CWE-918",
}

# Severity to SARIF level mapping
SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Severity to SARIF security-severity score (for GitHub)
SEVERITY_TO_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}

# CWE taxonomy entries
CWE_TAXA = [
    {"id": "CWE-22", "name": "Path Traversal"},
    {"id": "CWE-78", "name": "OS Command Injection"},
    {"id": "CWE-89", "name": "SQL Injection"},
    {"id": "CWE-94", "name": "Code Injection"},
    {"id": "CWE-200", "name": "Information Exposure"},
    {"id": "CWE-269", "name": "Improper Privilege Management"},
    {"id": "CWE-306", "name": "Missing Authentication"},
    {"id": "CWE-345", "name": "Insufficient Verification"},
    {"id": "CWE-918", "name": "Server-Side Request Forgery"},
    {"id": "CWE-1035", "name": "Security Weakness"},
]


def generate_rule_id(finding: Finding) -> str:
    """Generate a unique, stable rule ID for a finding."""
    scanner = finding.scanner.replace("-", "_").upper()
    return f"MCPSEC-{scanner}"


def generate_finding_fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for deduplication."""
    key = f"{finding.scanner}:{finding.tool_name}:{finding.parameter}:{finding.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _build_rule(finding: Finding) -> dict:
    """Build a SARIF rule definition from a finding."""
    rule_id = generate_rule_id(finding)
    cwe = finding.cwe or SCANNER_CWE_MAP.get(finding.scanner, "CWE-1035")

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": finding.scanner.replace("-", " ").title(),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "helpUri": f"https://github.com/manthanghasadiya/mcpsec/wiki/{finding.scanner}",
        "help": {
            "text": finding.remediation or f"Review the {finding.scanner} finding and apply appropriate fixes.",
            "markdown": (
                f"## {finding.title}\n\n"
                f"{finding.description or ''}\n\n"
                f"### Remediation\n\n"
                f"{finding.remediation or 'Review and fix the identified vulnerability.'}"
            ),
        },
        "properties": {
            "tags": ["security", "mcp", finding.scanner],
            "security-severity": str(SEVERITY_TO_SCORE.get(finding.severity, 5.0)),
            "precision": "high" if finding.confidence == "high" else "medium",
        },
        "defaultConfiguration": {
            "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
        },
    }

    if cwe:
        rule["relationships"] = [
            {
                "target": {
                    "id": cwe,
                    "toolComponent": {"name": "CWE"},
                },
                "kinds": ["superset"],
            }
        ]

    return rule


def _build_result(finding: Finding, rule_index: int) -> dict:
    """Build a SARIF result from a finding."""
    rule_id = generate_rule_id(finding)

    # Build location — use file_path if available (static analysis), otherwise MCP URI
    if finding.file_path:
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.file_path,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": finding.line_number or 1,
                    "startColumn": 1,
                },
            }
        }
    else:
        # Runtime scan — use MCP tool as logical location
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": f"mcp://tool/{finding.tool_name}" if finding.tool_name else "mcp://server",
                }
            },
            "logicalLocations": [
                {
                    "name": finding.tool_name or "server",
                    "kind": "function",
                    "fullyQualifiedName": (
                        f"mcp.tools.{finding.tool_name}.{finding.parameter}"
                        if finding.parameter
                        else f"mcp.tools.{finding.tool_name}"
                    ),
                }
            ],
        }

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning"),
        "message": {
            "text": finding.detail or finding.title,
            "markdown": f"**{finding.title}**\n\n{finding.detail or finding.description or ''}",
        },
        "locations": [location],
        "fingerprints": {
            "mcpsecFingerprint/v1": generate_finding_fingerprint(finding),
        },
        "partialFingerprints": {
            "toolName": finding.tool_name,
            "parameter": finding.parameter,
            "scanner": finding.scanner,
        },
        "properties": {
            "severity": finding.severity.value,
            "scanner": finding.scanner,
            "confidence": finding.confidence,
        },
    }

    # Add evidence if available
    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence[:1000]

    # Add code snippet as code flow
    if finding.code_snippet:
        result["codeFlows"] = [
            {
                "message": {"text": "Vulnerability trace"},
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": finding.file_path or "unknown"},
                                        "region": {
                                            "startLine": finding.line_number or 1,
                                            "snippet": {"text": finding.code_snippet[:500]},
                                        },
                                    },
                                    "message": {"text": finding.title},
                                }
                            }
                        ]
                    }
                ],
            }
        ]

    # Add taint flow metadata
    if finding.taint_source and finding.taint_sink:
        result["properties"]["taintFlow"] = {
            "source": finding.taint_source,
            "sink": finding.taint_sink,
            "flow": finding.taint_flow,
        }

    return result


def generate_sarif_report(result: ScanResult) -> dict:
    """
    Generate a complete SARIF 2.1.0 report from a ScanResult.

    Args:
        result: The ScanResult containing findings

    Returns:
        SARIF 2.1.0 compliant dictionary
    """
    findings = result.findings

    # Build unique rules from findings (deduplicate by rule ID)
    rules_map: dict[str, dict] = {}
    for finding in findings:
        rule_id = generate_rule_id(finding)
        if rule_id not in rules_map:
            rules_map[rule_id] = _build_rule(finding)

    rules = list(rules_map.values())
    rule_id_to_index = {r["id"]: i for i, r in enumerate(rules)}

    # Build results
    results = []
    for finding in findings:
        rule_id = generate_rule_id(finding)
        rule_index = rule_id_to_index.get(rule_id, 0)
        results.append(_build_result(finding, rule_index))

    now_utc = datetime.now(timezone.utc).isoformat()

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpsec",
                        "organization": "Manthan Ghasadiya",
                        "version": MCPSEC_VERSION,
                        "semanticVersion": MCPSEC_VERSION,
                        "informationUri": "https://github.com/manthanghasadiya/mcpsec",
                        "rules": rules,
                        "properties": {
                            "tags": ["security", "mcp", "ai-security", "vulnerability-scanner"]
                        },
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": len(result.errors) == 0,
                        "commandLine": f'mcpsec scan --stdio "{result.target}"' if result.target else "mcpsec scan",
                        "startTimeUtc": result.started_at.isoformat() if result.started_at else now_utc,
                        "endTimeUtc": result.completed_at.isoformat() if result.completed_at else now_utc,
                        "workingDirectory": {"uri": "."},
                        "toolExecutionNotifications": [
                            {"message": {"text": err}, "level": "error"} for err in result.errors
                        ]
                        if result.errors
                        else [],
                    }
                ],
                "results": results,
                "taxonomies": [
                    {
                        "name": "CWE",
                        "version": "4.13",
                        "organization": "MITRE",
                        "shortDescription": {"text": "Common Weakness Enumeration"},
                        "informationUri": "https://cwe.mitre.org/",
                        "isComprehensive": False,
                        "taxa": CWE_TAXA,
                    }
                ],
                "properties": {
                    "target": result.target,
                    "transport": result.transport.value if result.transport else "unknown",
                    "scannersRun": result.scanners_run,
                    "summary": {
                        "critical": result.critical_count,
                        "high": result.high_count,
                        "medium": result.medium_count,
                        "low": result.low_count,
                        "info": result.info_count,
                        "total": result.total_count,
                    },
                },
            }
        ],
    }

    return sarif


def save_sarif_report(result: ScanResult, output_path: str) -> bool:
    """
    Save a SARIF report to a file.

    Args:
        result: The ScanResult containing findings
        output_path: Path to write the SARIF file

    Returns:
        True if successful, False otherwise
    """
    try:
        sarif = generate_sarif_report(result)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

        return True
    except Exception:
        return False


# ─── Fuzz SARIF ──────────────────────────────────────────────────────────────


def generate_sarif_from_fuzz(fuzz_summary: dict, target: str) -> dict:
    """
    Generate SARIF from fuzz results.

    Args:
        fuzz_summary: The fuzzer summary dict with crashes, timeouts, interesting_cases
        target: The target MCP server

    Returns:
        SARIF 2.1.0 compliant dictionary
    """
    rules: list[dict] = []
    results: list[dict] = []

    # Add rules for each category if present
    if fuzz_summary.get("crashes", 0) > 0:
        rules.append(
            {
                "id": "MCPSEC-FUZZ-CRASH",
                "name": "Protocol Crash",
                "shortDescription": {"text": "Server crashed on malformed input"},
                "properties": {"security-severity": "8.5"},
                "defaultConfiguration": {"level": "error"},
            }
        )

    if fuzz_summary.get("timeouts", 0) > 0:
        rules.append(
            {
                "id": "MCPSEC-FUZZ-TIMEOUT",
                "name": "Protocol Timeout",
                "shortDescription": {"text": "Server timed out on input"},
                "properties": {"security-severity": "5.0"},
                "defaultConfiguration": {"level": "warning"},
            }
        )

    if fuzz_summary.get("interesting", 0) > 0:
        rules.append(
            {
                "id": "MCPSEC-FUZZ-ANOMALY",
                "name": "Protocol Anomaly",
                "shortDescription": {"text": "Unexpected server behavior"},
                "properties": {"security-severity": "4.0"},
                "defaultConfiguration": {"level": "note"},
            }
        )

    rule_id_to_index = {r["id"]: i for i, r in enumerate(rules)}

    # Convert interesting cases to results
    for case in fuzz_summary.get("interesting_cases", []):
        if case.get("crashed"):
            rule_id = "MCPSEC-FUZZ-CRASH"
            level = "error"
        elif case.get("timeout"):
            rule_id = "MCPSEC-FUZZ-TIMEOUT"
            level = "warning"
        else:
            rule_id = "MCPSEC-FUZZ-ANOMALY"
            level = "note"

        if rule_id not in rule_id_to_index:
            continue

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_id_to_index[rule_id],
                "level": level,
                "message": {
                    "text": f"{case.get('case_name', 'Unknown')}: {case.get('description', '')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"mcp://{target}"}
                        }
                    }
                ],
                "properties": {
                    "generator": case.get("generator", "unknown"),
                    "error": case.get("error", "")[:500],
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpsec",
                        "version": MCPSEC_VERSION,
                        "informationUri": "https://github.com/manthanghasadiya/mcpsec",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": target,
                    "summary": {
                        "total_tests": fuzz_summary.get("total_tests", 0),
                        "crashes": fuzz_summary.get("crashes", 0),
                        "timeouts": fuzz_summary.get("timeouts", 0),
                        "interesting": fuzz_summary.get("interesting", 0),
                    },
                },
            }
        ],
    }


def save_sarif_from_fuzz(fuzz_summary: dict, target: str, output_path: str) -> bool:
    """Save fuzz results as SARIF."""
    try:
        sarif = generate_sarif_from_fuzz(fuzz_summary, target)
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False
