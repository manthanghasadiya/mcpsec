"""
ChainReporter - Reports chained fuzzing results.

Generates reports in multiple formats:
- Console output (Rich)
- JSON
- SARIF (for CI/CD)
"""

import json
from datetime import datetime
from typing import Any
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()


class ChainReporter:
    """Reports chained fuzzing results."""
    
    def __init__(self):
        self._findings = []
    
    def add_finding(self, result: Any) -> None:
        """Add a finding to the report."""
        self._findings.append(result)
    
    def to_json(self) -> dict:
        """Convert results to JSON format."""
        return {
            "scan_type": "chained_fuzzing",
            "timestamp": datetime.utcnow().isoformat(),
            "total_chains_executed": len(self._findings),
            "findings_count": sum(1 for f in self._findings if f.is_finding),
            "findings": [
                {
                    "chain_id": f.chain.chain_id,
                    "target_tool": f.chain.target_tool,
                    "injection_point": f.injection_point,
                    "injection_type": f.chain.injection_point_type,
                    "payload": f.payload_used,
                    "status": f.status.value,
                    "crash_detected": f.crash_detected,
                    "exploitation_evidence": f.exploitation_evidence,
                    "execution_time_ms": f.execution_time_ms,
                    "error_message": f.error_message,
                }
                for f in self._findings
                if f.is_finding
            ]
        }
    
    def save_json(self, path: str) -> None:
        """Save results to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_json(), f, indent=2)
    
    def to_sarif(self) -> dict:
        """Convert results to SARIF format for CI/CD integration."""
        findings = [f for f in self._findings if f.is_finding]
        
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "mcpsec",
                        "version": "1.0.4",
                        "informationUri": "https://github.com/manthanghasadiya/mcpsec",
                        "rules": self._get_sarif_rules(findings),
                    }
                },
                "results": [
                    {
                        "ruleId": f"MCPSEC-CHAIN-{f.chain.injection_point_type.upper()}",
                        "level": "error" if f.crash_detected else "warning",
                        "message": {
                            "text": f"Potential {f.chain.injection_point_type} vulnerability in {f.chain.target_tool}.{f.injection_point}"
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f"mcp://{f.chain.target_tool}",
                                }
                            }
                        }],
                        "properties": {
                            "payload": f.payload_used,
                            "evidence": f.exploitation_evidence,
                        }
                    }
                    for f in findings
                ]
            }]
        }
    
    def _get_sarif_rules(self, findings: list) -> list[dict]:
        """Generate SARIF rule definitions."""
        rules = {}
        for f in findings:
            rule_id = f"MCPSEC-CHAIN-{f.chain.injection_point_type.upper()}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f"MCP {f.chain.injection_point_type.title()} Injection",
                    "shortDescription": {
                        "text": f"Potential {f.chain.injection_point_type} injection via chained tool calls"
                    },
                    "defaultConfiguration": {
                        "level": "error"
                    }
                }
        return list(rules.values())
