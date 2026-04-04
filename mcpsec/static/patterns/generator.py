"""
Pattern generator -- expands template patterns programmatically.

This module provides utilities for generating pattern variants
from base templates, e.g. for different string formats or
library variations, to maximize coverage without manual duplication.
"""

from __future__ import annotations

from mcpsec.static.patterns.base import (
    SinkPattern, Language, VulnType, Severity, Confidence
)


def generate_string_format_variants(
    base_id: str,
    base_pattern_prefix: str,
    function_name: str,
    vuln_type: VulnType,
    languages: list[Language],
    severity: Severity = Severity.CRITICAL,
    cwe: str = "",
    remediation: str = "",
    negative_patterns: list[str] | None = None,
) -> list[SinkPattern]:
    """
    Generate patterns for all common Python/JS string construction methods.

    For a base prefix like r'subprocess\.run\s*\(', generates:
    - prefix + f-string variant
    - prefix + .format() variant
    - prefix + % formatting variant
    - prefix + concatenation variant
    """
    neg = negative_patterns or []
    variants = [
        # f-string
        (f"{base_id}-fstr", rf"{base_pattern_prefix}\s*f['\"]", f"{function_name}(f-string)"),
        # .format()
        (f"{base_id}-fmt", rf"{base_pattern_prefix}[^)]*\.format\s*\(", f"{function_name}(.format())"),
        # % formatting
        (f"{base_id}-pct", rf"{base_pattern_prefix}[^)]*%[^)]*%", f"{function_name}(% format)"),
        # concatenation
        (f"{base_id}-cat", rf"{base_pattern_prefix}[^)]*\+[^)]*\)", f"{function_name}(concat)"),
    ]

    patterns = []
    for pid, pat, fname in variants:
        patterns.append(SinkPattern(
            id=pid,
            vuln_type=vuln_type,
            languages=languages,
            pattern=pat,
            function_name=fname,
            severity=severity,
            confidence=Confidence.HIGH,
            cwe=cwe,
            remediation=remediation,
            negative_patterns=neg,
        ))
    return patterns


def generate_js_template_variants(
    base_id: str,
    call_prefix: str,
    function_name: str,
    vuln_type: VulnType,
    severity: Severity = Severity.CRITICAL,
    cwe: str = "",
) -> list[SinkPattern]:
    """
    Generate JS/TS patterns for template literal, concatenation, and variable variants.
    """
    langs = [Language.TYPESCRIPT, Language.JAVASCRIPT]
    variants = [
        (
            f"{base_id}-tpl",
            rf"{call_prefix}\s*`[^`]*\${{[^}}]+}}",
            f"{function_name}(`${{...}}`)",
        ),
        (
            f"{base_id}-cat",
            rf"{call_prefix}[^)]*\+[^)]*\)",
            f"{function_name}(a + b)",
        ),
        (
            f"{base_id}-var",
            rf"{call_prefix}\s*[^'\"`\s][^)]*\)",
            f"{function_name}(variable)",
        ),
    ]

    patterns = []
    for pid, pat, fname in variants:
        patterns.append(SinkPattern(
            id=pid,
            vuln_type=vuln_type,
            languages=langs,
            pattern=pat,
            function_name=fname,
            severity=severity,
            confidence=Confidence.HIGH,
            cwe=cwe,
        ))
    return patterns
