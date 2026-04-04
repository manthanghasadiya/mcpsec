"""Sink pattern modules."""

from mcpsec.static.patterns.sinks import (
    command_injection,
    sql_injection,
    path_traversal,
    ssrf,
    deserialization,
    code_execution,
    xxe,
    crypto,
    additional,
    web_vulns,
    injection_extra,
    final_patterns,
    bulk_extension,
)

__all__ = [
    "command_injection",
    "sql_injection",
    "path_traversal",
    "ssrf",
    "deserialization",
    "code_execution",
    "xxe",
    "crypto",
    "additional",
    "web_vulns",
    "injection_extra",
    "final_patterns",
    "bulk_extension",
]
