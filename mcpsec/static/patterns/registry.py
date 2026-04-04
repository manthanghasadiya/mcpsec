"""
Pattern registry -- loads and indexes all patterns.
"""

from __future__ import annotations
from typing import Optional

from mcpsec.static.patterns.base import (
    SinkPattern, SourcePattern, SanitizerPattern,
    Language, VulnType,
)
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
from mcpsec.static.patterns.sources import mcp_frameworks
from mcpsec.static.patterns.sanitizers import sanitizers


class PatternRegistry:
    """
    Central registry for all patterns.
    Provides efficient lookup by language, vuln type, etc.
    """

    _instance: Optional[PatternRegistry] = None

    def __init__(self):
        self._sink_patterns: list[SinkPattern] = []
        self._source_patterns: list[SourcePattern] = []
        self._sanitizer_patterns: list[SanitizerPattern] = []

        self._by_language: dict[Language, list[SinkPattern]] = {}
        self._by_vuln_type: dict[VulnType, list[SinkPattern]] = {}

        self._load_all_patterns()

    @classmethod
    def get(cls) -> PatternRegistry:
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_all_patterns(self):
        """Load patterns from all modules."""
        sink_modules = [
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
        ]
        for module in sink_modules:
            if hasattr(module, "PATTERNS"):
                self._sink_patterns.extend(module.PATTERNS)

        if hasattr(mcp_frameworks, "PATTERNS"):
            self._source_patterns.extend(mcp_frameworks.PATTERNS)

        if hasattr(sanitizers, "PATTERNS"):
            self._sanitizer_patterns.extend(sanitizers.PATTERNS)

        self._build_indexes()

    def _build_indexes(self):
        """Build lookup indexes."""
        for lang in Language:
            self._by_language[lang] = [
                p for p in self._sink_patterns if p.applies_to(lang)
            ]
        for vuln in VulnType:
            self._by_vuln_type[vuln] = [
                p for p in self._sink_patterns if p.vuln_type == vuln
            ]

    def get_sink_patterns(
        self,
        language: Optional[Language] = None,
        vuln_type: Optional[VulnType] = None,
    ) -> list[SinkPattern]:
        """Get sink patterns with optional filters."""
        if language and vuln_type:
            return [
                p for p in self._by_language.get(language, [])
                if p.vuln_type == vuln_type
            ]
        elif language:
            return self._by_language.get(language, [])
        elif vuln_type:
            return self._by_vuln_type.get(vuln_type, [])
        return self._sink_patterns.copy()

    def get_source_patterns(
        self,
        framework: Optional[str] = None,
    ) -> list[SourcePattern]:
        """Get MCP source patterns."""
        if framework:
            return [p for p in self._source_patterns if p.framework == framework]
        return self._source_patterns.copy()

    def get_sanitizer_patterns(
        self,
        language: Optional[Language] = None,
        vuln_type: Optional[VulnType] = None,
    ) -> list[SanitizerPattern]:
        """Get sanitizer patterns."""
        patterns = self._sanitizer_patterns.copy()
        if language:
            patterns = [p for p in patterns if language in p.languages]
        if vuln_type:
            patterns = [p for p in patterns if vuln_type in p.sanitizes]
        return patterns

    def stats(self) -> dict:
        """Get pattern statistics."""
        return {
            "total_sink_patterns": len(self._sink_patterns),
            "total_source_patterns": len(self._source_patterns),
            "total_sanitizer_patterns": len(self._sanitizer_patterns),
            "by_language": {
                lang.value: len(patterns)
                for lang, patterns in self._by_language.items()
                if patterns
            },
            "by_vuln_type": {
                vuln.value: len(patterns)
                for vuln, patterns in self._by_vuln_type.items()
                if patterns
            },
        }


# Convenience functions

def get_patterns(
    language: Optional[Language] = None,
    vuln_type: Optional[VulnType] = None,
) -> list[SinkPattern]:
    """Get sink patterns."""
    return PatternRegistry.get().get_sink_patterns(language, vuln_type)


def get_sources(framework: Optional[str] = None) -> list[SourcePattern]:
    """Get MCP source patterns."""
    return PatternRegistry.get().get_source_patterns(framework)


def get_sanitizers(
    language: Optional[Language] = None,
    vuln_type: Optional[VulnType] = None,
) -> list[SanitizerPattern]:
    """Get sanitizer patterns."""
    return PatternRegistry.get().get_sanitizer_patterns(language, vuln_type)
