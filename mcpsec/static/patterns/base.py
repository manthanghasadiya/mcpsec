"""
Base classes for the pattern database.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re


class Language(str, Enum):
    """Supported programming languages."""
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    GO = "go"
    RUST = "rust"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    JAVA = "java"
    RUBY = "ruby"
    PHP = "php"


class VulnType(str, Enum):
    """Vulnerability categories."""
    COMMAND_INJECTION = "command-injection"
    SQL_INJECTION = "sql-injection"
    NOSQL_INJECTION = "nosql-injection"
    PATH_TRAVERSAL = "path-traversal"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    CODE_EXECUTION = "code-execution"
    XXE = "xxe"
    CRYPTO = "crypto-weakness"
    TEMPLATE_INJECTION = "template-injection"
    LDAP_INJECTION = "ldap-injection"
    LOG_INJECTION = "log-injection"
    PROTOTYPE_POLLUTION = "prototype-pollution"
    HARDCODED_SECRET = "hardcoded-secret"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Detection confidence."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SinkPattern:
    """Pattern identifying a dangerous sink."""
    id: str
    vuln_type: VulnType
    languages: list[Language]
    pattern: str
    function_name: str
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    cwe: str = ""
    remediation: str = ""
    negative_patterns: list[str] = field(default_factory=list)
    context_patterns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    flags: int = 0

    _compiled: Optional[re.Pattern] = field(default=None, repr=False)
    _negative_compiled: list[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self):
        """Compile regex patterns."""
        try:
            self._compiled = re.compile(self.pattern, re.MULTILINE | self.flags)
        except re.error:
            self._compiled = None

        self._negative_compiled = []
        for neg in self.negative_patterns:
            try:
                self._negative_compiled.append(re.compile(neg, re.MULTILINE))
            except re.error:
                pass

    def matches(self, code: str, line: str) -> bool:
        """Check if pattern matches and no negative patterns match."""
        if not self._compiled:
            return False
        if not self._compiled.search(line):
            return False
        for neg in self._negative_compiled:
            if neg.search(code):
                return False
        return True

    def applies_to(self, lang: Language) -> bool:
        """Check if pattern applies to language."""
        if lang in self.languages:
            return True
        if Language.TYPESCRIPT in self.languages and lang == Language.JAVASCRIPT:
            return True
        return False


@dataclass
class SourcePattern:
    """Pattern identifying MCP user input (taint source)."""
    id: str
    framework: str
    languages: list[Language]
    entry_pattern: str
    param_pattern: str
    description: str = ""

    _entry_compiled: Optional[re.Pattern] = field(default=None, repr=False)
    _param_compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        try:
            self._entry_compiled = re.compile(
                self.entry_pattern, re.MULTILINE | re.DOTALL
            )
        except re.error:
            self._entry_compiled = None
        try:
            self._param_compiled = re.compile(self.param_pattern, re.MULTILINE)
        except re.error:
            self._param_compiled = None


@dataclass
class SanitizerPattern:
    """Pattern identifying input sanitization."""
    id: str
    languages: list[Language]
    pattern: str
    sanitizes: list[VulnType]
    description: str = ""
    is_partial: bool = False
    context_patterns: list[str] = field(default_factory=list)

    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        try:
            self._compiled = re.compile(self.pattern, re.MULTILINE)
        except re.error:
            self._compiled = None


@dataclass
class SinkMatch:
    """A detected sink in source code."""
    pattern: SinkPattern
    file_path: str
    line_number: int
    code_line: str
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    match_text: str = ""

    @property
    def context(self) -> str:
        """Full context with line numbers."""
        lines = []
        start = self.line_number - len(self.context_before)
        for i, line in enumerate(self.context_before):
            lines.append(f"{start + i:4d} | {line}")
        lines.append(f"{self.line_number:4d} | {self.code_line}  <-- SINK")
        for i, line in enumerate(self.context_after):
            lines.append(f"{self.line_number + i + 1:4d} | {line}")
        return "\n".join(lines)

    @property
    def short_context(self) -> str:
        """Compact 3-line context."""
        lines = self.context_before[-2:] + [self.code_line] + self.context_after[:2]
        return "\n".join(lines)
