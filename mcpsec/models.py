"""
Core data models for mcpsec.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TransportType(str, Enum):
    STDIO = "stdio"
    HTTP = "http"


class ToolInfo(BaseModel):
    """Represents a discovered MCP tool."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    raw_schema: dict[str, Any] = Field(default_factory=dict)


class ResourceInfo(BaseModel):
    """Represents a discovered MCP resource."""

    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


class PromptInfo(BaseModel):
    """Represents a discovered MCP prompt."""

    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class ServerProfile(BaseModel):
    """Full profile of an MCP server's exposed surface."""

    server_name: str = ""
    server_version: str = ""
    transport: TransportType = TransportType.STDIO
    target: str = ""
    tools: list[ToolInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    enumerated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


HEURISTIC_NOTE = "Note: Heuristic lead requiring manual confirmation."


class Finding(BaseModel):
    """A single vulnerability finding."""

    id: str = ""
    severity: Severity
    scanner: str
    tool_name: str = ""
    parameter: str = ""
    title: str
    description: str = ""
    detail: str = ""
    evidence: str = ""
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    remediation: str = ""
    cwe: str = ""
    references: list[str] = Field(default_factory=list)
    # Taint Analysis Fields
    taint_source: str = ""
    taint_sink: str = ""
    taint_flow: str = ""
    confidence: str = "confirmed"

    @model_validator(mode="after")
    def _validate_evidence_model(self) -> Finding:
        conf_str = str(self.confidence or "").lower()
        if conf_str == "confirmed":
            self.confidence = "confirmed"
        else:
            self.confidence = "suspected"
            if self.severity == Severity.CRITICAL:
                self.severity = Severity.HIGH
        return self

    def short_str(self) -> str:
        if self.file_path:
            return f"[{self.severity.value.upper()}] {self.title} (file={self.file_path}:{self.line_number})"
        return f"[{self.severity.value.upper()}] {self.title} (tool={self.tool_name})"


def create_finding(
    *,
    severity: Severity,
    scanner: str,
    title: str,
    confidence: str = "confirmed",
    tool_name: str = "",
    parameter: str = "",
    description: str = "",
    detail: str = "",
    evidence: str = "",
    file_path: str = "",
    line_number: int = 0,
    code_snippet: str = "",
    remediation: str = "",
    cwe: str = "",
    references: list[str] | None = None,
    taint_source: str = "",
    taint_sink: str = "",
    taint_flow: str = "",
    id: str = "",
) -> Finding:
    """Central helper to emit a finding adhering to the evidence model.

    - confidence='confirmed': preserves full severity (CRITICAL/HIGH), tags title with [CONFIRMED].
    - confidence='suspected': caps severity to HIGH (never CRITICAL), tags title with [SUSPECTED],
      and appends a heuristic note to evidence.
    """
    conf = "confirmed" if str(confidence).lower() == "confirmed" else "suspected"
    clean_title = re.sub(r"\s*\[(CONFIRMED|SUSPECTED|LIKELY)\]", "", title, flags=re.I).strip()

    if conf == "confirmed":
        final_title = f"{clean_title} [CONFIRMED]"
        final_sev = severity
        final_ev = evidence
    else:
        final_title = f"{clean_title} [SUSPECTED]"
        final_sev = Severity.HIGH if severity == Severity.CRITICAL else severity
        if evidence:
            final_ev = (
                f"{evidence}\n{HEURISTIC_NOTE}"
                if HEURISTIC_NOTE not in evidence
                else evidence
            )
        else:
            final_ev = HEURISTIC_NOTE

    return Finding(
        id=id,
        severity=final_sev,
        scanner=scanner,
        tool_name=tool_name,
        parameter=parameter,
        title=final_title,
        description=description,
        detail=detail,
        evidence=final_ev,
        file_path=file_path,
        line_number=line_number,
        code_snippet=code_snippet,
        remediation=remediation,
        cwe=cwe,
        references=references or [],
        taint_source=taint_source,
        taint_sink=taint_sink,
        taint_flow=taint_flow,
        confidence=conf,
    )


class ScanResult(BaseModel):
    """Complete scan result."""

    scan_id: str = ""
    target: str = ""
    transport: TransportType = TransportType.STDIO
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    server_profile: ServerProfile | None = None
    findings: list[Finding] = Field(default_factory=list)
    scanners_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

    def mark_complete(self):
        self.completed_at = datetime.now(timezone.utc)

