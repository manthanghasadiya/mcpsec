"""
Core data models for mcpsec.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


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


class Finding(BaseModel):
    """A single vulnerability finding."""
    id: str = ""
    severity: Severity
    scanner: str
    tool_name: str = ""
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

    def short_str(self) -> str:
        if self.file_path:
            return f"[{self.severity.value.upper()}] {self.title} (file={self.file_path}:{self.line_number})"
        return f"[{self.severity.value.upper()}] {self.title} (tool={self.tool_name})"


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
