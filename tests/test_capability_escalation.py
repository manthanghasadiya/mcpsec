"""Tests for capability-escalation scanner declared capability detection and deduplication."""

from __future__ import annotations

from typing import Any
import pytest

from mcpsec.models import ServerProfile, Severity
from mcpsec.scanners.capability_escalation import CapabilityEscalationScanner


class FakeSession:
    """Fake MCP ClientSession for testing capability escalation."""

    def __init__(
        self,
        working_methods: list[str] | None = None,
        ambiguous_methods: dict[str, str] | None = None,
        soft_errors: dict[str, str] | None = None,
        hard_errors: dict[str, str] | None = None,
    ):
        self.working_methods = set(working_methods or [])
        self.ambiguous_methods = ambiguous_methods or {}
        self.soft_errors = soft_errors or {}
        self.hard_errors = hard_errors or {}

    async def list_tools(self) -> Any:
        return self._handle_call("tools/list", [{"name": "fake_tool"}])

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return self._handle_call("tools/call", {"result": "success"})

    async def list_resources(self) -> Any:
        return self._handle_call("resources/list", [{"uri": "test://fake"}])

    async def read_resource(self, uri: str) -> Any:
        return self._handle_call("resources/read", {"content": "data"})

    async def subscribe_resource(self, uri: str) -> Any:
        return self._handle_call("resources/subscribe", {"status": "ok"})

    async def list_prompts(self) -> Any:
        return self._handle_call("prompts/list", [{"name": "fake_prompt"}])

    async def get_prompt(self, name: str, arguments: Any = None) -> Any:
        return self._handle_call("prompts/get", {"description": "prompt"})

    async def set_logging_level(self, level: str) -> Any:
        return self._handle_call("logging/setLevel", {"level": level})

    def _handle_call(self, method: str, success_value: Any) -> Any:
        if method in self.hard_errors:
            raise RuntimeError(self.hard_errors[method])
        if method in self.soft_errors:
            raise RuntimeError(self.soft_errors[method])
        if method in self.ambiguous_methods:
            raise RuntimeError(self.ambiguous_methods[method])
        if method in self.working_methods:
            return success_value
        raise RuntimeError(f"Method not found: {method}")


class FakeClient:
    """Fake MCPSecClient wrapper holding session."""

    def __init__(self, session: FakeSession):
        self.session = session


@pytest.mark.asyncio
async def test_regression_n8n_case_empty_dict_capabilities():
    """ServerProfile with capabilities = {"tools": {}, "resources": {}} should not flag tools/resources."""
    scanner = CapabilityEscalationScanner()
    profile = ServerProfile(capabilities={"tools": {}, "resources": {}})

    # Session where tools and resources respond (working or ambiguous error)
    session = FakeSession(
        working_methods=["tools/list", "resources/list"],
        ambiguous_methods={"tools/call": "tool __test__ not found", "resources/read": "unknown uri"},
    )
    client = FakeClient(session)

    findings = await scanner.scan(profile, client)

    # Tools and resources are declared, so there must be NO Undeclared Capability Works
    # or Ambiguous Capability Response findings for tools or resources.
    tool_and_resource_findings = [
        f for f in findings
        if "tools" in f.title.lower() or "resources" in f.title.lower()
    ]
    assert tool_and_resource_findings == [], f"Unexpected findings for declared capabilities: {tool_and_resource_findings}"


@pytest.mark.asyncio
async def test_recall_preserved_and_deduplicated():
    """ServerProfile with capabilities = {} flags working tools as ONE finding, de-duplicating methods."""
    scanner = CapabilityEscalationScanner()
    profile = ServerProfile(capabilities={})

    # Both tools/list and tools/call succeed
    session = FakeSession(working_methods=["tools/list", "tools/call"])
    client = FakeClient(session)

    findings = await scanner.scan(profile, client)

    tools_findings = [f for f in findings if f.title == "Undeclared Capability Works: tools"]
    assert len(tools_findings) == 1, f"Expected exactly 1 tools finding, got {len(tools_findings)}"

    finding = tools_findings[0]
    assert finding.severity == Severity.HIGH
    assert "tools/list" in finding.detail
    assert "tools/call" in finding.detail
    assert "tools/list" in finding.description
    assert "tools/call" in finding.description


@pytest.mark.asyncio
async def test_experimental_sampling_declared():
    """capabilities = {"experimental": {"sampling": {}}} declares sampling."""
    scanner = CapabilityEscalationScanner()
    profile = ServerProfile(capabilities={"experimental": {"sampling": {}}})

    session = FakeSession(working_methods=["sampling/createMessage"])
    client = FakeClient(session)

    findings = await scanner.scan(profile, client)

    sampling_findings = [f for f in findings if "sampling" in f.title.lower()]
    assert sampling_findings == [], f"Expected sampling to be treated as declared, got: {sampling_findings}"


@pytest.mark.asyncio
async def test_ambiguous_capability_response_deduplicated():
    """Genuinely undeclared capability with ambiguous error emits at most ONE LOW finding."""
    scanner = CapabilityEscalationScanner()
    profile = ServerProfile(capabilities={})

    session = FakeSession(
        ambiguous_methods={
            "prompts/list": "internal server error: database unavailable",
            "prompts/get": "prompt retrieval failed with exception",
        }
    )
    client = FakeClient(session)

    findings = await scanner.scan(profile, client)

    prompt_findings = [f for f in findings if f.title == "Ambiguous Capability Response: prompts"]
    assert len(prompt_findings) == 1, f"Expected 1 ambiguous prompts finding, got {len(prompt_findings)}"
    assert prompt_findings[0].severity == Severity.LOW
    assert "prompts/list" in prompt_findings[0].detail
    assert "prompts/get" in prompt_findings[0].detail
