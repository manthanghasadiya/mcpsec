"""Tests for the code execution scanner oracle and reflection guards."""

import re
from unittest.mock import AsyncMock
import pytest

from mcpsec.models import Finding, ServerProfile, Severity, ToolInfo
from mcpsec.scanners.code_execution import CodeExecutionScanner


def _create_profile(
    tool_name: str, param_name: str, description: str = "A tool for code evaluation"
) -> ServerProfile:
    tool = ToolInfo(
        name=tool_name,
        description=description,
        parameters={param_name: {"type": "string"}},
        raw_schema={
            "inputSchema": {
                "properties": {param_name: {"type": "string"}},
                "required": [param_name],
            }
        },
    )
    return ServerProfile(server_name="test_server", tools=[tool])


def _create_mock_client(side_effect_fn):
    client = AsyncMock()

    class MockContent:
        def __init__(self, text: str):
            self.type = "text"
            self.text = text

    class MockResult:
        def __init__(self, text: str):
            self.content = [MockContent(text)]

    async def call_tool(tool_name: str, args: dict):
        text = side_effect_fn(tool_name, args)
        return MockResult(text)

    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


@pytest.mark.asyncio
async def test_echoing_tool_not_confirmed_code_exec():
    """Reflection regression (n8n case): a tool echoing query verbatim yields NO findings."""
    profile = _create_profile(
        "search_nodes", "query", description="Search nodes formula and code"
    )

    def echo_handler(tool_name: str, args: dict) -> str:
        q = args.get("query", "")
        # Emulates n8n-mcp search_nodes echoing query and returning mock docs
        return f"Echo query: {q}\nNo results found for {q}."

    client = _create_mock_client(echo_handler)
    scanner = CodeExecutionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 0, f"Expected 0 findings for echoing tool, got {findings}"


@pytest.mark.asyncio
async def test_true_positive_code_exec_confirmed():
    """A tool actually evaluating arithmetic yields a confirmed code execution finding."""
    profile = _create_profile(
        "calculate", "expr", description="Evaluate math expressions"
    )

    def eval_handler(tool_name: str, args: dict) -> str:
        expr = args.get("expr", "")
        m = re.search(r"(\d+)\s*\*\s*(\d+)", expr)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            return f"Result: {a * b}"
        return "Unknown expression"

    client = _create_mock_client(eval_handler)
    scanner = CodeExecutionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.confidence == "confirmed"
    assert "arithmetic payload" in f.evidence
    assert "evaluated to" in f.evidence


@pytest.mark.asyncio
async def test_corpus_collision_guard_49_not_confirmed_code_exec():
    """A tool whose response corpus contains '49' without evaluating anything yields NO findings."""
    profile = _create_profile(
        "compute_data", "data", description="Process data code and compute stats"
    )

    def corpus_49_handler(tool_name: str, args: dict) -> str:
        return "Loaded 49 items from cache. Status 49 OK."

    client = _create_mock_client(corpus_49_handler)
    scanner = CodeExecutionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_system_command_reflection_guard_code_exec():
    """If echoed text contains uid= or <class ' from the sent arguments, reflection guard skips it."""
    profile = _create_profile(
        "eval_script", "script", description="Evaluate script logic"
    )

    def echo_handler(tool_name: str, args: dict) -> str:
        s = args.get("script", "")
        # Reflects the sent script verbatim
        return f"Script received: {s}"

    client = _create_mock_client(echo_handler)
    scanner = CodeExecutionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_system_command_true_positive_code_exec():
    """True execution of system command returning uid= output is confirmed."""
    profile = _create_profile(
        "eval_script", "script", description="Evaluate script logic"
    )

    def exec_handler(tool_name: str, args: dict) -> str:
        s = args.get("script", "")
        if "os" in s or "subprocess" in s:
            return "uid=1000(user) gid=1000(user) groups=1000(user)"
        return "Syntax error"

    client = _create_mock_client(exec_handler)
    scanner = CodeExecutionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert "uid=" in findings[0].evidence
