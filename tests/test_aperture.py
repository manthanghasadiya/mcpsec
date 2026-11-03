"""Tests for widened oracle aperture and unified candidate parameter selection."""

import sys
import pytest

from mcpsec.models import ServerProfile, ToolInfo, Severity
from mcpsec.scanners.param_selection import candidate_injectable_params, HINT_KEYWORDS


def test_candidate_injectable_params_ordering_and_inclusion():
    """candidate_injectable_params includes all string and untyped params, hints first, excludes non-strings."""
    tool = ToolInfo(
        name="mixed_tool",
        description="A tool with various parameter types",
        parameters={
            "count": "integer",
            "verbose": "boolean",
            "projectName": "string",
            "untyped_field": "",
        },
        raw_schema={
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "verbose": {"type": "boolean"},
                    "projectName": {"type": "string"},
                    "dataModel": {"type": "string"},
                    "file_path": {"type": "string"},
                    "target_uri": {"type": "string", "format": "uri"},
                    "payload": {"type": "string"},
                    "item": {"type": "string"},
                    "input": {"type": "string"},
                    "untyped_field": {},
                },
            }
        },
    )

    params = candidate_injectable_params(tool, max_params=25)

    # 1. Non-string primitives must be excluded
    assert "count" not in params
    assert "verbose" not in params

    # 2. Non-keyword string and untyped parameters must NOT be excluded
    assert "payload" in params
    assert "item" in params
    assert "input" in params
    assert "projectName" in params
    assert "untyped_field" in params

    # 3. Hinted params must come before unhinted params
    hinted_params = {"dataModel", "file_path", "target_uri"}
    unhinted_params = {"projectName", "payload", "item", "input", "untyped_field"}

    # Find indices
    max_hint_idx = max(params.index(p) for p in hinted_params)
    min_unhint_idx = min(params.index(p) for p in unhinted_params)
    assert max_hint_idx < min_unhint_idx, "All hinted parameters should appear before unhinted parameters"


def test_candidate_injectable_params_respects_max_params():
    """candidate_injectable_params bounds the output list at max_params."""
    props = {f"param_{i}": {"type": "string"} for i in range(30)}
    tool = ToolInfo(
        name="wide_tool",
        description="A tool with 30 parameters",
        parameters={p: "string" for p in props},
        raw_schema={"inputSchema": {"properties": props}},
    )

    result_default = candidate_injectable_params(tool)
    assert len(result_default) == 25

    result_capped = candidate_injectable_params(tool, max_params=10)
    assert len(result_capped) == 10
    assert result_capped == [f"param_{i}" for i in range(10)]


@pytest.mark.asyncio
async def test_end_to_end_vulnerable_noname_server():
    """End-to-end scan of vulnerable_noname_server confirms cmdi, path-traversal, and sqli on non-keyword params."""
    from mcpsec.client.mcp_client import MCPSecClient
    from mcpsec.engine import run_scan

    async with MCPSecClient() as client:
        profile = await client.connect_stdio(
            sys.executable,
            ["tests/servers/vulnerable_noname_server.py"],
        )
        scan_result = await run_scan(
            profile=profile,
            client=client,
            scanner_names=["command-injection", "path-traversal", "sql-rce"],
        )

    # Collect confirmed findings
    findings = scan_result.findings

    cmdi_findings = [
        f for f in findings
        if f.scanner == "command-injection" and f.tool_name == "do_thing" and f.parameter == "payload"
    ]
    assert len(cmdi_findings) >= 1, "Expected confirmed command-injection finding on do_thing(payload)"
    assert cmdi_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    path_findings = [
        f for f in findings
        if f.scanner == "path-traversal" and f.tool_name == "process" and f.parameter == "item"
    ]
    assert len(path_findings) >= 1, "Expected confirmed path-traversal finding on process(item)"
    assert path_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    sqli_findings = [
        f for f in findings
        if f.scanner == "sql-rce" and f.tool_name == "handle" and f.parameter == "input"
    ]
    assert len(sqli_findings) >= 1, "Expected confirmed SQLi finding on handle(input)"
    assert sqli_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)
    assert "boolean" in sqli_findings[0].title.lower()

    # Regression: do_thing must NOT have any SQLi or SQL-to-RCE findings
    sql_on_do_thing = [
        f for f in findings
        if f.scanner == "sql-rce" and f.tool_name == "do_thing"
    ]
    assert sql_on_do_thing == [], f"Expected no SQL findings on do_thing, got: {sql_on_do_thing}"

    # Regression: NO "SQL Injection to ... via POSTGRES" findings anywhere
    postgres_findings = [
        f for f in findings
        if "postgres" in f.title.lower() or "via postgres" in f.title.lower()
    ]
    assert postgres_findings == [], f"Expected no Postgres findings, got: {postgres_findings}"


@pytest.mark.asyncio
async def test_safe_server_with_non_keyword_params_produces_no_vuln_findings():
    """Safe server with non-keyword parameters is probed, but produces no injection findings."""
    from mcpsec.client.mcp_client import MCPSecClient
    from mcpsec.engine import run_scan
    from unittest.mock import AsyncMock

    tool = ToolInfo(
        name="do_work",
        description="Safe processing tool with plain names",
        parameters={"item": "string", "payload": "string"},
        raw_schema={
            "inputSchema": {
                "type": "object",
                "properties": {
                    "item": {"type": "string"},
                    "payload": {"type": "string"},
                },
            }
        },
    )
    profile = ServerProfile(
        server_name="safe_server",
        tools=[tool],
    )

    client = AsyncMock()

    async def mock_safe_call(tool_name, args):
        class MockContent:
            type = "text"
            text = f"Processed safely: {args}"

        class MockResult:
            content = [MockContent()]

        return MockResult()

    client.call_tool = AsyncMock(side_effect=mock_safe_call)

    scan_result = await run_scan(
        profile=profile,
        client=client,
        scanner_names=[
            "command-injection",
            "path-traversal",
            "sql-rce",
            "code-execution",
            "template-injection",
            "deserialization",
            "ssrf",
        ],
    )

    vuln_findings = [
        f for f in scan_result.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert vuln_findings == [], f"Expected 0 confirmed findings on safe server, got: {vuln_findings}"
