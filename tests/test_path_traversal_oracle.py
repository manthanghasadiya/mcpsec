"""Unit and integration tests for the Path Traversal Sentinel Oracle."""

import os
import tempfile
from unittest.mock import AsyncMock
import pytest

from mcpsec.models import ServerProfile, Severity, ToolInfo
from mcpsec.scanners.oracles import (
    OracleResult,
    confirm_path_traversal,
    confirm_path_traversal_sync,
)
from mcpsec.scanners.path_traversal import PathTraversalScanner


@pytest.mark.asyncio
async def test_sentinel_positive():
    """Sentinel positive: call_fn that actually reads the file at the injected path -> confirmed."""

    async def call_fn(tool_name: str, args: dict):
        p = args.get("path", "")
        if p.startswith("file://"):
            p = p[7:]
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read(), 0.01
        except Exception as e:
            return f"error: {e}", 0.01

    result: OracleResult = await confirm_path_traversal(
        call_fn=call_fn,
        tool_name="read_file",
        param_name="path",
        base_args={"path": "default"},
    )

    assert result.confirmed is True
    assert result.method == "sentinel-file"
    assert "Sentinel file content token" in result.evidence
    assert result.payload != ""


@pytest.mark.asyncio
async def test_reflection_negative():
    """Reflection negative (critical): call_fn returns path in response but never reads -> NOT confirmed."""

    async def call_fn(tool_name: str, args: dict):
        p = args.get("path", "")
        return f"Echo path: {p}", 0.01

    result: OracleResult = await confirm_path_traversal(
        call_fn=call_fn,
        tool_name="reflect_path",
        param_name="path",
        base_args={"path": "default"},
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No sentinel content retrieved" in result.evidence


@pytest.mark.asyncio
async def test_safe_negative():
    """Safe negative: call_fn refuses to read outside an allowlisted base -> NOT confirmed."""
    safe_base = os.path.realpath(tempfile.gettempdir())

    async def call_fn(tool_name: str, args: dict):
        p = args.get("path", "")
        if p.startswith("file://"):
            p = p[7:]
        # Deny traversal attempts
        if ".." in p or p.startswith("/"):
            return "Error: Access denied (path traversal blocked)", 0.01
        return "Safe content", 0.01

    result: OracleResult = await confirm_path_traversal(
        call_fn=call_fn,
        tool_name="safe_read",
        param_name="path",
        base_args={"path": "default"},
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No sentinel content retrieved" in result.evidence


@pytest.mark.asyncio
async def test_sentinel_cleanup():
    """Cleanup: the sentinel file no longer exists on disk after confirm_path_traversal returns."""
    sentinel_dir = tempfile.mkdtemp()
    sentinel_path_seen = []

    async def call_fn(tool_name: str, args: dict):
        p = args.get("path", "")
        # Record the path to check after
        if p.startswith("file://"):
            p = p[7:]
        if os.path.exists(p) and "mcpsec_sentinel_" in p:
            sentinel_path_seen.append(p)
            with open(p, "r", encoding="utf-8") as f:
                return f.read(), 0.01
        return "error", 0.01

    try:
        result = await confirm_path_traversal(
            call_fn=call_fn,
            tool_name="read_file",
            param_name="path",
            base_args={"path": "default"},
            sentinel_dir=sentinel_dir,
        )
        assert result.confirmed is True
        assert len(sentinel_path_seen) > 0
        # Check that all seen sentinel paths have been cleaned up
        for sp in sentinel_path_seen:
            assert not os.path.exists(sp), f"Sentinel file was not cleaned up: {sp}"
        # Check that no files remain in sentinel_dir
        remaining = os.listdir(sentinel_dir)
        assert remaining == [], f"Files remained in sentinel_dir: {remaining}"
    finally:
        if os.path.exists(sentinel_dir):
            try:
                os.rmdir(sentinel_dir)
            except OSError:
                pass


def test_confirm_path_traversal_sync():
    """Synchronous helper confirm_path_traversal_sync works properly."""

    def call_fn(tool_name: str, args: dict):
        p = args.get("path", "")
        if p.startswith("file://"):
            p = p[7:]
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read(), 0.01
        except Exception as e:
            return f"error: {e}", 0.01

    result = confirm_path_traversal_sync(
        call_fn=call_fn,
        tool_name="read_file",
        param_name="path",
        base_args={"path": "default"},
    )
    assert result.confirmed is True
    assert result.method == "sentinel-file"


@pytest.mark.asyncio
async def test_path_traversal_scanner_e2e():
    """End-to-end test of PathTraversalScanner distinguishing real reads from reflections."""
    mock_client = AsyncMock()

    async def mock_call_tool(tool_name: str, args: dict):
        class MockResult:

            def __init__(self, text: str):
                class Block:

                    def __init__(self, t: str):
                        self.text = t

                self.content = [Block(text)]
                self.isError = False

        path = args.get("path", "")
        if tool_name == "read_file":
            if path.startswith("file://"):
                path = path[7:]
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return MockResult(f.read())
            except Exception as e:
                return MockResult(f"Error: {e}")
        elif tool_name == "reflect_path":
            return MockResult(f"Echo path: {path}")
        return MockResult("Unknown tool")

    mock_client.call_tool = mock_call_tool

    profile = ServerProfile(
        server_name="test_server",
        tools=[
            ToolInfo(
                name="read_file",
                description="Read a file from disk",
                parameters={"path": {"type": "string"}},
                raw_schema={
                    "inputSchema": {
                        "properties": {"path": {"type": "string"}}
                    }
                },
            ),
            ToolInfo(
                name="reflect_path",
                description="Reflect path",
                parameters={"path": {"type": "string"}},
                raw_schema={
                    "inputSchema": {
                        "properties": {"path": {"type": "string"}}
                    }
                },
            ),
        ],
    )

    scanner = PathTraversalScanner()
    findings = await scanner.scan(profile, mock_client)

    tool_names = [f.tool_name for f in findings]
    assert "read_file" in tool_names
    assert "reflect_path" not in tool_names

    read_finding = next(f for f in findings if f.tool_name == "read_file")
    assert read_finding.severity == Severity.CRITICAL
    assert read_finding.confidence == "confirmed"
    assert "sentinel-file" in read_finding.detail
