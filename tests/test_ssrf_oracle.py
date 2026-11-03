"""Unit and integration tests for the SSRF Oracle and OOB Collector."""

import asyncio
import time
import urllib.parse
import urllib.request
from unittest.mock import AsyncMock
import pytest

from mcpsec.models import ResourceInfo, ServerProfile, Severity, ToolInfo
from mcpsec.scanners.oracles import (
    OOBCollector,
    OracleResult,
    confirm_ssrf,
)
from mcpsec.scanners.oracles.ssrf import confirm_ssrf_sync
from mcpsec.scanners.resource_ssrf import ResourceSSRFScanner
from mcpsec.scanners.ssrf import SSRFScanner


def test_collector_unit():
    """Collector unit: probe minting, manual HTTP GET recording, hit retrieval, bound port."""
    with OOBCollector() as collector:
        assert collector.port > 0
        assert collector.bind_host == "127.0.0.1"

        token1, url1 = collector.new_probe()
        token2, url2 = collector.new_probe()

        assert token1 != token2
        assert url1 != url2
        assert f":{collector.port}/{token1}" in url1
        assert f":{collector.port}/{token2}" in url2

        # Verify received returns None before any hit
        assert collector.received(token1, settle=0.05) is None
        assert collector.received("unknown_token", settle=0.05) is None

        # Manual HTTP GET to url1
        req = urllib.request.Request(url1, headers={"User-Agent": "mcpsec-test-agent"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            body = resp.read()
            assert resp.status == 200
            assert body == b"OK"

        # Hit should now be recorded
        hit = collector.received(token1, settle=1.0)
        assert hit is not None
        assert hit["token"] == token1
        assert hit["method"] == "GET"
        assert f"/{token1}" in hit["path"]
        assert hit["source_ip"] in ("127.0.0.1", "::1", "localhost")
        assert "timestamp" in hit

        # token2 should still have no hit
        assert collector.received(token2, settle=0.05) is None


def test_collector_advertise_host():
    """When advertise_host is routable, collector binds 0.0.0.0 and advertises that host."""
    collector = OOBCollector(advertise_host="192.168.1.100")
    assert collector.bind_host == "0.0.0.0"
    assert collector.advertise_host == "192.168.1.100"

    collector_local = OOBCollector(advertise_host="127.0.0.1")
    assert collector_local.bind_host == "127.0.0.1"
    assert collector_local.advertise_host == "127.0.0.1"


@pytest.mark.asyncio
async def test_confirm_ssrf_positive():
    """Positive: a call_fn that actually GETs the injected URL -> confirm_ssrf confirmed."""
    with OOBCollector() as collector:

        async def call_fn(tool_name: str, args: dict):
            url = args.get("url", "")
            try:
                with urllib.request.urlopen(url, timeout=3.0) as resp:
                    return f"fetched status={resp.status}", 0.05
            except Exception as e:
                return f"fetch error: {e}", 0.05

        result: OracleResult = await confirm_ssrf(
            call_fn=call_fn,
            tool_name="fetch_url",
            param_name="url",
            base_args={"url": "default"},
            collector=collector,
            settle_seconds=2.0,
        )

        assert result.confirmed is True
        assert result.method == "oob-http"
        assert "Out-of-band HTTP request received" in result.evidence
        assert result.payload.startswith(f"http://127.0.0.1:{collector.port}/")


@pytest.mark.asyncio
async def test_confirm_ssrf_reflection_negative():
    """Reflection negative (critical): call_fn returns URL in response but never fetches -> NOT confirmed."""
    with OOBCollector() as collector:

        async def call_fn(tool_name: str, args: dict):
            url = args.get("url", "")
            return f"Reflected URL: {url}", 0.01

        result: OracleResult = await confirm_ssrf(
            call_fn=call_fn,
            tool_name="reflect_url",
            param_name="url",
            base_args={"url": "default"},
            collector=collector,
            settle_seconds=0.3,
        )

        assert result.confirmed is False
        assert result.method is None
        assert "No out-of-band HTTP request received" in result.evidence


@pytest.mark.asyncio
async def test_confirm_ssrf_safe_negative():
    """Safe negative: a call_fn that never fetches -> NOT confirmed."""
    with OOBCollector() as collector:

        async def call_fn(tool_name: str, args: dict):
            return "Error: host not allowed", 0.01

        result: OracleResult = await confirm_ssrf(
            call_fn=call_fn,
            tool_name="safe_fetch",
            param_name="url",
            base_args={"url": "default"},
            collector=collector,
            settle_seconds=0.3,
        )

        assert result.confirmed is False
        assert result.method is None
        assert "No out-of-band HTTP request received" in result.evidence


def test_confirm_ssrf_sync_positive():
    """Sync helper confirm_ssrf_sync confirms out-of-band HTTP interaction."""
    with OOBCollector() as collector:

        def call_fn(tool_name: str, args: dict):
            url = args.get("url", "")
            with urllib.request.urlopen(url, timeout=3.0) as resp:
                return f"status={resp.status}", 0.05

        result: OracleResult = confirm_ssrf_sync(
            call_fn=call_fn,
            tool_name="fetch_url",
            param_name="url",
            base_args={},
            collector=collector,
            settle_seconds=2.0,
        )

        assert result.confirmed is True
        assert result.method == "oob-http"


@pytest.mark.asyncio
async def test_ssrf_scanner_tools_e2e():
    """End-to-end test of SSRFScanner distinguishing fetch_url from reflect_url."""
    mock_client = AsyncMock()

    async def mock_call_tool(tool_name: str, args: dict):
        class MockResult:

            def __init__(self, text: str):
                class Block:

                    def __init__(self, t: str):
                        self.text = t

                self.content = [Block(text)]
                self.isError = False

        url = args.get("url", "")
        if tool_name == "fetch_url":
            try:
                with urllib.request.urlopen(url, timeout=3.0) as resp:
                    return MockResult(f"Status: {resp.status}")
            except Exception as e:
                return MockResult(f"Error: {e}")
        elif tool_name == "reflect_url":
            return MockResult(f"Reflected URL: {url}")
        return MockResult("Unknown tool")

    mock_client.call_tool = mock_call_tool

    profile = ServerProfile(
        server_name="test_server",
        tools=[
            ToolInfo(
                name="fetch_url",
                description="Fetch a URL",
                parameters={"url": {"type": "string"}},
                raw_schema={
                    "inputSchema": {
                        "properties": {"url": {"type": "string", "format": "uri"}}
                    }
                },
            ),
            ToolInfo(
                name="reflect_url",
                description="Reflect a URL",
                parameters={"url": {"type": "string"}},
                raw_schema={
                    "inputSchema": {
                        "properties": {"url": {"type": "string", "format": "uri"}}
                    }
                },
            ),
        ],
    )

    scanner = SSRFScanner()
    findings = await scanner.scan(profile, mock_client)

    tool_names = [f.tool_name for f in findings]
    assert "fetch_url" in tool_names
    assert "reflect_url" not in tool_names

    fetch_finding = next(f for f in findings if f.tool_name == "fetch_url")
    assert fetch_finding.severity == Severity.CRITICAL
    assert fetch_finding.confidence == "confirmed"
    assert "oob-http" in fetch_finding.detail


@pytest.mark.asyncio
async def test_resource_ssrf_scanner_no_bare_response():
    """ResourceSSRFScanner does NOT raise any finding for bare response without indicators."""
    mock_client = AsyncMock()
    mock_session = AsyncMock()

    class MockReadResult:

        class Content:
            text = "Normal resource content with no sensitive data"

        contents = [Content()]

    mock_session.read_resource = AsyncMock(return_value=MockReadResult())
    mock_client.session = mock_session

    profile = ServerProfile(
        server_name="test_server",
        resources=[
            ResourceInfo(
                uri="http://example.com/api/get?url={url}",
                name="fetch_resource",
                description="Fetches a remote URL",
            ),
        ],
    )

    scanner = ResourceSSRFScanner()
    findings = await scanner.scan(profile, mock_client)

    # Since neither OOB hit nor cloud metadata matched, no finding should be raised
    assert len(findings) == 0
