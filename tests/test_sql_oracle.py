"""Tests for SQL injection oracle confirming vulnerabilities by effect."""

import json
import re
import pytest

from mcpsec.scanners.oracles.command_injection import OracleResult
from mcpsec.scanners.oracles.sql_injection import confirm_sqli, confirm_sqli_sync
from mcpsec.scanners.sql_rce import SQLInjectionRCEScanner
from tests.servers.vulnerable_sql_server import handle_call_tool


async def live_fixture_call_fn(tool_name: str, args: dict) -> tuple[str, float]:
    """Call tool handler from the vulnerable SQL test server."""
    res = await handle_call_tool(tool_name, args)
    text = res[0].text if res else ""
    return text, 0.05


@pytest.mark.asyncio
async def test_boolean_positive_confirmed():
    """Boolean positive: query_users -> confirmed=True, method='boolean-differential'."""
    result: OracleResult = await confirm_sqli(
        call_fn=live_fixture_call_fn,
        tool_name="query_users",
        param_name="name",
        base_args={"name": "alice"},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is True
    assert result.method == "boolean-differential"
    assert "boolean-differential" in result.evidence.lower()
    assert result.payload


@pytest.mark.asyncio
async def test_boolean_safe_negative_not_confirmed():
    """Boolean safe negative: safe_search (parameterized) -> confirmed=False."""
    result: OracleResult = await confirm_sqli(
        call_fn=live_fixture_call_fn,
        tool_name="safe_search",
        param_name="q",
        base_args={"q": "alice"},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no sql injection confirmed" in result.evidence.lower()


@pytest.mark.asyncio
async def test_reflection_negative_not_confirmed():
    """Reflection negative: reflect_query echoes the payload -> confirmed=False."""
    result: OracleResult = await confirm_sqli(
        call_fn=live_fixture_call_fn,
        tool_name="reflect_query",
        param_name="q",
        base_args={"q": "test"},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no sql injection confirmed" in result.evidence.lower()


@pytest.mark.asyncio
async def test_no_error_fp_guard_n8n_case():
    """No-error FP guard: static doc search returns with no error and no differential -> NO finding."""
    async def n8n_call_fn(tool_name: str, args: dict) -> tuple[str, float]:
        # Simulates a SQLite-backed doc search server (e.g. n8n-mcp) returning static search results
        return json.dumps([{"title": "Webhooks Guide", "content": "How to configure webhooks in n8n"}]), 0.02

    result: OracleResult = await confirm_sqli(
        call_fn=n8n_call_fn,
        tool_name="search_docs",
        param_name="query",
        base_args={"query": "webhook"},
        baseline_latency_ms=20.0,
    )

    assert result.confirmed is False
    assert result.method is None

    # Regression check: verify scanner classifier does NOT claim RCE from absence of an error
    scanner = SQLInjectionRCEScanner()
    normal_response = json.dumps([{"title": "Webhooks Guide", "content": "How to configure webhooks in n8n"}])
    sev, ev = scanner._classify_rce_result(
        response=normal_response,
        attack_type="rce",
        payload="'; COPY cmd_exec TO PROGRAM 'id'-- -",
    )
    assert sev is None
    assert ev == ""

    # Also test file_write and webshell attack types
    for atk in ("file_write", "webshell"):
        sev, ev = scanner._classify_rce_result(
            response=normal_response,
            attack_type=atk,
            payload="'; SELECT 1-- -",
        )
        assert sev is None
        assert ev == ""


@pytest.mark.asyncio
async def test_time_positive_confirmed():
    """Time positive: call_fn sleeps scaled with requested duration -> confirmed=True, method='time-based'."""
    def mock_time_call(tool_name: str, args: dict) -> tuple[str, float]:
        q = args.get("q", "")
        m = re.search(r"(?:sleep|pg_sleep|dbms_lock\.sleep)\s*\(\s*['\"]?(\d+)", q, re.I)
        if m:
            dur = float(m.group(1))
            return f"Query returned after {dur}s", dur
        return "Query completed", 0.05

    result: OracleResult = await confirm_sqli(
        call_fn=mock_time_call,
        tool_name="slow_query",
        param_name="q",
        base_args={"q": "test"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is True
    assert result.method == "time-based"
    assert "delay confirmed" in result.evidence.lower()
    assert result.payload


@pytest.mark.asyncio
async def test_time_negative_uniformly_slow_not_confirmed():
    """Time negative: uniformly slow responses not scaling with duration -> confirmed=False."""
    def flat_slow_call(tool_name: str, args: dict) -> tuple[str, float]:
        # Always returns flat 6.0 seconds regardless of payload sleep duration
        return "Slow database response", 6.0

    result: OracleResult = await confirm_sqli(
        call_fn=flat_slow_call,
        tool_name="flat_slow_query",
        param_name="q",
        base_args={"q": "test"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no sql injection confirmed" in result.evidence.lower()


def test_confirm_sqli_sync_works():
    """confirm_sqli_sync works correctly from synchronous callers."""
    result: OracleResult = confirm_sqli_sync(
        call_fn=live_fixture_call_fn,
        tool_name="query_users",
        param_name="name",
        base_args={"name": "alice"},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is True
    assert result.method == "boolean-differential"
