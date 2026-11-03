"""Tests for deserialization oracle confirming vulnerabilities by effect."""

import re
import pytest

pytest.importorskip("yaml")  # test fixture needs PyYAML; skip cleanly if unavailable

from mcpsec.scanners.oracles.command_injection import OracleResult
from mcpsec.scanners.oracles.deserialization import (
    confirm_deserialization,
    confirm_deserialization_sync,
)
from tests.servers.vulnerable_deser_server import handle_call_tool


def mock_load_config_time_call(tool_name: str, args: dict) -> tuple[str, float]:
    """Simulate load_config constructing time.sleep objects and executing scaled delay."""
    data = args.get("data", "")
    m = re.search(r"sleep\s*(?:\[\s*(\d+)|\"\s*sleep\s+(\d+))", data, re.I)
    if m:
        dur = float(m.group(1) or m.group(2) or 5)
        return "Config loaded: NoneType", dur
    return "Config loaded", 0.05


@pytest.mark.asyncio
async def test_time_positive_confirmed():
    """Time positive: load_config (UnsafeLoader) with scaled sleep payload -> confirmed=True, method='time-based'."""
    result: OracleResult = await confirm_deserialization(
        call_fn=mock_load_config_time_call,
        tool_name="load_config",
        param_name="data",
        base_args={"data": "test"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is True
    assert result.method == "time-based"
    assert "scaled time-based delay confirmed" in result.evidence.lower()
    assert result.payload


@pytest.mark.asyncio
async def test_safe_negative_not_confirmed():
    """Safe negative: safe_load_config rejects python tags without executing -> confirmed=False."""
    async def safe_call_fn(tool_name: str, args: dict) -> tuple[str, float]:
        res = await handle_call_tool(tool_name, args)
        text = res[0].text if res else ""
        return text, 0.01

    result: OracleResult = await confirm_deserialization(
        call_fn=safe_call_fn,
        tool_name="safe_load_config",
        param_name="data",
        base_args={"data": "key: value"},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no unsafe deserialization confirmed" in result.evidence.lower()


@pytest.mark.asyncio
async def test_reflection_negative_not_confirmed():
    """Reflection negative (critical, n8n regression): reflect_config echoes payload -> confirmed=False."""
    async def reflect_call_fn(tool_name: str, args: dict) -> tuple[str, float]:
        res = await handle_call_tool(tool_name, args)
        text = res[0].text if res else ""
        return text, 0.01

    result: OracleResult = await confirm_deserialization(
        call_fn=reflect_call_fn,
        tool_name="reflect_config",
        param_name="data",
        base_args={"data": '!!python/object/apply:str ["mcpsec_yaml_success"]'},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no unsafe deserialization confirmed" in result.evidence.lower()


@pytest.mark.asyncio
async def test_parse_error_negative_not_confirmed():
    """Parse-error negative: tool returns ConstructorError/parse error without executing -> confirmed=False."""
    def parse_error_call_fn(tool_name: str, args: dict) -> tuple[str, float]:
        # Simulates a parser returning a ConstructorError without running unsafe construction
        return (
            "yaml.constructor.ConstructorError: could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply:time.sleep'",
            0.01,
        )

    result: OracleResult = await confirm_deserialization(
        call_fn=parse_error_call_fn,
        tool_name="parse_error_tool",
        param_name="data",
        base_args={"data": "test"},
        baseline_latency_ms=10.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no unsafe deserialization confirmed" in result.evidence.lower()


@pytest.mark.asyncio
async def test_time_negative_uniformly_slow_not_confirmed():
    """Time negative: uniformly slow responses not scaling with duration -> confirmed=False."""
    def flat_slow_call_fn(tool_name: str, args: dict) -> tuple[str, float]:
        # Always returns flat 6.0 seconds regardless of payload sleep duration
        return "Slow YAML parser response", 6.0

    result: OracleResult = await confirm_deserialization(
        call_fn=flat_slow_call_fn,
        tool_name="flat_slow_tool",
        param_name="data",
        base_args={"data": "test"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "no unsafe deserialization confirmed" in result.evidence.lower()


def test_confirm_deserialization_sync_works():
    """confirm_deserialization_sync works correctly from synchronous callers."""
    result: OracleResult = confirm_deserialization_sync(
        call_fn=mock_load_config_time_call,
        tool_name="load_config",
        param_name="data",
        base_args={"data": "test"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is True
    assert result.method == "time-based"
