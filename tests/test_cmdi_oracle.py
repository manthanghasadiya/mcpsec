"""Unit and integration tests for the Command Injection Oracle."""

import asyncio
import inspect
import json
import re
from unittest.mock import AsyncMock
import pytest

from mcpsec.scanners.oracles.command_injection import (
    OracleResult,
    confirm_command_injection,
    confirm_command_injection_sync,
)


@pytest.mark.asyncio
async def test_verbatim_reflector_not_confirmed():
    """Verbatim reflector returns payload unchanged -> confirmed=False."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        return f"Echo output: {cmd}", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="safe_echo_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No command execution confirmed" in result.evidence


@pytest.mark.asyncio
async def test_last_token_reflector_not_confirmed():
    """Last-token reflector returns only the last whitespace-separated token -> confirmed=False."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        tokens = cmd.strip().split()
        last_tok = tokens[-1] if tokens else ""
        return f"Processed: {last_tok}", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="token_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No command execution confirmed" in result.evidence


@pytest.mark.asyncio
async def test_strip_echo_reflector_not_confirmed():
    """Strip-echo reflector removes leading echo / ; echo and returns remainder -> confirmed=False."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        stripped = re.sub(r"^[;\s|&]*(?:echo\s+)?", "", cmd)
        return f"Echo output: {stripped}", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="strip_echo_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No command execution confirmed" in result.evidence


@pytest.mark.asyncio
async def test_executing_fake_arithmetic_expansion_confirmed():
    """Executing fake evaluates $(( ... )) and `expr ...` -> confirmed=True, method='canary'."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")

        def eval_posix(match):
            expr = match.group(1).replace(" ", "")
            a, b = expr.split("+")
            return str(int(a) + int(b))

        def eval_expr(match):
            a, b = match.group(1), match.group(2)
            return str(int(a) + int(b))

        executed = re.sub(r"\$\(\(\s*([^)]+?)\s*\)\)", eval_posix, cmd)
        executed = re.sub(r"`expr\s+(\d+)\s*\+\s*(\d+)`", eval_expr, executed)
        return f"Shell output: {executed}\n", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="cmd_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is True
    assert result.method == "canary"
    assert "arithmetic canary:" in result.evidence
    m = re.search(
        r"arithmetic canary:\s*(\d+)\s*\+\s*(\d+)\s*evaluated to\s*(\d+)",
        result.evidence,
    )
    assert m is not None, f"Expected arithmetic details in evidence: {result.evidence}"
    a, b, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
    assert a + b == s


@pytest.mark.asyncio
async def test_metachar_sanitizer_reflector_not_confirmed():
    """Metachar-sanitizer reflector strips $ ( ) ` and echoes remainder -> confirmed=False."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        # Sanitizes input by stripping shell metacharacters: $, (, ), `
        sanitized = re.sub(r"[\$\(\)`]", "", cmd)
        return f"Echo output: {sanitized}", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="sanitizing_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No command execution confirmed" in result.evidence


@pytest.mark.asyncio
async def test_timing_positive_confirmed():
    """Timing positive: call_fn sleeps for D seconds -> confirmed=True, method='timing'."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        m = re.search(r"sleep\s+(\d+)", cmd)
        if m:
            d = float(m.group(1))
            return "Sleep completed", d
        return "Success", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="blind_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=100.0,
    )

    assert result.confirmed is True
    assert result.method == "timing"
    assert "differential delay confirmed" in result.evidence.lower()
    assert "sleep" in result.payload


@pytest.mark.asyncio
async def test_timing_negative_uniformly_slow_not_confirmed():
    """Timing negative: call_fn uniformly slow but not scaling with D -> confirmed=False."""

    def call_fn(tool_name: str, args: dict):
        return "Slow response", 6.0

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="slow_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=100.0,
    )

    assert result.confirmed is False
    assert result.method is None
    assert "No command execution confirmed" in result.evidence


@pytest.mark.asyncio
async def test_baseline_integration_scales_threshold():
    """Baseline integration: timing threshold scales with baseline latency."""

    def call_fn(tool_name: str, args: dict):
        return "Normal delay", 5.0

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="heavy_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=4000.0,
    )

    assert result.confirmed is False


def test_sync_helper():
    """confirm_command_injection_sync works correctly from synchronous callers."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")

        def eval_posix(match):
            expr = match.group(1).replace(" ", "")
            a, b = expr.split("+")
            return str(int(a) + int(b))

        executed = re.sub(r"\$\(\(\s*([^)]+?)\s*\)\)", eval_posix, cmd)
        return executed, 0.01

    res = confirm_command_injection_sync(
        call_fn=call_fn,
        tool_name="sync_tool",
        param_name="cmd",
        base_args={"cmd": "test"},
        baseline_latency_ms=10.0,
    )
    assert res.confirmed is True
    assert res.method == "canary"


@pytest.mark.asyncio
async def test_scan_path_oracle_deduped(monkeypatch):
    """Scan path: oracle is invoked at most once per (tool, param) even when many payloads reflect."""
    from mcpsec.models import ServerProfile, ToolInfo
    from mcpsec.scanners.command_injection import CommandInjectionScanner
    import mcpsec.scanners.command_injection as cmdi_mod

    scanner = CommandInjectionScanner()

    tool = ToolInfo(
        name="reflect_tool",
        description="A tool that reflects everything",
        parameters={"text": {"type": "string"}},
        raw_schema={"inputSchema": {"properties": {"text": {"type": "string"}}}},
    )
    profile = ServerProfile(
        server_name="test_server",
        tools=[tool],
    )

    client = AsyncMock()

    async def mock_call_tool(tool_name, args):
        val = args.get("text", "")

        class MockContent:
            type = "text"
            text = f"Reflected: {val}"

        class MockResult:
            content = [MockContent()]

        return MockResult()

    client.call_tool = AsyncMock(side_effect=mock_call_tool)

    oracle_call_count = 0
    real_confirm = cmdi_mod.confirm_command_injection

    async def counting_oracle(*args, **kwargs):
        nonlocal oracle_call_count
        oracle_call_count += 1
        return await real_confirm(*args, **kwargs)

    monkeypatch.setattr(cmdi_mod, "confirm_command_injection", counting_oracle)

    findings = await scanner.scan(profile, client)

    # In PR #31 before dedupe, reflecting tools triggered the oracle ~150 times.
    # Now it must be invoked at most once per (tool, param).
    assert oracle_call_count <= 1
    assert len(findings) == 0


def test_fuzzer_decoupled_and_deviation_preserved():
    """Fuzzer test: fuzz_engine no longer imports/calls oracle, and reflected DEVIATION stays DEVIATION."""
    import mcpsec.fuzzer.fuzz_engine as fe
    from mcpsec.fuzzer.fuzz_engine import FuzzEngine
    from mcpsec.fuzzer.baseline import ToolBaseline, Verdict
    from mcpsec.fuzzer.generators.base import FuzzCase
    from mcpsec.fuzzer.transport.stdio_fuzzer import FuzzResult

    # 1. Assert fuzz_engine does not import or contain confirm_command_injection
    source = inspect.getsource(fe)
    assert "confirm_command_injection" not in source
    assert not hasattr(fe, "confirm_command_injection")
    assert not hasattr(fe, "confirm_command_injection_sync")

    # 2. Assert reflected payload DEVIATION stays a DEVIATION (not cleared to CLEAN)
    engine = FuzzEngine(command="dummy", timeout=2.0)
    bline = ToolBaseline(
        tool_name="echo_tool",
        ok=True,
        error_codes=set(),
        response_shape="{}",
        size_range=(10, 50),
        baseline_latency_ms=20.0,
        error_signature="",
        benign_samples=["Benign response"],
    )
    engine.baselines["echo_tool"] = bline

    case = FuzzCase(
        name="schema_echo_tool_cmd_cmdi_semicolon",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"echo_tool","arguments":{"cmd":"; echo pwned"}}}\n',
        description="Command injection semicolon ; echo pwned",
        expected_behavior="Handled cleanly",
    )

    class EchoFuzzer:
        def __init__(self):
            self.framing = "jsonl"
            self.test_count = 1
            self.crash_count = 0
            self.timeout_count = 0
            self.error_log_path = None
            self.process = None

        def is_alive(self):
            return True

        def _check_real_crash(self):
            return False, ""

        def restart_server(self):
            pass

        def send_raw(self, payload: bytes, headers: dict | None = None):
            body = payload.rstrip(b"\n")
            data = json.loads(body)
            cmd = data.get("params", {}).get("arguments", {}).get("cmd", "")
            resp = (
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"content": [{"type": "text", "text": f"Echo: {cmd}"}]},
                }).encode()
                + b"\n"
            )
            return FuzzResult(
                test_id=1,
                generator=case.generator,
                payload=payload,
                response=resp,
                elapsed_ms=25.0,
                crashed=False,
                timeout=False,
            )

    fuzzer = EchoFuzzer()
    engine._run_generator(fuzzer, case, framing="jsonl")

    assert len(engine.interesting) == 1
    flagged_case, flagged_res = engine.interesting[0]
    assert flagged_res.verdict == Verdict.DEVIATION.value
    assert flagged_res.verdict_reason == "payload reflected"
