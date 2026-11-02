"""Unit and integration tests for the Command Injection Oracle."""

import asyncio
import re
import pytest

from mcpsec.scanners.oracles.command_injection import (
    OracleResult,
    confirm_command_injection,
    confirm_command_injection_sync,
)


@pytest.mark.asyncio
async def test_canary_execution_confirmed():
    """Canary path: a call_fn that returns the nonce (simulating execution) yields confirmed=True, method='canary'."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        # Simulate shell execution of `echo <token>` -> output contains only the token
        m = re.search(r"echo\s+([A-Za-z0-9_]+)", cmd)
        if m:
            token = m.group(1)
            return f"Command output:\n{token}\n", 0.05
        return "Command completed", 0.05

    result: OracleResult = await confirm_command_injection(
        call_fn=call_fn,
        tool_name="cmd_tool",
        param_name="cmd",
        base_args={"cmd": "default"},
        baseline_latency_ms=50.0,
    )

    assert result.confirmed is True
    assert result.method == "canary"
    assert "mcpsec_" in result.evidence
    assert "; echo" in result.payload or "echo" in result.payload


@pytest.mark.asyncio
async def test_reflection_guard_not_confirmed():
    """Reflection guard: a call_fn that returns the full payload string verbatim

    (including '; echo') yields confirmed=False. This is the critical false-positive test.
    """

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        # Simulates a formatter or echo tool returning the verbatim payload
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
async def test_timing_differential_path_confirmed():
    """Timing path: a call_fn that sleeps for D seconds yields confirmed=True, method='timing'."""

    def call_fn(tool_name: str, args: dict):
        cmd = args.get("cmd", "")
        # Simulate shell executing sleep D
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
async def test_uniformly_slow_server_yields_false():
    """A call_fn that is uniformly slow (e.g. 6.0s on all requests) but does not scale with D

    yields confirmed=False.
    """

    def call_fn(tool_name: str, args: dict):
        # Always slow regardless of injected payload
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


@pytest.mark.asyncio
async def test_baseline_integration_scales_threshold():
    """Baseline integration: timing threshold is derived from the passed baseline latency,

    not a hardcoded 5.0s threshold.
    """

    # If baseline is 4.0s (4000ms), a 5.0s response is just normal latency jitter, not command execution!
    def call_fn(tool_name: str, args: dict):
        return "Normal server delay", 5.0

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
        m = re.search(r"echo\s+([A-Za-z0-9_]+)", cmd)
        if m:
            return m.group(1), 0.01
        return "", 0.01

    res = confirm_command_injection_sync(
        call_fn=call_fn,
        tool_name="sync_tool",
        param_name="cmd",
        base_args={"cmd": "test"},
        baseline_latency_ms=10.0,
    )
    assert res.confirmed is True
    assert res.method == "canary"


def test_fuzzer_differential_escalation_positive():
    """Fuzzer differential escalates cmdi deviation to confirmed finding via oracle."""
    import json
    from mcpsec.fuzzer.fuzz_engine import FuzzEngine
    from mcpsec.fuzzer.baseline import ToolBaseline, Verdict
    from mcpsec.fuzzer.generators.base import FuzzCase
    from mcpsec.fuzzer.transport.stdio_fuzzer import FuzzResult

    engine = FuzzEngine(command="dummy", timeout=2.0)
    bline = ToolBaseline(
        tool_name="exec_tool",
        ok=True,
        error_codes=set(),
        response_shape="{}",
        size_range=(10, 50),
        baseline_latency_ms=20.0,
        error_signature="",
        benign_samples=["Benign response"],
    )
    engine.baselines["exec_tool"] = bline

    case = FuzzCase(
        name="schema_exec_tool_cmd_cmdi_semicolon",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"exec_tool","arguments":{"cmd":"; echo pwned"}}}\n',
        description="Command injection semicolon ; echo pwned",
        expected_behavior="Handled cleanly",
    )

    class ShellFuzzer:
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
            m = re.search(r"echo\s+([A-Za-z0-9_]+)", cmd)
            if m:
                resp = f'{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"{m.group(1)}\\n"}}]}}}}\n'.encode()
            else:
                resp = f'{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"pwned\\n"}}]}}}}\n'.encode()
            return FuzzResult(test_id=1, generator=case.generator, payload=payload, response=resp, elapsed_ms=25.0, crashed=False, timeout=False)

    fuzzer = ShellFuzzer()
    engine._run_generator(fuzzer, case, framing="jsonl")

    assert len(engine.interesting) == 1
    flagged_case, flagged_res = engine.interesting[0]
    assert flagged_res.verdict == Verdict.DEVIATION.value
    assert "confirmed command injection" in flagged_res.verdict_reason


def test_fuzzer_differential_escalation_negative_reflection_dropped():
    """Fuzzer differential drops reflection-only cmdi deviation when oracle does not confirm."""
    import json
    from mcpsec.fuzzer.fuzz_engine import FuzzEngine
    from mcpsec.fuzzer.baseline import ToolBaseline, Verdict
    from mcpsec.fuzzer.generators.base import FuzzCase
    from mcpsec.fuzzer.transport.stdio_fuzzer import FuzzResult

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
            resp = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": f"Echo: {cmd}"}]}}).encode() + b"\n"
            return FuzzResult(test_id=1, generator=case.generator, payload=payload, response=resp, elapsed_ms=25.0, crashed=False, timeout=False)

    fuzzer = EchoFuzzer()
    engine._run_generator(fuzzer, case, framing="jsonl")

    assert len(engine.interesting) == 0
    assert engine.results[-1].verdict == Verdict.CLEAN.value
    assert "reflection only" in engine.results[-1].verdict_reason
