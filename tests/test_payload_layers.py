"""Tests for payload layers (handler vs transport layer) in schema fuzzer and engine."""

import json
from typing import Any
import pytest

from mcpsec.fuzzer.fuzz_engine import FuzzEngine
from mcpsec.fuzzer.generators import schema_fuzzer
from mcpsec.fuzzer.generators.base import FuzzCase
from mcpsec.fuzzer.transport.stdio_fuzzer import FuzzResult


def _unframe_payload(payload: bytes) -> dict:
    if b"\r\n\r\n" in payload:
        body = payload.split(b"\r\n\r\n", 1)[1]
    elif payload.endswith(b"\n"):
        body = payload.rstrip(b"\n")
    else:
        body = payload
    return json.loads(body.decode("utf-8"))


def _contains_lone_surrogates(obj: Any) -> bool:
    if isinstance(obj, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in obj)
    if isinstance(obj, dict):
        return any(_contains_lone_surrogates(k) or _contains_lone_surrogates(v) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return any(_contains_lone_surrogates(x) for x in obj)
    return False


def _contains_nan_or_inf(obj: Any) -> bool:
    if isinstance(obj, float):
        import math
        return math.isnan(obj) or math.isinf(obj)
    if isinstance(obj, dict):
        return any(_contains_nan_or_inf(k) or _contains_nan_or_inf(v) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return any(_contains_nan_or_inf(x) for x in obj)
    return False


SAMPLE_TOOL = {
    "name": "test_tool",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
            "enabled": {"type": "boolean"},
        },
        "required": ["query"],
    },
}


def test_lone_surrogate_has_transport_layer():
    """The lone-surrogate string case has layer == 'transport'."""
    cases = schema_fuzzer.generate_for_tools([SAMPLE_TOOL], intensity="medium")
    lone_surrogate_cases = [c for c in cases if "unicode_lone_surrogate" in c.name]
    assert len(lone_surrogate_cases) > 0, "Expected unicode_lone_surrogate case to be generated"

    for case in lone_surrogate_cases:
        assert case.layer == "transport", f"Expected case {case.name} to have layer == 'transport', got {case.layer}"


def test_nan_and_inf_have_transport_layer():
    """Special JSON numeric tokens (NaN / Inf) have layer == 'transport'."""
    cases = schema_fuzzer.generate_for_tools([SAMPLE_TOOL], intensity="medium")
    special_number_cases = [
        c for c in cases if any(token in c.name for token in ("nan_token", "infinity_token", "neg_infinity_token"))
    ]
    assert len(special_number_cases) > 0, "Expected NaN/Inf cases to be generated"

    for case in special_number_cases:
        assert case.layer == "transport", f"Expected case {case.name} to have layer == 'transport', got {case.layer}"


def test_handler_layer_payloads_have_no_lone_surrogates_or_nan():
    """Every case with layer == 'handler' produces well-formed arguments reaching the handler."""
    tools = [
        {
            "name": "all_types_tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "str_val": {"type": "string"},
                    "int_val": {"type": "integer"},
                    "bool_val": {"type": "boolean"},
                    "arr_val": {"type": "array", "items": {"type": "string"}},
                    "obj_val": {"type": "object", "properties": {"nested": {"type": "string"}}},
                },
                "required": ["str_val"],
            },
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, intensity="medium")
    handler_cases = [c for c in cases if c.layer == "handler"]
    assert len(handler_cases) > 0, "Expected handler cases to be generated"

    for case in handler_cases:
        data = _unframe_payload(case.payload)
        args = data.get("params", {}).get("arguments", {})
        assert not _contains_lone_surrogates(args), (
            f"Case {case.name} with layer='handler' contains lone surrogate code points: {args}"
        )
        assert not _contains_nan_or_inf(args), (
            f"Case {case.name} with layer='handler' contains NaN or Inf: {args}"
        )


def test_valid_unicode_mutations_preserve_handler_layer():
    """Valid unicode mutations (e.g. 4-byte emoji, fullwidth) remain layer == 'handler'."""
    cases = schema_fuzzer.generate_for_tools([SAMPLE_TOOL], intensity="medium")
    valid_unicode_cases = [
        c for c in cases if any(u in c.name for u in ("unicode_emoji_4byte", "unicode_fullwidth", "unicode_rtl_override"))
    ]
    assert len(valid_unicode_cases) > 0, "Expected valid unicode cases to be generated"

    for case in valid_unicode_cases:
        assert case.layer == "handler", f"Expected {case.name} to have layer == 'handler', got {case.layer}"


class DummyFuzzer:
    def __init__(self, result: FuzzResult):
        self.result = result
        self.framing = "jsonl"
        self.test_count = 1
        self.crash_count = 1 if result.crashed else 0
        self.timeout_count = 1 if result.timeout else 0
        self.error_log_path = None
        self.process = None

    def is_alive(self):
        return True

    def _check_real_crash(self):
        return True, "crash"

    def restart_server(self):
        pass

    def send_raw(self, payload: bytes, headers: dict | None = None):
        return self.result


def test_engine_transport_layer_timeout_classified_transport_reject_not_interesting():
    """An engine-level assertion: a transport-layer case that times out is classified

    TRANSPORT_REJECT and is not in interesting.
    """
    engine = FuzzEngine(command="dummy", timeout=2.0)
    case = FuzzCase(
        name="schema_test_tool_query_unicode_lone_surrogate",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test_tool","arguments":{"query":"\\ud800"}}}\n',
        description="Lone surrogate Unicode code point",
        expected_behavior="Rejection or graceful error handling",
        layer="transport",
    )
    result = FuzzResult(
        test_id=1,
        generator=case.generator,
        payload=case.payload,
        response=None,
        elapsed_ms=2000.0,
        crashed=False,
        timeout=True,
    )
    dummy_fuzzer = DummyFuzzer(result)

    engine._run_generator(dummy_fuzzer, case, framing="jsonl")

    assert result.verdict == "TRANSPORT_REJECT"
    assert result.verdict_reason == "expected transport-layer rejection"
    assert len(engine.interesting) == 0, f"Transport-layer timeout must not be in interesting, found: {engine.interesting}"


def test_engine_transport_layer_clean_reject_not_interesting():
    """A transport-layer case that returns a clean or transport error is not in interesting."""
    engine = FuzzEngine(command="dummy", timeout=2.0)
    case = FuzzCase(
        name="schema_test_tool_query_unicode_lone_surrogate",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test_tool","arguments":{"query":"\\ud800"}}}\n',
        description="Lone surrogate Unicode code point",
        expected_behavior="Rejection or graceful error handling",
        layer="transport",
    )
    result = FuzzResult(
        test_id=1,
        generator=case.generator,
        payload=case.payload,
        response=b'{"jsonrpc":"2.0","id":1,"error":{"code":-32700,"message":"Parse error"}}\n',
        elapsed_ms=10.0,
        crashed=False,
        timeout=False,
    )
    dummy_fuzzer = DummyFuzzer(result)

    engine._run_generator(dummy_fuzzer, case, framing="jsonl")

    assert result.verdict == "TRANSPORT_REJECT"
    assert result.verdict_reason == "expected transport-layer rejection"
    assert len(engine.interesting) == 0


def test_engine_transport_layer_crash_flags_as_interesting():
    """A transport-layer case that crashes the server process is flagged as interesting."""
    engine = FuzzEngine(command="dummy", timeout=2.0)
    case = FuzzCase(
        name="schema_test_tool_query_unicode_lone_surrogate",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test_tool","arguments":{"query":"\\ud800"}}}\n',
        description="Lone surrogate Unicode code point",
        expected_behavior="Rejection or graceful error handling",
        layer="transport",
    )
    result = FuzzResult(
        test_id=1,
        generator=case.generator,
        payload=case.payload,
        response=None,
        elapsed_ms=50.0,
        crashed=True,
        timeout=False,
        error_message="process terminated unexpectedly with code 1",
    )
    dummy_fuzzer = DummyFuzzer(result)

    engine._run_generator(dummy_fuzzer, case, framing="jsonl")

    assert result.verdict == "DEVIATION"
    assert len(engine.interesting) == 1
    assert engine.interesting[0] == (case, result)


def test_engine_transport_layer_stacktrace_flags_as_interesting():
    """A transport-layer case that returns a stacktrace is flagged as interesting."""
    engine = FuzzEngine(command="dummy", timeout=2.0)
    case = FuzzCase(
        name="schema_test_tool_query_unicode_lone_surrogate",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test_tool","arguments":{"query":"\\ud800"}}}\n',
        description="Lone surrogate Unicode code point",
        expected_behavior="Rejection or graceful error handling",
        layer="transport",
    )
    result = FuzzResult(
        test_id=1,
        generator=case.generator,
        payload=case.payload,
        response=b'HTTP/1.1 500 Internal Server Error\r\n\r\nTraceback (most recent call last):\n  File "server.py", line 12\nValueError',
        elapsed_ms=50.0,
        crashed=False,
        timeout=False,
    )
    dummy_fuzzer = DummyFuzzer(result)

    engine._run_generator(dummy_fuzzer, case, framing="jsonl")

    assert result.verdict == "DEVIATION"
    assert result.verdict_reason == "stacktrace in response"
    assert len(engine.interesting) == 1
    assert engine.interesting[0] == (case, result)


def test_engine_handler_layer_timeout_remains_interesting():
    """A handler-layer case that times out is treated as DEVIATION and is interesting."""
    engine = FuzzEngine(command="dummy", timeout=2.0)
    case = FuzzCase(
        name="schema_test_tool_query_length_huge",
        generator="schema_fuzzer",
        payload=b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"test_tool","arguments":{"query":"AAAA"}}}\n',
        description="Huge string",
        expected_behavior="Handled cleanly without crash",
        layer="handler",
    )
    result = FuzzResult(
        test_id=1,
        generator=case.generator,
        payload=case.payload,
        response=None,
        elapsed_ms=2000.0,
        crashed=False,
        timeout=True,
    )
    dummy_fuzzer = DummyFuzzer(result)

    engine._run_generator(dummy_fuzzer, case, framing="jsonl")

    assert result.verdict == "DEVIATION"
    assert result.verdict_reason == "request timeout"
    assert len(engine.interesting) == 1
    assert engine.interesting[0] == (case, result)
