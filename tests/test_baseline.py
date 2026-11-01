"""Tests for baseline-differential response analyzer (mcpsec/fuzzer/baseline.py)."""

from mcpsec.fuzzer.baseline import (
    ToolBaseline,
    Verdict,
    build_baseline,
    classify,
    normalize_shape,
)
from mcpsec.fuzzer.fuzz_engine import FuzzEngine
from mcpsec.fuzzer.generators.base import FuzzCase
from mcpsec.fuzzer.generators.schema_fuzzer import build_valid_arguments
from mcpsec.fuzzer.transport.stdio_fuzzer import FuzzResult


def test_normalize_shape_identical_for_different_scalars():
    """Returns the same signature for responses with identical structure but different values."""
    r1 = (
        '{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "hello"}], '
        '"count": 42, "active": true}}'
    )
    r2 = (
        '{"id": 999, "jsonrpc": "2.0", "result": {"active": false, "count": 0, '
        '"content": [{"text": "world", "type": "text"}]}}'
    )
    shape1 = normalize_shape(r1)
    shape2 = normalize_shape(r2)
    assert shape1 == shape2
    assert "text" in shape1
    assert "count" in shape1


def test_normalize_shape_different_for_different_structures():
    """normalize_shape returns different signatures for different response structures."""
    success_resp = (
        '{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}'
    )
    error_resp = (
        '{"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}}'
    )
    assert normalize_shape(success_resp) != normalize_shape(error_resp)


def test_build_valid_arguments():
    """build_valid_arguments populates valid values based on schema properties."""
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "default": "search_term"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "flags": {"type": "array", "items": {"type": "string"}},
            "active": {"type": "boolean"},
        },
        "required": ["query"],
    }
    args = build_valid_arguments(schema)
    assert args["query"] == "search_term"
    assert isinstance(args["limit"], int)
    assert isinstance(args["flags"], list)
    assert isinstance(args["active"], bool)


def test_build_baseline_produces_fingerprint():
    """build_baseline produces a fingerprint from benign responses via mock send_fn."""
    tool = {
        "name": "lookup_user",
        "description": "Finds a user",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
            },
            "required": ["user_id"],
        },
    }

    call_count = 0
    resp = (
        b'{"jsonrpc": "2.0", "id": 1, "result": {"content": '
        b'[{"type": "text", "text": "user_found"}]}}'
    )

    def mock_send(payload: bytes) -> FuzzResult:
        nonlocal call_count
        call_count += 1
        return FuzzResult(
            test_id=call_count,
            generator="baseline",
            payload=payload,
            response=resp,
            elapsed_ms=25.0,
            crashed=False,
            timeout=False,
        )

    baseline = build_baseline(tool, mock_send)
    assert call_count == 3
    assert baseline.tool_name == "lookup_user"
    assert baseline.ok is True
    assert baseline.error_codes == set()
    assert baseline.baseline_latency_ms == 25.0
    assert baseline.size_range[0] > 0
    assert baseline.response_shape == normalize_shape(resp.decode())


def test_classify_returns_transport_reject_for_32602():
    """classify returns TRANSPORT_REJECT for a JSON-RPC -32602 response."""
    baseline = ToolBaseline(
        tool_name="lookup_user",
        ok=True,
        error_codes=set(),
        response_shape=(
            '{"id":"int","jsonrpc":"str","result":{"content":[{"text":"str","type":"str"}]}}'
        ),
        size_range=(50, 100),
        baseline_latency_ms=20.0,
        error_signature="",
    )

    payload = (
        b'{"jsonrpc": "2.0", "id": 2, "method": "tools/call", '
        b'"params": {"name": "lookup_user", "arguments": {"user_id": 123}}}'
    )
    response = (
        b'{"jsonrpc": "2.0", "id": 2, "error": {"code": -32602, '
        b'"message": "Invalid params: user_id must be string"}}'
    )
    res = FuzzResult(
        test_id=1,
        generator="schema_fuzzer",
        payload=payload,
        response=response,
        elapsed_ms=10.0,
        crashed=False,
        timeout=False,
    )

    verdict, reason = classify(res, baseline, res.payload)
    assert verdict == Verdict.TRANSPORT_REJECT
    assert "safe error" in reason.lower() or "-32602" in reason or "32602" in reason


def test_classify_returns_transport_reject_for_mcp_validation_error():
    """classify returns TRANSPORT_REJECT for schema validation error in tool result."""
    baseline = ToolBaseline(
        tool_name="lookup_user",
        ok=True,
        error_codes=set(),
        response_shape=(
            '{"id":"int","jsonrpc":"str","result":{"content":[{"text":"str","type":"str"}]}}'
        ),
        size_range=(50, 100),
        baseline_latency_ms=20.0,
        error_signature="",
    )

    payload = (
        b'{"jsonrpc": "2.0", "id": 3, "method": "tools/call", '
        b'"params": {"name": "lookup_user", "arguments": {"user_id": 123}}}'
    )
    response = (
        b'{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text",'
        b'"text":"Input validation error: 123 is not of type \'string\'"}],"isError":true}}'
    )
    res = FuzzResult(
        test_id=2,
        generator="schema_fuzzer",
        payload=payload,
        response=response,
        elapsed_ms=15.0,
        crashed=False,
        timeout=False,
    )

    verdict, reason = classify(res, baseline, res.payload)
    assert verdict == Verdict.TRANSPORT_REJECT


def test_classify_returns_deviation_when_payload_token_reflected():
    """classify returns DEVIATION when a unique payload token is reflected in response."""
    baseline = ToolBaseline(
        tool_name="lookup_user",
        ok=True,
        error_codes=set(),
        response_shape=(
            '{"id":"int","jsonrpc":"str","result":{"content":[{"text":"str","type":"str"}]}}'
        ),
        size_range=(50, 100),
        baseline_latency_ms=20.0,
        error_signature="",
        benign_samples=['{"result": {"content": [{"type": "text", "text": "standard_result"}]}}'],
    )

    payload = (
        b'{"jsonrpc": "2.0", "id": 10, "method": "tools/call", '
        b'"params": {"name": "lookup_user", "arguments": {"user_id": "CANARY_TOKEN_98765"}}}'
    )
    response = (
        b'{"jsonrpc": "2.0", "id": 10, "result": {"content": '
        b'[{"type": "text", "text": "Echo: CANARY_TOKEN_98765"}]}}'
    )
    res = FuzzResult(
        test_id=10,
        generator="oracle",
        payload=payload,
        response=response,
        elapsed_ms=22.0,
        crashed=False,
        timeout=False,
    )

    verdict, reason = classify(res, baseline, payload)
    assert verdict == Verdict.DEVIATION
    assert "payload reflected" in reason


def test_classify_returns_deviation_for_stacktrace():
    """classify returns DEVIATION for a response containing stacktrace."""
    baseline = ToolBaseline(
        tool_name="lookup_user",
        ok=True,
        error_codes=set(),
        response_shape=(
            '{"id":"int","jsonrpc":"str","result":{"content":[{"text":"str","type":"str"}]}}'
        ),
        size_range=(50, 100),
        baseline_latency_ms=20.0,
        error_signature="",
    )

    response = (
        b'{"jsonrpc": "2.0", "id": 11, "error": {"code": -32603, "message": '
        b'"Internal error: Traceback (most recent call last):\n  File server.py, line 50"}}'
    )
    res = FuzzResult(
        test_id=11,
        generator="injection",
        payload=b'{"bad": "input"}',
        response=response,
        elapsed_ms=18.0,
        crashed=False,
        timeout=False,
    )

    verdict, reason = classify(res, baseline, res.payload)
    assert verdict == Verdict.DEVIATION
    assert "stacktrace" in reason


def test_classify_returns_clean_for_matching_baseline():
    """classify returns CLEAN for a response matching the baseline shape."""
    expected_shape = (
        '{"id":"int","jsonrpc":"str","result":{"content":[{"text":"str","type":"str"}]}}'
    )
    baseline = ToolBaseline(
        tool_name="lookup_user",
        ok=True,
        error_codes=set(),
        response_shape=expected_shape,
        size_range=(50, 150),
        baseline_latency_ms=20.0,
        error_signature="",
    )

    payload = (
        b'{"jsonrpc": "2.0", "id": 12, "method": "tools/call", '
        b'"params": {"name": "lookup_user", "arguments": {"user_id": "other_value"}}}'
    )
    response = (
        b'{"jsonrpc": "2.0", "id": 12, "result": {"content": '
        b'[{"type": "text", "text": "normal_data"}]}}'
    )
    res = FuzzResult(
        test_id=12,
        generator="fuzzer",
        payload=payload,
        response=response,
        elapsed_ms=22.0,
        crashed=False,
        timeout=False,
    )

    verdict, reason = classify(res, baseline, res.payload)
    assert verdict == Verdict.CLEAN
    assert "matches baseline" in reason


def test_integration_engine_interesting_decision():
    """Assert only reflected canary is marked interesting among diverse results."""
    engine = FuzzEngine(command="dummy")
    baseline = ToolBaseline(
        tool_name="test_tool",
        ok=True,
        error_codes=set(),
        response_shape=(
            '{"id":"int","jsonrpc":"str","result":{"content":[{"text":"str","type":"str"}]}}'
        ),
        size_range=(50, 150),
        baseline_latency_ms=20.0,
        error_signature="",
        benign_samples=[
            '{"jsonrpc": "2.0", "id": 1, "result": {"content": '
            '[{"type": "text", "text": "baseline_data"}]}}'
        ],
    )
    engine.baselines["test_tool"] = baseline

    # 1. JSON-RPC -32602 rejection
    reject_payload = (
        b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", '
        b'"params": {"name": "test_tool", "arguments": {"x": 123}}}'
    )
    case_reject = FuzzCase(
        name="schema_test_tool_arg_type_int",
        generator="schema_fuzzer",
        payload=reject_payload,
        description="type int",
        expected_behavior="error",
    )
    res_reject = FuzzResult(
        test_id=1,
        generator="schema_fuzzer",
        payload=case_reject.payload,
        response=(
            b'{"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}}'
        ),
        elapsed_ms=10.0,
        crashed=False,
        timeout=False,
    )

    # 2. Reflected canary
    canary_payload = (
        b'{"jsonrpc": "2.0", "id": 2, "method": "tools/call", '
        b'"params": {"name": "test_tool", "arguments": {"x": "CANARY_INJECT_12345"}}}'
    )
    case_canary = FuzzCase(
        name="oracle_test_tool_canary",
        generator="oracle",
        payload=canary_payload,
        description="canary test",
        expected_behavior="handled",
    )
    canary_response = (
        b'{"jsonrpc": "2.0", "id": 2, "result": {"content": '
        b'[{"type": "text", "text": "Reflected: CANARY_INJECT_12345"}]}}'
    )
    res_canary = FuzzResult(
        test_id=2,
        generator="oracle",
        payload=canary_payload,
        response=canary_response,
        elapsed_ms=15.0,
        crashed=False,
        timeout=False,
    )

    # 3. Clean baseline match
    clean_payload = (
        b'{"jsonrpc": "2.0", "id": 3, "method": "tools/call", '
        b'"params": {"name": "test_tool", "arguments": {"x": "safe_val"}}}'
    )
    case_clean = FuzzCase(
        name="schema_test_tool_arg_benign",
        generator="schema_fuzzer",
        payload=clean_payload,
        description="safe value",
        expected_behavior="handled",
    )
    clean_response = (
        b'{"jsonrpc": "2.0", "id": 3, "result": {"content": '
        b'[{"type": "text", "text": "baseline_data"}]}}'
    )
    res_clean = FuzzResult(
        test_id=3,
        generator="schema_fuzzer",
        payload=case_clean.payload,
        response=clean_response,
        elapsed_ms=18.0,
        crashed=False,
        timeout=False,
    )

    test_cases = [(case_reject, res_reject), (case_canary, res_canary), (case_clean, res_clean)]

    for case, result in test_cases:
        target_tool = engine._get_target_tool_for_case(case)
        bline = engine.baselines.get(target_tool) if target_tool else None
        verdict, reason = classify(result, bline, case.payload)
        result.verdict = verdict.value
        result.verdict_reason = reason
        if verdict == Verdict.DEVIATION:
            engine.interesting.append((case, result))

    # Assert only the reflected-canary is marked interesting
    assert len(engine.interesting) == 1
    flagged_case, flagged_res = engine.interesting[0]
    assert flagged_case.name == "oracle_test_tool_canary"
    assert flagged_res.verdict == Verdict.DEVIATION.value
    assert "payload reflected" in flagged_res.verdict_reason

    # Summarize checks
    summary = engine._summarize(mock_fuzzer_for_summary())
    assert summary["interesting"] == 1
    assert len(summary["interesting_cases"]) == 1
    assert summary["interesting_cases"][0]["verdict"] == Verdict.DEVIATION.value


def mock_fuzzer_for_summary():
    class DummyFuzzer:
        test_count = 3
        crash_count = 0
        timeout_count = 0
        error_log_path = ""

    return DummyFuzzer()
