"""MCP protocol state machine tests — lifecycle, transitions, edge cases."""

import json
from .base import FuzzCase


def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _rpc(method: str, params=None, req_id=1) -> bytes:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def _notif(method: str, params=None) -> bytes:
    msg: dict = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    def _f(body: bytes) -> bytes:
        return _frame(body, framing)

    def _add(name: str, payload: bytes, desc: str):
        cases.append(FuzzCase(name=name, generator="protocol_state",
                              payload=payload, description=desc,
                              expected_behavior="Server handles state correctly"))

    INIT_PARAMS = {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "mcpsec-fuzzer", "version": "1.0.0"},
    }

    # ── Full lifecycle sequences ─────────────────────────────────────
    # Normal: init → initialized → tools/list → tools/call
    lifecycle = (
        _f(_rpc("initialize", INIT_PARAMS, 1)) +
        _f(_notif("notifications/initialized")) +
        _f(_rpc("tools/list", req_id=2)) +
        _f(_rpc("tools/call", {"name": "nonexistent", "arguments": {}}, 3))
    )
    _add("full_lifecycle", lifecycle,
         "Complete init → list → call lifecycle")

    # ── Skip phases ──────────────────────────────────────────────────
    _add("skip_to_call",
         _f(_rpc("tools/call", {"name": "test", "arguments": {}}, 1)),
         "tools/call without any initialization")

    _add("skip_to_resources",
         _f(_rpc("resources/list", req_id=1)),
         "resources/list without initialization")

    _add("skip_to_prompts",
         _f(_rpc("prompts/list", req_id=1)),
         "prompts/list without initialization")

    _add("skip_to_completion",
         _f(_rpc("completion/complete", {"ref": {"type": "ref/prompt", "name": "test"}, "argument": {"name": "x", "value": ""}}, 1)),
         "completion/complete without initialization")

    # ── Re-initialization ────────────────────────────────────────────
    reinit = (
        _f(_rpc("initialize", INIT_PARAMS, 1)) +
        _f(_notif("notifications/initialized")) +
        _f(_rpc("tools/list", req_id=2)) +
        _f(_rpc("initialize", INIT_PARAMS, 3))  # Re-init mid-session
    )
    _add("reinit_after_list", reinit,
         "Re-initialize after tools/list")

    triple_init = b"".join(
        _f(_rpc("initialize", INIT_PARAMS, i)) for i in range(1, 4)
    )
    _add("triple_init", triple_init,
         "Three initialize requests in a row")

    # ── Ping tests ───────────────────────────────────────────────────
    _add("ping_before_init",
         _f(_rpc("ping", req_id=1)),
         "Ping before initialization")

    ping_after = (
        _f(_rpc("initialize", INIT_PARAMS, 1)) +
        _f(_notif("notifications/initialized")) +
        _f(_rpc("ping", req_id=2))
    )
    _add("ping_after_init", ping_after,
         "Ping after proper initialization")

    rapid_pings = b"".join(_f(_rpc("ping", req_id=i)) for i in range(1, 101))
    _add("rapid_100_pings", rapid_pings,
         "100 pings sent rapidly")

    # ── Resources operations ─────────────────────────────────────────
    _add("resources_read_no_uri",
         _f(_rpc("resources/read", {}, 1)),
         "resources/read with empty params (no URI)")

    _add("resources_read_fake",
         _f(_rpc("resources/read", {"uri": "file:///nonexistent/path"}, 1)),
         "resources/read with nonexistent URI")

    subscribe_unsubscribe = (
        _f(_rpc("resources/subscribe", {"uri": "test://resource"}, 1)) +
        _f(_rpc("resources/unsubscribe", {"uri": "test://resource"}, 2))
    )
    _add("subscribe_unsubscribe", subscribe_unsubscribe,
         "Subscribe then immediately unsubscribe")

    _add("unsubscribe_never_subscribed",
         _f(_rpc("resources/unsubscribe", {"uri": "test://never"}, 1)),
         "Unsubscribe from never-subscribed resource")

    # ── Logging levels ───────────────────────────────────────────────
    levels = ["debug", "info", "notice", "warning", "error", "critical",
              "alert", "emergency", "invalid_level", "", None, 42]
    for i, level in enumerate(levels):
        _add(f"log_level_{i}",
             _f(_rpc("logging/setLevel", {"level": level}, i + 1)),
             f"Set log level to: {repr(level)}")

    # ── Unknown notification methods ─────────────────────────────────
    unknown_notifs = [
        "notifications/unknown",
        "notifications/",
        "custom/event",
        "internal/shutdown",
        "$/cancelRequest",
        "window/showMessage",
    ]
    for i, method in enumerate(unknown_notifs):
        _add(f"unknown_notif_{i}",
             _f(_notif(method, {"data": "test"})),
             f"Unknown notification: {method}")

    # ── Send response objects (not requests) ─────────────────────────
    responses = [
        ("success_response",
         {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}},
         "Success response object (not a request)"),
        ("error_response",
         {"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "test"}},
         "Error response object (not a request)"),
        ("result_and_error",
         {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "both"}},
         "Response with both result and error"),
    ]
    for name, msg, desc in responses:
        _add(name, _f(json.dumps(msg).encode()), desc)

    # ── Rapid state transitions ──────────────────────────────────────
    rapid_transitions = b""
    for i in range(50):
        if i % 3 == 0:
            rapid_transitions += _f(_rpc("tools/list", req_id=i + 1000))
        elif i % 3 == 1:
            rapid_transitions += _f(_rpc("tools/call",
                                         {"name": f"tool_{i}", "arguments": {}},
                                         i + 1000))
        else:
            rapid_transitions += _f(_rpc("ping", req_id=i + 1000))
    _add("rapid_transitions_50", rapid_transitions,
         "50 rapid list/call/ping transitions")

    # ── Cancel with progressToken ────────────────────────────────────
    call_with_progress = (
        _f(_rpc("tools/call", {
            "name": "slow_tool", "arguments": {},
            "_meta": {"progressToken": "xyz-123"}
        }, 1)) +
        _f(_notif("notifications/cancelled", {
            "requestId": 1, "reason": "timeout"
        }))
    )
    _add("call_then_cancel", call_with_progress,
         "tools/call with progressToken then cancel")

    # ── Batch-style (array of requests) ──────────────────────────────
    batch = json.dumps([
        {"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        {"jsonrpc": "2.0", "method": "ping", "id": 2},
    ]).encode()
    _add("batch_array", _f(batch),
         "JSON-RPC batch (array of requests) — not in MCP spec")

    # ── Method that looks like internal RPC ──────────────────────────
    internal_methods = [
        "rpc.discover", "system.listMethods", "system.describe",
        "debug.gc", "admin.shutdown", "server.restart",
    ]
    for i, m in enumerate(internal_methods):
        _add(f"internal_method_{i}",
             _f(_rpc(m, req_id=i + 2000)),
             f"Internal-looking method: {m}")

    return cases
