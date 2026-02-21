"""Timing and concurrency fuzz cases — race conditions, floods, slow-loris."""

import json
import time
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


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    def _f(body: bytes) -> bytes:
        return _frame(body, framing)

    def _add(name: str, payload: bytes, desc: str):
        cases.append(FuzzCase(name=name, generator="timing_attacks",
                              payload=payload, description=desc,
                              expected_behavior="Server handles gracefully"))

    # ── Rapid-fire identical requests ────────────────────────────────
    burst_10 = b"".join(_f(_rpc("tools/list", req_id=i)) for i in range(1, 11))
    _add("burst_10_tools_list", burst_10,
         "10 tools/list requests in single write")

    burst_50 = b"".join(_f(_rpc("ping", req_id=i)) for i in range(1, 51))
    _add("burst_50_pings", burst_50,
         "50 ping requests in single write")

    burst_100 = b"".join(_f(_rpc("tools/list", req_id=i)) for i in range(1, 101))
    _add("burst_100_tools_list", burst_100,
         "100 tools/list requests in single write (flood)")

    # ── Interleaved valid + invalid ──────────────────────────────────
    interleaved = b""
    for i in range(20):
        if i % 2 == 0:
            interleaved += _f(_rpc("tools/list", req_id=i + 100))
        else:
            interleaved += _f(b"NOT JSON")
    _add("interleave_valid_invalid_20", interleaved,
         "20 alternating valid/invalid messages")

    # ── Interleaved methods ──────────────────────────────────────────
    methods = ["tools/list", "ping", "resources/list", "prompts/list"]
    mixed = b"".join(_f(_rpc(methods[i % len(methods)], req_id=i + 200))
                     for i in range(40))
    _add("mixed_methods_40", mixed,
         "40 rapid requests cycling through different methods")

    # ── Duplicate IDs (race) ─────────────────────────────────────────
    dup_ids = b"".join(_f(_rpc("tools/list", req_id=999)) for _ in range(10))
    _add("dup_id_race_10", dup_ids,
         "10 requests all with id=999 (ID collision race)")

    # ── Request + notification mixed ─────────────────────────────────
    req_notif = b""
    for i in range(20):
        if i % 3 == 0:
            # notification (no id)
            notif = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                     "params": {"requestId": i, "reason": "test"}}
            req_notif += _f(json.dumps(notif).encode())
        else:
            req_notif += _f(_rpc("tools/list", req_id=i + 300))
    _add("request_notification_mix", req_notif,
         "Interleaved requests and cancel notifications")

    # ── Slow-loris style: half a message ─────────────────────────────
    full = _rpc("tools/list", req_id=1)
    half = full[:len(full) // 2]
    if framing == "clrf":
        header = f"Content-Length: {len(full)}\r\n\r\n".encode()
        _add("slow_loris_half", header + half,
             "Half of a message body (slow-loris)")
    else:
        _add("slow_loris_half", half,
             "Half of a message body (slow-loris)")

    # ── Partial header (CLRF only) ───────────────────────────────────
    if framing == "clrf":
        _add("partial_header", b"Content-Leng",
             "Truncated header (partial Content-Length)")
        _add("header_no_body", b"Content-Length: 100\r\n\r\n",
             "Complete header but missing body")

    # ── Many small writes (fragmentation) ────────────────────────────
    full_msg = _f(_rpc("tools/list", req_id=1))
    # Send byte-by-byte (simulated as single payload — engine sends atomically,
    # but the content itself is one valid message)
    _add("single_byte_message", full_msg,  # Can't actually fragment in our engine
         "Normal single message (baseline for timing)")

    # ── Pipelining: many methods as fast as possible ─────────────────
    all_methods = [
        "tools/list", "resources/list", "prompts/list",
        "completion/complete", "logging/setLevel", "ping",
    ]
    pipeline = b"".join(
        _f(_rpc(m, req_id=i + 400, params={} if m != "ping" else None))
        for i, m in enumerate(all_methods * 5)
    )
    _add("pipeline_30_methods", pipeline,
         "30 pipelined requests across 6 different methods")

    # ── Zero-length payload ──────────────────────────────────────────
    if framing == "clrf":
        _add("zero_length_body", b"Content-Length: 0\r\n\r\n",
             "Content-Length: 0 with empty body")

    # ── Massive single write ─────────────────────────────────────────
    massive = b"".join(_f(_rpc("ping", req_id=i)) for i in range(1, 201))
    _add("massive_200_pings", massive,
         "200 pings in a single write (~100KB)")

    # ── Back-to-back tools/call ──────────────────────────────────────
    calls = b"".join(
        _f(json.dumps({
            "jsonrpc": "2.0", "method": "tools/call", "id": i + 500,
            "params": {"name": f"nonexistent_{i}", "arguments": {}}
        }).encode())
        for i in range(20)
    )
    _add("rapid_call_20_nonexistent", calls,
         "20 rapid tools/call to nonexistent tools")

    # ── Cancel flood ─────────────────────────────────────────────────
    cancels = b"".join(
        _f(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": i, "reason": "fuzz"}
        }).encode())
        for i in range(50)
    )
    _add("cancel_flood_50", cancels,
         "50 cancel notifications for non-existent requests")

    # ── Out-of-order IDs ─────────────────────────────────────────────
    ooo = b"".join(_f(_rpc("tools/list", req_id=rid))
                   for rid in [100, 3, 999, 1, 50, 7, 42])
    _add("out_of_order_ids", ooo,
         "Requests with non-sequential IDs")

    # ── Negative IDs ─────────────────────────────────────────────────
    neg = b"".join(_f(_rpc("tools/list", req_id=rid))
                   for rid in [-1, -100, -999999])
    _add("negative_ids", neg,
         "Requests with negative IDs")

    # ── Float IDs ────────────────────────────────────────────────────
    for fid in [1.5, 0.0, -0.0, 1e10, 1e-10]:
        msg = {"jsonrpc": "2.0", "method": "tools/list", "id": fid}
        _add(f"float_id_{str(fid).replace('.','_').replace('-','neg')}",
             _f(json.dumps(msg).encode()),
             f"Request with float ID: {fid}")

    return cases
