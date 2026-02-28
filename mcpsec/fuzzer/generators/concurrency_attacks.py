"""
Concurrency Attack Generator — Test race conditions and state corruption.

MCP servers maintain session state. Concurrent requests can expose:
- Race conditions in tool registration
- Double-free / use-after-free in session handling
- Deadlocks in resource management
- ID collision behavior
"""

import json

GENERATOR_NAME = "concurrency_attacks"
GENERATOR_DESCRIPTION = "Tests race conditions and concurrent request handling"


def generate(intensity: str = "medium", **kwargs) -> list[dict]:
    cases = []

    # ── Rapid-fire same request (test deduplication) ─────────────
    rapid_count = 20 if intensity == "insane" else 10
    for i in range(rapid_count):
        cases.append({
            "name": f"rapid_tools_list_{i}",
            "description": "Rapid consecutive tools/list calls",
            "payload": {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            "crash_indicates_bug": True,
            "delay_between": 0.0,
        })

    # ── ID collision — multiple requests with same ID ────────────
    for method in ["tools/list", "resources/list", "prompts/list"]:
        cases.append({
            "name": f"id_collision_{method.replace('/', '_')}",
            "description": f"Same ID for different methods: {method}",
            "payload": {"jsonrpc": "2.0", "id": 42, "method": method, "params": {}},
            "crash_indicates_bug": True,
        })

    # ── Many concurrent tool calls ───────────────────────────────
    call_count = 20 if intensity in ("high", "insane") else 5
    for i in range(call_count):
        cases.append({
            "name": f"concurrent_call_{i}",
            "description": f"Concurrent tool call #{i}",
            "payload": {
                "jsonrpc": "2.0", "id": 100 + i,
                "method": "tools/call",
                "params": {"name": "test", "arguments": {"data": f"concurrent_{i}"}}
            },
            "delay_between": 0.001,
            "crash_indicates_bug": True,
        })

    # ── Cancel during execution ──────────────────────────────────
    cases.append({
        "name": "cancel_inflight_request",
        "description": "Cancel notification for request that may be in-flight",
        "payload": {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 999, "reason": "Test cancellation"},
        },
        "crash_indicates_bug": True,
    })

    # ── Cancel with non-existent request ID ──────────────────────
    cases.append({
        "name": "cancel_nonexistent",
        "description": "Cancel notification for ID that was never sent",
        "payload": {
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 99999999},
        },
        "crash_indicates_bug": True,
    })

    # ── Re-initialize during session ─────────────────────────────
    cases.append({
        "name": "reinit_during_session",
        "description": "Send initialize during active session",
        "payload": {
            "jsonrpc": "2.0", "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fuzzer-reinit", "version": "1.0"}
            }
        },
        "send_after_init": True,
        "crash_indicates_bug": True,
    })

    # ── Notification flood ───────────────────────────────────────
    notif_count = 50 if intensity == "insane" else 10
    for i in range(notif_count):
        cases.append({
            "name": f"notification_flood_{i}",
            "description": f"Progress notification flood #{i}",
            "payload": {
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": f"tok_{i}", "progress": i, "total": notif_count}
            },
            "delay_between": 0.0,
            "crash_indicates_bug": True,
        })

    # ── Interleaved request/notification ─────────────────────────
    cases.append({
        "name": "interleave_request_notification",
        "description": "List tools immediately followed by random notification",
        "payload": {"jsonrpc": "2.0", "id": 500, "method": "tools/list", "params": {}},
        "crash_indicates_bug": True,
    })
    cases.append({
        "name": "interleave_notification_after",
        "description": "Notification sent after request (no waiting)",
        "payload": {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        },
        "crash_indicates_bug": True,
    })

    return cases
