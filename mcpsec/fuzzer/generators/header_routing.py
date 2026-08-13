"""Header-based routing attacks for the 2026-07-28 stateless protocol.

Streamable HTTP requests now carry Mcp-Method and Mcp-Name headers (SEP-2243)
so gateways can route and authorize on headers directly. This generator tests
header/body mismatches, spoofing, missing headers, and protocol-version
handling — the new attack surface introduced by header-based routing.
"""

import json

from .base import FuzzCase

MCP_PROTOCOL_VERSION = "2026-07-28"


def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _rpc(method: str, params=None, req_id=1) -> bytes:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def _add(cases, name: str, payload: bytes, desc: str, headers: dict | None = None,
         expected: str = "Server handles gracefully"):
    cases.append(
        FuzzCase(
            name=name,
            generator="header_routing",
            payload=payload,
            description=desc,
            expected_behavior=expected,
            headers=headers,
        )
    )


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    body = _rpc("tools/list", req_id=1)
    call_body = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "search", "arguments": {}},
        }
    ).encode()

    # ── Missing required headers ─────────────────────────────────────
    _add(
        cases,
        "missing_mcp_method",
        _frame(body, framing),
        "Request without Mcp-Method header (required by SEP-2243)",
        expected="Server rejects or handles gracefully",
    )

    # ── Header/body method mismatch ───────────────────────────────────
    mismatches = [
        ("tools/call", "tools/list", "Header says tools/call, body says tools/list"),
        ("tools/list", "tools/call", "Header says tools/list, body says tools/call"),
        ("ping", "tools/list", "Header says ping, body says tools/list"),
        ("server/discover", "tools/list", "Header says server/discover, body says tools/list"),
        ("", "tools/list", "Empty Mcp-Method header, body says tools/list"),
    ]
    for i, (header_method, body_method, desc) in enumerate(mismatches):
        body_msg = json.dumps(
            {"jsonrpc": "2.0", "method": body_method, "id": 1}
        ).encode()
        _add(
            cases,
            f"mismatch_{i}",
            _frame(body_msg, framing),
            f"{desc} (Mcp-Method: {header_method!r})",
            headers={"Mcp-Method": header_method, "Mcp-Name": "search"},
            expected="Gateway/server must not route on untrusted header alone",
        )

    # ── Mcp-Name spoofing ────────────────────────────────────────────
    name_spoofs = [
        ("admin", "Spoofed Mcp-Name: admin"),
        ("search", "Spoofed Mcp-Name: search (legit-looking)"),
        ("../../etc/passwd", "Path traversal in Mcp-Name"),
        ("a" * 10000, "10KB Mcp-Name header"),
        ("tools/call", "Mcp-Name with slash (method-like)"),
        ("\r\nX-Evil: injected", "CRLF injection in Mcp-Name"),
        ("\u0000null", "Null byte in Mcp-Name"),
    ]
    for i, (name, desc) in enumerate(name_spoofs):
        _add(
            cases,
            f"name_spoof_{i}",
            _frame(call_body, framing),
            f"{desc} (Mcp-Name: {name[:40]!r})",
            headers={"Mcp-Method": "tools/call", "Mcp-Name": name},
            expected="Server must not trust Mcp-Name for authorization",
        )

    # ── Mcp-Method spoofing ──────────────────────────────────────────
    method_spoofs = [
        ("tools/call", "Spoofed Mcp-Method: tools/call"),
        ("server/discover", "Spoofed Mcp-Method: server/discover"),
        ("tasks/get", "Spoofed Mcp-Method: tasks/get"),
        ("tools/list", "Spoofed Mcp-Method: tools/list"),
        ("a" * 10000, "10KB Mcp-Method header"),
        ("\r\nX-Evil: injected", "CRLF injection in Mcp-Method"),
    ]
    for i, (method, desc) in enumerate(method_spoofs):
        _add(
            cases,
            f"method_spoof_{i}",
            _frame(body, framing),
            f"{desc} (Mcp-Method: {method[:40]!r})",
            headers={"Mcp-Method": method, "Mcp-Name": "search"},
            expected="Server must not trust Mcp-Method for authorization",
        )

    # ── Protocol version header ──────────────────────────────────────
    version_variants = [
        ("2026-07-28", "Correct modern version"),
        ("2024-11-05", "Legacy version"),
        ("9999.99.99", "Future version"),
        ("", "Empty version"),
        ("2026-07-28; DROP TABLE", "SQL injection in version"),
        ("a" * 10000, "10KB version header"),
        ("\r\nX-Evil: injected", "CRLF injection in version header"),
    ]
    for i, (version, desc) in enumerate(version_variants):
        _add(
            cases,
            f"version_{i}",
            _frame(body, framing),
            f"{desc} (MCP-Protocol-Version: {version[:40]!r})",
            headers={"Mcp-Method": "tools/list", "MCP-Protocol-Version": version},
            expected="Server validates protocol version header",
        )

    # ── Conflicting / comma-list headers ───────────────────────────────
    _add(
        cases,
        "conflicting_mcp_method",
        _frame(body, framing),
        "Mcp-Method header with comma-separated conflicting values",
        headers={"Mcp-Method": "tools/list, tools/call"},
        expected="Server handles conflicting header values deterministically",
    )

    # ── Header-only requests (no body) ──────────────────────────────
    _add(
        cases,
        "empty_body",
        _frame(b"", framing),
        "Empty body with Mcp-Method header",
        headers={"Mcp-Method": "tools/list"},
        expected="Server rejects empty body gracefully",
    )

    # ── Mcp-Name matching body tool name ─────────────────────────────
    _add(
        cases,
        "name_matches_body",
        _frame(call_body, framing),
        "Mcp-Name matches tools/call body name (search)",
        headers={"Mcp-Method": "tools/call", "Mcp-Name": "search"},
        expected="Server processes normally",
    )

    # ── Mcp-Name with tool name mismatch ──────────────────────────────
    _add(
        cases,
        "name_mismatch_body",
        _frame(call_body, framing),
        "Mcp-Name says 'admin', body calls tool 'search'",
        headers={"Mcp-Method": "tools/call", "Mcp-Name": "admin"},
        expected="Server must not authorize based on Mcp-Name alone",
    )

    return cases
