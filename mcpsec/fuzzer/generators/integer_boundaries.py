"""
Integer Boundary Fuzzer — Test integer handling edge cases.

Many crashes occur at integer boundaries: overflow, underflow,
signed/unsigned confusion, 32/64 bit differences.
"""

import json
import math

GENERATOR_NAME = "integer_boundaries"
GENERATOR_DESCRIPTION = "Tests integer overflow, underflow, and type confusion"


def generate(intensity: str = "medium", **kwargs) -> list[dict]:
    cases = []

    # ── Standard integer boundaries ──────────────────────────────
    boundaries = {
        "int8":  [-129, -128, -1, 0, 1, 127, 128, 255, 256],
        "int16": [-32769, -32768, 32767, 32768, 65535, 65536],
        "int32": [-2147483649, -2147483648, 2147483647, 2147483648, 4294967295, 4294967296],
    }

    if intensity in ("high", "insane"):
        boundaries["int64"] = [
            -9223372036854775809, -9223372036854775808,
            9223372036854775807, 9223372036854775808,
        ]

    # Test in request ID field
    for type_name, values in boundaries.items():
        for val in values:
            cases.append({
                "name": f"id_{type_name}_{val}",
                "description": f"Request ID at {type_name} boundary: {val}",
                "payload": {"jsonrpc": "2.0", "id": val, "method": "tools/list", "params": {}},
                "crash_indicates_bug": True,
            })

    # Test in params
    for type_name, values in boundaries.items():
        for val in values:
            cases.append({
                "name": f"param_{type_name}_{val}",
                "description": f"Numeric parameter at {type_name} boundary",
                "payload": {
                    "jsonrpc": "2.0", "id": 1,
                    "method": "tools/call",
                    "params": {"name": "test", "arguments": {"count": val, "offset": val}}
                },
                "crash_indicates_bug": True,
            })

    # ── Float specials ───────────────────────────────────────────
    # Can't put inf/nan in JSON directly, use string representations
    float_specials = [1e308, -1e308, 1e-308, -1e-308, 0.0, -0.0, 1.7976931348623157e+308]
    for val in float_specials:
        cases.append({
            "name": f"float_{val}",
            "description": f"Float edge case: {val}",
            "payload": {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"limit": val}},
            "crash_indicates_bug": True,
        })

    # ── Scientific notation edge cases (as raw JSON strings) ─────
    scientific = ["1e9999", "-1e9999", "1e-9999", "0e0", "0e9999", "1E+308", "-1E+308"]
    for s in scientific:
        # Send as raw JSON to test parser
        raw = f'{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{"limit":{s}}}}}'
        cases.append({
            "name": f"scientific_{s}",
            "description": f"Scientific notation: {s}",
            "payload": raw.encode("utf-8"),
            "crash_indicates_bug": True,
        })

    # ── Negative zero ────────────────────────────────────────────
    cases.append({
        "name": "negative_zero_id",
        "description": "Request with -0 as ID",
        "payload": b'{"jsonrpc":"2.0","id":-0,"method":"tools/list","params":{}}',
        "crash_indicates_bug": True,
    })

    # ── Very large number (>JSON spec) ───────────────────────────
    if intensity in ("high", "insane"):
        huge = "9" * 1000
        cases.append({
            "name": "huge_number_1000_digits",
            "description": "Number with 1000 digits",
            "payload": f'{{"jsonrpc":"2.0","id":{huge},"method":"tools/list","params":{{}}}}'.encode(),
            "crash_indicates_bug": True,
        })

    return cases
