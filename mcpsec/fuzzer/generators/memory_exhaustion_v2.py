"""
Memory Exhaustion Generator — Test resource limits and OOM handling.

Tests how servers handle:
- Large allocations
- Deeply nested structures
- Many small allocations (fragmentation)
- Huge strings
"""

import json

GENERATOR_NAME = "memory_exhaustion"
GENERATOR_DESCRIPTION = "Tests memory limits and OOM handling"


def generate(intensity: str = "medium", **kwargs) -> list[dict]:
    cases = []

    # ── Deeply nested JSON ───────────────────────────────────────
    if intensity == "insane":
        depths = [100, 500, 1000, 5000]
    elif intensity == "high":
        depths = [100, 500, 1000]
    else:
        depths = [100, 500]

    for depth in depths:
        nested = {"a": None}
        current = nested
        for _ in range(depth):
            current["a"] = {"a": None}
            current = current["a"]

        cases.append({
            "name": f"nested_depth_{depth}",
            "description": f"JSON nested {depth} levels deep",
            "payload": {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": nested},
            "crash_indicates_bug": True,
        })

    # ── Deeply nested arrays ─────────────────────────────────────
    for depth in [100, 500]:
        arr = ["a"]
        for _ in range(depth):
            arr = [arr]
        cases.append({
            "name": f"nested_array_{depth}",
            "description": f"Array nested {depth} levels deep",
            "payload": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "test", "arguments": {"data": arr}}},
            "crash_indicates_bug": True,
        })

    # ── Wide objects (many keys) ─────────────────────────────────
    if intensity == "insane":
        widths = [1000, 10000, 100000]
    elif intensity == "high":
        widths = [1000, 10000]
    else:
        widths = [1000]

    for width in widths:
        wide = {f"k{i}": f"v{i}" for i in range(width)}
        cases.append({
            "name": f"wide_object_{width}",
            "description": f"Object with {width} keys",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": wide}
            },
            "crash_indicates_bug": True,
        })

    # ── Large arrays ─────────────────────────────────────────────
    if intensity in ("high", "insane"):
        sizes = [10000, 100000]
    else:
        sizes = [10000]

    for size in sizes:
        cases.append({
            "name": f"large_array_{size}",
            "description": f"Array with {size} elements",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": {"data": list(range(size))}}
            },
            "crash_indicates_bug": True,
        })

    # ── Huge strings ─────────────────────────────────────────────
    if intensity == "insane":
        string_sizes = [100000, 1000000, 10000000]
    elif intensity == "high":
        string_sizes = [100000, 1000000]
    else:
        string_sizes = [100000]

    for sz in string_sizes:
        cases.append({
            "name": f"huge_string_{sz}",
            "description": f"String of {sz} bytes",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": {"data": "A" * sz}}
            },
            "crash_indicates_bug": True,
        })

    # ── Many keys with long names ────────────────────────────────
    cases.append({
        "name": "long_key_names",
        "description": "Object with 100 keys of 1000 chars each",
        "payload": {
            "jsonrpc": "2.0", "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": {
                f"{'k' * 1000}_{i}": "v" for i in range(100)
            }}
        },
        "crash_indicates_bug": True,
    })

    # ── Repeated requests (memory leak detection) ────────────────
    cases.append({
        "name": "memory_leak_repeated",
        "description": "50 identical requests to detect memory leaks",
        "payload": {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        "repeat": 50,
        "delay_between": 0.01,
        "crash_indicates_bug": True,
    })

    return cases
