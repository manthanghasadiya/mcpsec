"""
Regex DoS (ReDoS) Generator — Test catastrophic backtracking.

Many servers use regex for input validation. Malicious patterns can
cause exponential time complexity (Catastrophic Backtracking).
"""

GENERATOR_NAME = "regex_dos"
GENERATOR_DESCRIPTION = "Tests for Regular Expression Denial of Service"


def generate(intensity: str = "medium", **kwargs) -> list[dict]:
    cases = []

    # Classic ReDoS trigger strings
    redos_patterns = [
        # (a+)+ pattern — exponential backtracking
        "a" * 25 + "!",
        "a" * 30 + "!",
        # Email-like regex abuse
        "a" * 25 + "@a.a",
        "a" * 30 + "@" + "a" * 30 + ".com!",
        # URL-like regex abuse
        "http://" + "a" * 50 + "!",
        # Number parsing regex
        "0" * 50 + "x",
        "0" * 100 + "x",
        # Nested quantifiers (.*)* pattern
        "." * 50 + "!",
        "." * 100 + "!",
        # Alternation abuse (a|a|a|...)
        "|".join(["a"] * 100),
        # Bracket expression abuse
        "a]" * 25,
        "a]" * 50,
        # Whitespace regex abuse
        " " * 50 + "x",
        "\t" * 50 + "x",
        # Path-like regex
        "/" + "/a" * 50 + "!",
        # IP-like regex
        "1" * 50 + ".1.1.1!",
    ]

    if intensity in ("high", "insane"):
        redos_patterns.extend([
            "a" * 50 + "!",
            "a" * 50 + "@a.a",
            "0" * 200 + "x",
            "." * 200 + "!",
        ])

    # Send each pattern to multiple parameter names that likely use regex
    param_sets = [
        {"input": None, "email": None, "pattern": None},
        {"query": None, "search": None, "filter": None},
        {"url": None, "name": None, "path": None},
    ]

    for i, pattern in enumerate(redos_patterns):
        for param_set in param_sets:
            args = {k: pattern for k in param_set}
            cases.append({
                "name": f"redos_{i}_{list(param_set.keys())[0]}",
                "description": f"ReDoS pattern ({len(pattern)} chars): {pattern[:30]}...",
                "payload": {
                    "jsonrpc": "2.0", "id": 1,
                    "method": "tools/call",
                    "params": {"name": "test", "arguments": args}
                },
                "crash_indicates_bug": True,
            })

    # Also test in method name (some servers regex-match methods)
    for i, pattern in enumerate(redos_patterns[:5]):
        cases.append({
            "name": f"redos_method_{i}",
            "description": f"ReDoS in method name: {pattern[:20]}...",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": pattern,
                "params": {}
            },
            "crash_indicates_bug": True,
        })

    return cases
