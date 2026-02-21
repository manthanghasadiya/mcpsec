"""Mutate params/arguments for tools/call — type confusion, injection, prototype pollution."""

import json
from .base import FuzzCase


def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def _call(name_val, arguments=None, req_id=1) -> bytes:
    msg: dict = {
        "jsonrpc": "2.0", "method": "tools/call", "id": req_id,
        "params": {"name": name_val},
    }
    if arguments is not None:
        msg["params"]["arguments"] = arguments
    return json.dumps(msg).encode()


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    def _f(body: bytes) -> bytes:
        return _frame(body, framing)

    def _add(name: str, payload: bytes, desc: str):
        cases.append(FuzzCase(name=name, generator="param_mutations",
                              payload=_f(payload), description=desc,
                              expected_behavior="Error or graceful reject"))

    # ── Name field mutations ─────────────────────────────────────────
    name_mutations = [
        ("name_empty", "", "Empty string as tool name"),
        ("name_whitespace", "   ", "Whitespace-only tool name"),
        ("name_null_byte", "test\x00evil", "Null byte in tool name"),
        ("name_traversal", "../../../etc/passwd", "Path traversal as tool name"),
        ("name_sqli", "test' OR 1=1 --", "SQL injection in tool name"),
        ("name_cmdi", "test; rm -rf /", "Command injection in tool name"),
        ("name_unicode_rtl", "\u202Etest", "RTL override in tool name"),
        ("name_very_long", "A" * 100_000, "100KB tool name string"),
        ("name_newlines", "test\n\ninjected", "Newlines in tool name"),
        ("name_json_break", 'test","evil":"x', "JSON-breaking tool name"),
    ]
    for n, val, desc in name_mutations:
        _add(n, _call(val), desc)

    # ── Name as wrong types ──────────────────────────────────────────
    wrong_types = [
        ("name_int", 42), ("name_float", 3.14), ("name_bool", True),
        ("name_null", None), ("name_array", [1, 2, 3]),
        ("name_object", {"nested": "value"}),
    ]
    for n, val in wrong_types:
        msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1,
               "params": {"name": val}}
        _add(n, json.dumps(msg).encode(), f"Tool name as {type(val).__name__}")

    # ── Arguments field — deeply nested ──────────────────────────────
    nested = {"a": None}
    current = nested
    for _ in range(100):
        current["a"] = {"a": None}
        current = current["a"]
    _add("args_deep_100", _call("test", nested), "100-level nested arguments")

    # ── Arguments — many keys ────────────────────────────────────────
    many_keys = {f"key_{i}": f"val_{i}" for i in range(1000)}
    _add("args_1000_keys", _call("test", many_keys), "1000 keys in arguments")

    # ── Arguments — keys with special chars ──────────────────────────
    special_keys = {
        ".": "dot", "..": "dotdot", "/": "slash", "\\": "backslash",
        "\x00": "null", "\n": "newline", "'": "quote", '"': "dquote",
        "$": "dollar", "__proto__": "proto", "constructor": "ctor",
        "prototype": "prototype", "toString": "toString",
        "__defineGetter__": "defineGetter",
    }
    _add("args_special_keys", _call("test", special_keys),
         "Arguments with special/dangerous key names")

    # ── Arguments — numeric keys ─────────────────────────────────────
    num_keys = {"0": "zero", "1": "one", "-1": "neg", "1e10": "exp",
                "NaN": "nan", "Infinity": "inf"}
    _add("args_numeric_keys", _call("test", num_keys),
         "Arguments with numeric string keys")

    # ── Arguments — values as every JSON type ────────────────────────
    type_vals = [
        ("val_int", {"x": 42}), ("val_float", {"x": 3.14}),
        ("val_neg", {"x": -999}), ("val_zero", {"x": 0}),
        ("val_bool_t", {"x": True}), ("val_bool_f", {"x": False}),
        ("val_null", {"x": None}), ("val_empty_str", {"x": ""}),
        ("val_array", {"x": [1, "a", None, True]}),
        ("val_nested_obj", {"x": {"y": {"z": 1}}}),
        ("val_empty_arr", {"x": []}), ("val_empty_obj", {"x": {}}),
    ]
    for n, args in type_vals:
        _add(n, _call("test", args), f"Argument value type: {n}")

    # ── Prototype pollution attempts ─────────────────────────────────
    proto_payloads = [
        ("proto_proto", {"__proto__": {"admin": True}}),
        ("proto_constructor", {"constructor": {"prototype": {"admin": True}}}),
        ("proto_nested", {"a": {"__proto__": {"polluted": True}}}),
        ("proto_array_proto", {"__proto__": [1, 2, 3]}),
    ]
    for n, args in proto_payloads:
        _add(n, _call("test", args), f"Prototype pollution: {n}")

    # ── Common exploit argument values ───────────────────────────────
    exploits = [
        ("exploit_path", {"path": "../../../../etc/passwd"}),
        ("exploit_cmd", {"command": "; rm -rf /"}),
        ("exploit_ssrf", {"url": "http://169.254.169.254/latest/meta-data/"}),
        ("exploit_sqli", {"query": "' OR 1=1 --"}),
        ("exploit_xss", {"input": "<script>alert(1)</script>"}),
        ("exploit_file_uri", {"file": "file:///etc/passwd"}),
        ("exploit_ssti_jinja", {"data": "{{7*7}}"}),
        ("exploit_ssti_dollar", {"template": "${7*7}"}),
        ("exploit_xxe", {"xml": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'}),
        ("exploit_ldap", {"filter": "*)(&"}),
        ("exploit_nosql", {"query": {"$gt": ""}}),
        ("exploit_regex", {"pattern": "(a+)+$"}),
        ("exploit_format_str", {"name": "%s%s%s%s%s%n"}),
        ("exploit_log_inject", {"msg": "user=admin\nINFO: Logged in"}),
        ("exploit_header", {"host": "evil.com\r\nX-Injected: true"}),
    ]
    for n, args in exploits:
        _add(n, _call("test", args), f"Exploit payload: {n}")

    # ── _meta field mutations ────────────────────────────────────────
    meta_cases = [
        ("meta_null", None), ("meta_string", "not an object"),
        ("meta_int", 42), ("meta_huge", {"progressToken": "X" * 50_000}),
        ("meta_nested", {"a": {"b": {"c": {"d": "deep"}}}}),
        ("meta_proto", {"__proto__": {"admin": True}}),
    ]
    for n, meta_val in meta_cases:
        msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1,
               "params": {"name": "test", "arguments": {}, "_meta": meta_val}}
        _add(f"meta_{n}", json.dumps(msg).encode(), f"_meta field: {n}")

    # ── Extra top-level fields ───────────────────────────────────────
    extra_fields = [
        ("extra_proto", {"__proto__": {"admin": True}}),
        ("extra_constructor", {"constructor": "Function"}),
        ("extra_random", {"x-evil": "payload", "admin": True}),
    ]
    for n, extra in extra_fields:
        msg = {"jsonrpc": "2.0", "method": "tools/call", "id": 1,
               "params": {"name": "test"}}
        msg.update(extra)
        _add(n, json.dumps(msg).encode(), f"Extra top-level fields: {n}")

    # ── Boundary value arguments ─────────────────────────────────────
    boundary_args = [
        ("arg_max_int32", {"x": 2147483647}),
        ("arg_min_int32", {"x": -2147483648}),
        ("arg_max_int64", {"x": 9223372036854775807}),
        ("arg_min_int64", {"x": -9223372036854775808}),
        ("arg_huge_float", {"x": 1.7976931348623157e+308}),
        ("arg_tiny_float", {"x": 5e-324}),
        ("arg_negative_zero", {"x": -0.0}),
        ("arg_true_string", {"x": "true"}),
        ("arg_false_string", {"x": "false"}),
        ("arg_null_string", {"x": "null"}),
        ("arg_undefined", {"x": "undefined"}),
        ("arg_nan_string", {"x": "NaN"}),
        ("arg_inf_string", {"x": "Infinity"}),
    ]
    for n, args in boundary_args:
        _add(n, _call("test", args), f"Boundary value: {n}")

    # ── Resources/read param mutations ───────────────────────────────
    resource_mutations = [
        ("res_empty_uri", {"uri": ""}),
        ("res_null_uri", {"uri": None}),
        ("res_int_uri", {"uri": 42}),
        ("res_traversal_uri", {"uri": "file:///../../etc/passwd"}),
        ("res_ssrf_uri", {"uri": "http://127.0.0.1:6379/"}),
        ("res_data_uri", {"uri": "data:text/html,<script>alert(1)</script>"}),
        ("res_javascript_uri", {"uri": "javascript:alert(1)"}),
        ("res_ftp_uri", {"uri": "ftp://evil.com/malware"}),
        ("res_long_uri", {"uri": "file:///" + "a" * 50_000}),
        ("res_unicode_uri", {"uri": "file:///тест/файл"}),
        ("res_null_byte_uri", {"uri": "file:///tmp/test\x00evil"}),
    ]
    for n, params in resource_mutations:
        msg = {"jsonrpc": "2.0", "method": "resources/read", "id": 1, "params": params}
        _add(n, json.dumps(msg).encode(), f"resources/read: {n}")

    # ── Prompts/get param mutations ──────────────────────────────────
    prompt_mutations = [
        ("prompt_empty_name", {"name": ""}),
        ("prompt_null_name", {"name": None}),
        ("prompt_int_name", {"name": 42}),
        ("prompt_sqli_name", {"name": "' OR 1=1 --"}),
        ("prompt_xss_name", {"name": "<script>alert(1)</script>"}),
        ("prompt_ssti_name", {"name": "{{7*7}}"}),
        ("prompt_huge_args", {"name": "test", "arguments": {f"k{i}": "x" * 1000 for i in range(100)}}),
        ("prompt_empty_args", {"name": "test", "arguments": {}}),
        ("prompt_null_args", {"name": "test", "arguments": None}),
    ]
    for n, params in prompt_mutations:
        msg = {"jsonrpc": "2.0", "method": "prompts/get", "id": 1, "params": params}
        _add(n, json.dumps(msg).encode(), f"prompts/get: {n}")

    # ── tools/call with many arguments of same key ───────────────────
    _add("args_dup_values",
         _call("test", {"x": 1, " x": 2, "x ": 3, "X": 4}),
         "Multiple similar-looking key names (x, ' x', 'x ', 'X')")

    # ── Huge individual argument values ──────────────────────────────
    _add("arg_huge_string", _call("test", {"data": "X" * 500_000}), "500KB string argument")
    _add("arg_huge_array", _call("test", {"data": list(range(50_000))}), "50K element array argument")
    _add("arg_huge_nested_obj",
         _call("test", {"data": {str(i): {str(j): "v" for j in range(10)} for i in range(100)}}),
         "100 objects with 10 keys each in arguments")

    # ── Unicode-heavy argument values ────────────────────────────────
    unicode_args = [
        ("arg_rtl", {"text": "\u202Ehello"}),
        ("arg_bom", {"text": "\ufeffhello"}),
        ("arg_zwj", {"text": "a\u200db"}),
        ("arg_zwnj", {"text": "a\u200cb"}),
        ("arg_surrogate_emoji", {"text": "😀🔥💯"}),
        ("arg_cjk", {"text": "测试漢字テスト"}),
        ("arg_arabic", {"text": "مرحبا"}),
        ("arg_combining", {"text": "Z̴̡̢̞̬̩̝̮̯̩̰̒̔̀̐̾̽̿͝ą̵̠̤̠̘̩̺̺̘̌̾̈́̿̐̄̈́l̶̙̲̺̝̯̽̏̂̈́̐g̵̡̳̙̹̑̉̈́̿̿̑̂̈́"}),
    ]
    for n, args in unicode_args:
        _add(n, _call("test", args), f"Unicode edge case: {n}")

    return cases
