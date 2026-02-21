"""Advanced JSON parsing edge cases — numbers, nesting, types, escapes."""

import json
import struct
from .base import FuzzCase


def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    def _f(body: bytes) -> bytes:
        return _frame(body, framing)

    def _add(name: str, payload: bytes, desc: str):
        cases.append(FuzzCase(name=name, generator="json_edge_cases",
                              payload=_f(payload), description=desc,
                              expected_behavior="Server rejects or handles"))

    # ── Number precision edge cases ──────────────────────────────────
    number_cases = [
        ("num_max_safe_int", 9007199254740991, "Max safe integer (2^53-1)"),
        ("num_above_safe", 9007199254740992, "Above max safe integer"),
        ("num_huge", 99999999999999999999, "20-digit integer"),
        ("num_negative_huge", -99999999999999999999, "Huge negative integer"),
        ("num_zero", 0, "Zero as ID"),
        ("num_neg_zero", -0.0, "Negative zero as ID"),
        ("num_exp_large", "1e308", "Maximum double exponent"),
        ("num_exp_small", "1e-308", "Minimum positive double"),
        ("num_exp_overflow", "1e309", "Double overflow (>max)"),
        ("num_float_prec", 0.1, "Floating point 0.1"),
    ]
    for name, val, desc in number_cases:
        if isinstance(val, str):
            # Raw string for values that aren't valid Python but valid-ish JSON
            raw = f'{{"jsonrpc":"2.0","method":"tools/list","id":{val}}}'
            _add(name, raw.encode(), desc)
        else:
            msg = {"jsonrpc": "2.0", "method": "tools/list", "id": val}
            _add(name, json.dumps(msg).encode(), desc)

    # ── Invalid JSON number literals ─────────────────────────────────
    invalid_nums = [
        ("num_infinity", "Infinity", "Infinity as ID (non-standard)"),
        ("num_neg_infinity", "-Infinity", "Negative Infinity"),
        ("num_nan", "NaN", "NaN as ID"),
        ("num_hex_literal", "0xFF", "Hex literal as ID"),
        ("num_octal", "0777", "Octal literal as ID"),
        ("num_leading_plus", "+1", "Leading plus sign"),
    ]
    for name, val, desc in invalid_nums:
        _add(name, f'{{"jsonrpc":"2.0","method":"tools/list","id":{val}}}'.encode(), desc)

    # ── Deeply nested structures ─────────────────────────────────────
    # Nested arrays
    deep_arr = "[" * 500 + "1" + "]" * 500
    _add("deep_array_500", f'{{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{deep_arr}}}'.encode(),
         "500-level nested arrays")

    # Nested objects
    deep_obj = '{"a":' * 200 + '"end"' + '}' * 200
    _add("deep_obj_200", f'{{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{{"name":"test","arguments":{deep_obj}}}}}'.encode(),
         "200-level nested objects")

    # Mixed nesting
    mixed = '{"a":[{"b":[' * 100 + '1' + ']}]}' * 100
    _add("deep_mixed_100",
         f'{{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{mixed}}}'.encode(),
         "100-level mixed object/array nesting")

    # ── Large arrays ─────────────────────────────────────────────────
    big_arr = json.dumps(list(range(10000)))
    _add("array_10k", f'{{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{{"name":"test","arguments":{{"data":{big_arr}}}}}}}'.encode(),
         "10,000 element array in arguments")

    big_str_arr = json.dumps(["x" * 100] * 1000)
    _add("array_1k_strings", f'{{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{{"name":"test","arguments":{{"data":{big_str_arr}}}}}}}'.encode(),
         "1,000 x 100-char strings in array")

    # ── Every field as wrong type ────────────────────────────────────
    wrong_type_msgs = [
        ("all_obj", '{"jsonrpc":{},"method":{},"id":{}}', "All fields as empty objects"),
        ("all_arr", '{"jsonrpc":[],"method":[],"id":[]}', "All fields as empty arrays"),
        ("all_bool", '{"jsonrpc":true,"method":false,"id":true}', "All fields as booleans"),
        ("all_null", '{"jsonrpc":null,"method":null,"id":null}', "All fields as null"),
        ("all_num", '{"jsonrpc":2,"method":42,"id":"one"}', "Swapped: version=int, method=int, id=string"),
    ]
    for name, raw, desc in wrong_type_msgs:
        _add(name, raw.encode(), desc)

    # ── Unicode escape sequences ─────────────────────────────────────
    unicode_escapes = [
        ("esc_null", r'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{"x":"\u0000"}}',
         r"Unicode null escape \u0000 in params"),
        ("esc_ffff", r'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{"x":"\uFFFF"}}',
         r"Unicode \uFFFF in params"),
        ("esc_surrogate_hi", r'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{"x":"\uD800"}}',
         "Lone high surrogate"),
        ("esc_surrogate_lo", r'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{"x":"\uDC00"}}',
         "Lone low surrogate"),
        ("esc_surrogate_pair", r'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{"x":"\uD83D\uDE00"}}',
         "Valid surrogate pair (emoji)"),
    ]
    for name, raw, desc in unicode_escapes:
        _add(name, raw.encode(), desc)

    # ── Escaped characters everywhere ────────────────────────────────
    _add("all_escapes",
         r'{"jsonrpc":"2.0","method":"tools\/list","id":1,"params":{"a":"\"\\\/\b\f\n\r\t"}}'.encode(),
         "All JSON escape sequences in values")

    # ── Control characters in strings ────────────────────────────────
    for cc in [0x01, 0x08, 0x0B, 0x0C, 0x0E, 0x1F]:
        raw = f'{{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{{"x":"test{chr(cc)}end"}}}}'
        _add(f"control_char_0x{cc:02x}", raw.encode(),
             f"Control character 0x{cc:02X} in string value")

    # ── Emoji in every field ─────────────────────────────────────────
    _add("emoji_everywhere",
         '{"jsonrpc":"2.0","method":"🔧/📋","id":1,"params":{"🔑":"🔓"}}'.encode(),
         "Emoji characters in method and params")

    # ── Exponent notation for ID ─────────────────────────────────────
    exp_ids = [
        ("id_1e2", "1e2", "ID as 1e2 (=100)"),
        ("id_1e0", "1e0", "ID as 1e0 (=1)"),
        ("id_1E2", "1E2", "ID as 1E2 (uppercase)"),
        ("id_neg_exp", "-1e2", "ID as -1e2 (=-100)"),
    ]
    for name, val, desc in exp_ids:
        _add(name, f'{{"jsonrpc":"2.0","method":"tools/list","id":{val}}}'.encode(), desc)

    # ── String ID variations ─────────────────────────────────────────
    str_ids = [
        ("id_str_num", '"1"', "ID as string '1'"),
        ("id_str_empty", '""', "ID as empty string"),
        ("id_str_uuid", '"550e8400-e29b-41d4-a716-446655440000"', "ID as UUID string"),
        ("id_str_object", '"[object Object]"', "ID as '[object Object]' string"),
    ]
    for name, val, desc in str_ids:
        _add(name, f'{{"jsonrpc":"2.0","method":"tools/list","id":{val}}}'.encode(), desc)

    # ── Duplicate keys at same level ─────────────────────────────────
    _add("dup_jsonrpc",
         b'{"jsonrpc":"2.0","jsonrpc":"1.0","method":"tools/list","id":1}',
         "Duplicate jsonrpc key with different values")
    _add("dup_id",
         b'{"jsonrpc":"2.0","method":"tools/list","id":1,"id":2}',
         "Duplicate id key with different values")
    _add("dup_params",
         b'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{},"params":{"evil":true}}',
         "Duplicate params key")

    # ── Whitespace variations ────────────────────────────────────────
    _add("compact_json",
         b'{"jsonrpc":"2.0","method":"tools/list","id":1}',
         "Maximally compact JSON (no spaces)")
    _add("pretty_json",
         json.dumps({"jsonrpc": "2.0", "method": "tools/list", "id": 1}, indent=4).encode(),
         "Pretty-printed JSON with 4-space indent")
    _add("tabs_json",
         b'{\t"jsonrpc"\t:\t"2.0"\t,\t"method"\t:\t"tools/list"\t,\t"id"\t:\t1\t}',
         "JSON with tabs as whitespace")

    # ── Trailing commas ──────────────────────────────────────────────
    _add("trailing_comma_obj",
         b'{"jsonrpc":"2.0","method":"tools/list","id":1,}',
         "Trailing comma in object (invalid JSON)")
    _add("trailing_comma_arr",
         b'{"jsonrpc":"2.0","method":"tools/list","id":1,"params":{"x":[1,2,3,]}}',
         "Trailing comma in array (invalid JSON)")

    # ── Comments in JSON ─────────────────────────────────────────────
    _add("line_comment",
         b'{"jsonrpc":"2.0","method":"tools/list","id":1} // comment',
         "JSON with line comment (invalid)")
    _add("block_comment",
         b'{"jsonrpc":"2.0",/* comment */"method":"tools/list","id":1}',
         "JSON with block comment (invalid)")

    # ── BOM and encoding marks ───────────────────────────────────────
    _add("bom_utf8",
         b'\xef\xbb\xbf{"jsonrpc":"2.0","method":"tools/list","id":1}',
         "UTF-8 BOM prefix")
    _add("bom_utf16le",
         b'\xff\xfe{"jsonrpc":"2.0","method":"tools/list","id":1}',
         "UTF-16LE BOM prefix")

    # ── jsonrpc version variations ───────────────────────────────────
    versions = [
        ("ver_10", "1.0"), ("ver_11", "1.1"), ("ver_30", "3.0"),
        ("ver_empty", ""), ("ver_null_str", "null"), ("ver_int", "2"),
    ]
    for name, ver in versions:
        _add(name, f'{{"jsonrpc":"{ver}","method":"tools/list","id":1}}'.encode(),
             f"jsonrpc version: '{ver}'")

    # ── Missing required fields ──────────────────────────────────────
    _add("missing_jsonrpc", b'{"method":"tools/list","id":1}', "Missing jsonrpc field")
    _add("missing_method", b'{"jsonrpc":"2.0","id":1}', "Missing method field")
    _add("missing_id", b'{"jsonrpc":"2.0","method":"tools/list"}', "Missing id field")
    _add("empty_object", b'{}', "Empty object")
    _add("empty_array", b'[]', "Empty array (not a valid request)")
    _add("just_string", b'"tools/list"', "Just a string literal")
    _add("just_number", b'42', "Just a number literal")
    _add("just_null", b'null', "Just null")
    _add("just_true", b'true', "Just boolean true")
    _add("just_false", b'false', "Just boolean false")

    return cases
