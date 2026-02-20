"""Encoding attack test cases — test how servers handle various encodings."""

import json
from .base import FuzzCase

def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases = []

    valid_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    valid_json = json.dumps(valid_req)

    # 1. UTF-16 LE with BOM
    utf16_body = b"\xff\xfe" + valid_json.encode("utf-16-le")
    cases.append(FuzzCase(
        name="utf16_le_bom",
        generator="encoding_attacks",
        payload=_frame(utf16_body, framing),
        description="UTF-16 LE encoded JSON with BOM",
        expected_behavior="Server rejects non-UTF-8 encoding",
    ))

    # 2. UTF-16 BE with BOM
    utf16be_body = b"\xfe\xff" + valid_json.encode("utf-16-be")
    cases.append(FuzzCase(
        name="utf16_be_bom",
        generator="encoding_attacks",
        payload=_frame(utf16be_body, framing),
        description="UTF-16 BE encoded JSON with BOM",
        expected_behavior="Server rejects non-UTF-8 encoding",
    ))

    # 3. UTF-8 with BOM
    utf8_bom = b"\xef\xbb\xbf" + valid_json.encode("utf-8")
    cases.append(FuzzCase(
        name="utf8_with_bom",
        generator="encoding_attacks",
        payload=_frame(utf8_bom, framing),
        description="UTF-8 JSON with BOM prefix",
        expected_behavior="Server handles BOM gracefully",
    ))

    # 4. Overlong UTF-8 for '/' (path traversal bypass)
    # Normal '/' is 0x2F. Overlong 2-byte: 0xC0 0xAF
    overlong_body = b'{"jsonrpc":"2.0","id":1,"method":"tools' + b"\xc0\xaf" + b'list"}'
    cases.append(FuzzCase(
        name="overlong_utf8_slash",
        generator="encoding_attacks",
        payload=_frame(overlong_body, framing),
        description="Overlong UTF-8 encoding for '/' character",
        expected_behavior="Server rejects invalid UTF-8 sequences",
    ))

    # 5. Overlong UTF-8 for '.' (path traversal bypass)
    # Normal '.' is 0x2E. Overlong 2-byte: 0xC0 0xAE
    overlong_dot = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test","arguments":{"path":"' + b"\xc0\xae\xc0\xae\xc0\xaf" + b'etc/passwd"}}}'
    cases.append(FuzzCase(
        name="overlong_utf8_dot",
        generator="encoding_attacks",
        payload=_frame(overlong_dot, framing),
        description="Overlong UTF-8 encoding for '.' in path traversal",
        expected_behavior="Server rejects invalid UTF-8 sequences",
    ))

    # 6. CRLF injection in JSON string values
    crlf_req = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test",
            "arguments": {"data": "value\r\nInjected-Header: evil"},
        },
    }
    cases.append(FuzzCase(
        name="crlf_in_json_value",
        generator="encoding_attacks",
        payload=_frame(json.dumps(crlf_req).encode(), framing),
        description="CRLF injection in JSON string value",
        expected_behavior="Server does not interpret CRLF in values",
    ))

    # 7. JSON with JavaScript comments
    js_comment_json = b'{"jsonrpc":"2.0","id":1,/* comment */"method":"tools/list"}'
    cases.append(FuzzCase(
        name="json_with_block_comments",
        generator="encoding_attacks",
        payload=_frame(js_comment_json, framing),
        description="JSON with block comments (invalid JSON)",
        expected_behavior="Server rejects as parse error",
    ))

    # 8. JSON with line comments
    line_comment = b'{"jsonrpc":"2.0","id":1,\n// this is a comment\n"method":"tools/list"}'
    cases.append(FuzzCase(
        name="json_with_line_comments",
        generator="encoding_attacks",
        payload=_frame(line_comment, framing),
        description="JSON with line comments (invalid JSON)",
        expected_behavior="Server rejects as parse error",
    ))

    # 9. JSON with trailing commas
    trailing = b'{"jsonrpc":"2.0","id":1,"method":"tools/list",}'
    cases.append(FuzzCase(
        name="json_trailing_comma",
        generator="encoding_attacks",
        payload=_frame(trailing, framing),
        description="JSON with trailing comma",
        expected_behavior="Server rejects as parse error",
    ))

    # 10. JSON with single quotes
    single = b"{'jsonrpc':'2.0','id':1,'method':'tools/list'}"
    cases.append(FuzzCase(
        name="json_single_quotes",
        generator="encoding_attacks",
        payload=_frame(single, framing),
        description="JSON with single quotes instead of double",
        expected_behavior="Server rejects as parse error",
    ))

    # 11. JSON with unquoted keys
    unquoted = b'{jsonrpc:"2.0",id:1,method:"tools/list"}'
    cases.append(FuzzCase(
        name="json_unquoted_keys",
        generator="encoding_attacks",
        payload=_frame(unquoted, framing),
        description="JSON with unquoted keys",
        expected_behavior="Server rejects as parse error",
    ))

    # 12. Raw binary data mixed with valid JSON
    binary_mixed = b"\x00\x01\x02" + valid_json.encode() + b"\xff\xfe\xfd"
    cases.append(FuzzCase(
        name="binary_mixed_json",
        generator="encoding_attacks",
        payload=_frame(binary_mixed, framing),
        description="Raw binary bytes mixed with valid JSON",
        expected_behavior="Server rejects as parse error",
    ))

    # 13. Null bytes embedded in JSON
    null_json = valid_json.encode()[:20] + b"\x00" + valid_json.encode()[20:]
    cases.append(FuzzCase(
        name="null_byte_in_json",
        generator="encoding_attacks",
        payload=_frame(null_json, framing),
        description="Null bytes embedded in JSON body",
        expected_behavior="Server rejects or strips null bytes",
    ))

    # 14. Latin-1 characters in JSON keys
    latin1 = b'{"jsonrpc":"2.0","id":1,"m\xe9thod":"tools/list"}'
    cases.append(FuzzCase(
        name="latin1_in_keys",
        generator="encoding_attacks",
        payload=_frame(latin1, framing),
        description="Latin-1 encoded characters in JSON keys",
        expected_behavior="Server rejects invalid key names",
    ))

    # 15. JSON with escaped unicode null (\u0000)
    unicode_null_req = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "test", "arguments": {"data": "file\u0000.txt"}},
    }
    cases.append(FuzzCase(
        name="unicode_null_escape",
        generator="encoding_attacks",
        payload=_frame(json.dumps(unicode_null_req).encode(), framing),
        description="Unicode null escape (\\u0000) in value",
        expected_behavior="Server handles without null byte interpretation",
    ))

    # 16. MessagePack instead of JSON
    # Simulate by sending raw msgpack-like binary
    msgpack_like = bytes([0x83, 0xa7]) + b"jsonrpc" + bytes([0xa3]) + b"2.0" + bytes([0xa2]) + b"id" + bytes([0x01])
    cases.append(FuzzCase(
        name="msgpack_format",
        generator="encoding_attacks",
        payload=_frame(msgpack_like, framing),
        description="MessagePack-like binary instead of JSON",
        expected_behavior="Server rejects non-JSON format",
    ))

    # 17. Extremely long string key
    long_key = "A" * 50000
    long_key_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "test", "arguments": {long_key: "value"}}}
    cases.append(FuzzCase(
        name="extremely_long_key",
        generator="encoding_attacks",
        payload=_frame(json.dumps(long_key_req).encode(), framing),
        description="50KB JSON key name",
        expected_behavior="Server handles without crash",
    ))

    return cases
