"""Generate malformed JSON payloads that test parser robustness."""

import json
from .base import FuzzCase

def _frame(body: bytes, framing: str = "clrf") -> bytes:
    """Add MCP framing (Content-Length or newline)."""
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases = []
    
    # 1. Completely invalid JSON
    cases.append(FuzzCase(
        name="garbage_bytes",
        generator="malformed_json",
        payload=_frame(b"THIS IS NOT JSON AT ALL", framing),
        description="Non-JSON garbage data",
        expected_behavior="Server returns JSON-RPC parse error (-32700)"
    ))
    
    # 2. Empty body
    cases.append(FuzzCase(
        name="empty_body",
        generator="malformed_json",
        payload=_frame(b"", framing),
        description="Empty message body",
        expected_behavior="Server returns parse error or ignores"
    ))
    
    # 3. Null byte in JSON
    cases.append(FuzzCase(
        name="null_byte_in_json",
        generator="malformed_json",
        payload=_frame(b'{"jsonrpc":"2.0","method":"tools/list","id":\x001}', framing),
        description="Null byte embedded in JSON",
        expected_behavior="Server rejects or sanitizes"
    ))
    
    # 4. Truncated JSON
    cases.append(FuzzCase(
        name="truncated_json",
        generator="malformed_json",
        payload=_frame(b'{"jsonrpc":"2.0","method":"tools/li', framing),
        description="JSON truncated mid-string",
        expected_behavior="Server returns parse error"
    ))
    
    # 5. Deeply nested objects (parser bomb)
    deep = '{"a":' * 1000 + '1' + '}' * 1000
    cases.append(FuzzCase(
        name="deep_nesting_1000",
        generator="malformed_json",
        payload=_frame(deep.encode(), framing),
        description="1000-level deep nesting (parser bomb)",
        expected_behavior="Server rejects or handles gracefully"
    ))
    
    # 6. Huge string value (1MB)
    big_string = '{"jsonrpc":"2.0","method":"' + 'A' * 1_000_000 + '","id":1}'
    cases.append(FuzzCase(
        name="megabyte_string",
        generator="malformed_json",
        payload=_frame(big_string.encode(), framing),
        description="1MB string in method field",
        expected_behavior="Server rejects oversized message"
    ))
    
    # 7. Duplicate keys
    cases.append(FuzzCase(
        name="duplicate_keys",
        generator="malformed_json",
        payload=_frame(b'{"jsonrpc":"2.0","method":"tools/list","method":"initialize","id":1}', framing),
        description="Duplicate 'method' key in JSON object",
        expected_behavior="Server uses first or last key consistently"
    ))
    
    # 8. Wrong Content-Length (too small) - Only relevant for clrf
    body = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
    if framing == "clrf":
        cases.append(FuzzCase(
            name="content_length_too_small",
            generator="malformed_json",
            payload=f"Content-Length: 5\r\n\r\n".encode() + body,
            description="Content-Length smaller than actual body",
            expected_behavior="Server reads only 5 bytes, gets parse error"
        ))
    
    # 9. Wrong Content-Length (too large) - Only relevant for clrf
    if framing == "clrf":
        cases.append(FuzzCase(
            name="content_length_too_large",
            generator="malformed_json",
            payload=f"Content-Length: 999999\r\n\r\n".encode() + body,
            description="Content-Length much larger than actual body",
            expected_behavior="Server waits for more data or times out"
        ))
    
    # 10. Negative Content-Length - Only relevant for clrf
    if framing == "clrf":
        cases.append(FuzzCase(
            name="negative_content_length",
            generator="malformed_json",
            payload=b"Content-Length: -1\r\n\r\n" + body,
            description="Negative Content-Length header",
            expected_behavior="Server rejects invalid header"
        ))
    
    # 11. No Content-Length header - Only relevant for clrf (for jsonl this is normal)
    # Actually, for jsonl, "no content length" is just the message.
    # But if we send raw bytes without newline in jsonl mode?
    if framing == "clrf":
        cases.append(FuzzCase(
            name="no_content_length",
            generator="malformed_json",
            payload=body,
            description="Raw JSON without Content-Length framing",
            expected_behavior="Server rejects unframed message"
        ))
    
    # 12. Multiple messages in one write (request smuggling)
    msg1 = _frame(b'{"jsonrpc":"2.0","method":"tools/list","id":1}', framing)
    msg2 = _frame(b'{"jsonrpc":"2.0","method":"tools/list","id":2}', framing)
    cases.append(FuzzCase(
        name="request_smuggling",
        generator="malformed_json",
        payload=msg1 + msg2,
        description="Two complete messages in single write (smuggling)",
        expected_behavior="Server processes both or rejects"
    ))
    
    # 13. JSON with BOM
    cases.append(FuzzCase(
        name="json_with_bom",
        generator="malformed_json",
        payload=_frame(b'\xef\xbb\xbf{"jsonrpc":"2.0","method":"tools/list","id":1}', framing),
        description="JSON prefixed with UTF-8 BOM",
        expected_behavior="Server handles BOM gracefully"
    ))
    
    # 14. JSON with trailing garbage
    cases.append(FuzzCase(
        name="trailing_garbage",
        generator="malformed_json",
        payload=_frame(b'{"jsonrpc":"2.0","method":"tools/list","id":1}GARBAGE', framing),
        description="Valid JSON followed by trailing bytes",
        expected_behavior="Server parses JSON, ignores trailing data"
    ))
    
    return cases
