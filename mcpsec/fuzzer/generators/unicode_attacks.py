"""Unicode edge cases that can cause parser bugs."""

import json
from .base import FuzzCase

def generate() -> list[FuzzCase]:
    cases = []
    
    unicode_payloads = [
        ("null_bytes_in_method", "tools/\x00list", "Null byte in method"),
        ("rtl_override", "\u202etools/list", "Right-to-left override character"),
        ("zero_width_space", "tools/\u200blist", "Zero-width space in method"),
        ("zero_width_joiner", "tools\u200d/list", "Zero-width joiner in method"),
        ("homoglyph_slash", "tools\u2215list", "Division slash homoglyph instead of /"),
        ("fullwidth_chars", "\uff54\uff4f\uff4f\uff4c\uff53/list", "Fullwidth Latin characters"),
        ("surrogate_pair", "tools/\ud800list", "Lone surrogate (invalid UTF-16)"),
        ("bom_in_method", "\ufefftools/list", "BOM character in method name"),
        ("combining_chars", "too\u0308ls/list", "Combining diacritical mark in method"),
    ]
    
    for name, method, desc in unicode_payloads:
        try:
            msg = {"jsonrpc": "2.0", "method": method, "id": 1}
            body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
            cases.append(FuzzCase(
                name=name,
                generator="unicode",
                payload=f"Content-Length: {len(body)}\r\n\r\n".encode() + body,
                description=desc,
                expected_behavior="Server normalizes or rejects"
            ))
        except (UnicodeEncodeError, ValueError):
            # Some payloads can't be JSON-encoded, send raw
            raw = f'{{"jsonrpc":"2.0","method":"{method}","id":1}}'.encode(
                "utf-8", errors="surrogatepass"
            )
            cases.append(FuzzCase(
                name=name,
                generator="unicode",
                payload=f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw,
                description=desc,
                expected_behavior="Server normalizes or rejects"
            ))
    
    # Unicode in tool arguments
    tool_unicode = [
        ("arg_null_bytes", {"path": "/etc/\x00passwd"}, "Null byte in argument"),
        ("arg_rtl_override", {"query": "\u202eSELECT * FROM users"}, "RTL in SQL argument"),
        ("arg_path_with_unicode", {"path": "..\\u002f..\\u002fetc/passwd"}, "Unicode-encoded path traversal"),
    ]
    
    for name, args, desc in tool_unicode:
        msg = {
            "jsonrpc": "2.0", "method": "tools/call", "id": 1,
            "params": {"name": "test", "arguments": args}
        }
        body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
        cases.append(FuzzCase(
            name=f"tool_{name}",
            generator="unicode",
            payload=f"Content-Length: {len(body)}\r\n\r\n".encode() + body,
            description=desc,
            expected_behavior="Server sanitizes unicode in arguments"
        ))
    
    return cases
