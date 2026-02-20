"""Injection payload test cases — path traversal, command injection, SQLi, SSRF, XSS, etc."""

import json
from .base import FuzzCase

def _frame(body: bytes, framing: str = "clrf") -> bytes:
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


# Each payload is a (name, value, description) triple.
INJECTION_PAYLOADS = [
    # Path traversal
    ("path_traversal_basic", "../../etc/passwd", "Basic path traversal"),
    ("path_traversal_windows", "..\\..\\windows\\system32\\config\\sam", "Windows path traversal"),
    ("path_traversal_encoded", "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded path traversal"),
    ("path_traversal_null", "file\x00.txt", "Null byte path traversal"),
    ("path_traversal_double", "....//....//etc/passwd", "Double-encoding path traversal"),

    # Command injection
    ("cmdi_semicolon", "; id", "Semicolon command injection"),
    ("cmdi_pipe", "| whoami", "Pipe command injection"),
    ("cmdi_backtick", "`id`", "Backtick command injection"),
    ("cmdi_dollar", "$(whoami)", "Dollar-paren command injection"),
    ("cmdi_newline", "x\nid", "Newline command injection"),
    ("cmdi_ampersand", "& net user", "Ampersand command injection"),
    ("cmdi_or", "|| id", "Or command injection"),

    # SQL injection
    ("sqli_basic", "' OR 1=1 --", "Basic SQL injection"),
    ("sqli_union", "' UNION SELECT 1,2,3--", "UNION SQL injection"),
    ("sqli_stacked", "'; DROP TABLE users; --", "Stacked query SQL injection"),
    ("sqli_blind_time", "' OR SLEEP(5)--", "Time-based blind SQLi"),
    ("sqli_blind_bool", "' OR 1=1#", "Boolean-based blind SQLi"),

    # SSRF
    ("ssrf_metadata_aws", "http://169.254.169.254/latest/meta-data/", "AWS SSRF metadata"),
    ("ssrf_metadata_gcp", "http://metadata.google.internal/computeMetadata/v1/", "GCP SSRF metadata"),
    ("ssrf_localhost", "http://127.0.0.1:22", "SSRF localhost port scan"),
    ("ssrf_internal", "http://internal-service.local/admin", "SSRF internal service"),

    # XSS
    ("xss_basic", "<script>alert(1)</script>", "Basic XSS"),
    ("xss_img", "<img src=x onerror=alert(1)>", "IMG tag XSS"),
    ("xss_svg", "<svg onload=alert(1)>", "SVG XSS"),

    # Template injection
    ("ssti_jinja", "{{7*7}}", "Jinja2 template injection"),
    ("ssti_dollar", "${7*7}", "Dollar template injection"),
    ("ssti_ejs", "<%= 7*7 %>", "EJS template injection"),

    # Log / header injection
    ("log_injection", "\r\nINJECTED LOG ENTRY\r\n", "CRLF log injection"),
    ("header_injection", "value\r\nX-Injected: true", "HTTP header injection"),

    # Unicode normalization
    ("unicode_fullwidth_script", "\uff1cscript\uff1e", "Fullwidth angle brackets XSS"),
    ("unicode_homoglyph", "a\u0430dmin", "Cyrillic 'a' homoglyph"),

    # Prototype pollution (JSON)
    ("proto_pollution", '{"__proto__": {"admin": true}}', "Prototype pollution via JSON"),
    ("constructor_pollution", '{"constructor": {"prototype": {"isAdmin": true}}}', "Constructor pollution"),
]


def generate(framing: str = "clrf") -> list[FuzzCase]:
    """Generate injection payload fuzz cases wrapped in tools/call."""
    cases = []

    # Use a generic tool call structure — the fuzzer will send these after init
    for payload_name, payload_value, desc in INJECTION_PAYLOADS:
        # Wrap each payload in a tools/call request to a fake tool
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "test_tool",
                "arguments": {
                    "input": payload_value,
                    "path": payload_value,
                    "query": payload_value,
                    "url": payload_value,
                    "command": payload_value,
                },
            },
        }
        cases.append(FuzzCase(
            name=f"injection_{payload_name}",
            generator="injection_payloads",
            payload=_frame(json.dumps(request).encode(), framing),
            description=desc,
            expected_behavior="Server sanitizes input or returns safe error",
        ))

    # Also test payloads in resource URIs
    for payload_name, payload_value, desc in INJECTION_PAYLOADS[:10]:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": payload_value},
        }
        cases.append(FuzzCase(
            name=f"resource_injection_{payload_name}",
            generator="injection_payloads",
            payload=_frame(json.dumps(request).encode(), framing),
            description=f"Resource URI: {desc}",
            expected_behavior="Server validates URI and rejects malicious input",
        ))

    return cases
