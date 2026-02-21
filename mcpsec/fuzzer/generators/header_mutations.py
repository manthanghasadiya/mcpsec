"""Mutate Content-Length header and framing — header injection, overflow, smuggling."""

import json
from .base import FuzzCase


def _rpc_body(method: str = "tools/list", req_id: int = 1) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0", "method": method, "id": req_id
    }).encode()


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []
    body = _rpc_body()

    def _add(name: str, payload: bytes, desc: str):
        cases.append(FuzzCase(name=name, generator="header_mutations",
                              payload=payload, description=desc,
                              expected_behavior="Server rejects or handles gracefully"))

    # Most header mutations only apply to CLRF framing
    if framing == "clrf":
        # ── Content-Length value mutations ────────────────────────────
        cl_mutations = [
            ("cl_zero", "0", "Content-Length: 0 with non-empty body"),
            ("cl_negative", "-1", "Content-Length: -1"),
            ("cl_huge", "99999999999999999", "Content-Length: overflow value"),
            ("cl_nan", "NaN", "Content-Length: NaN"),
            ("cl_float", "1.5", "Content-Length: 1.5 (float)"),
            ("cl_quoted", '"100"', 'Content-Length: "100" (quoted)'),
            ("cl_hex", "0x30", "Content-Length: hex value"),
            ("cl_octal", "0144", "Content-Length: octal value"),
            ("cl_leading_zeros", "00" + str(len(body)), "Content-Length with leading zeros"),
            ("cl_spaces", f" {len(body)} ", "Content-Length with spaces"),
            ("cl_plus", f"+{len(body)}", "Content-Length with + prefix"),
            ("cl_empty", "", "Content-Length: (empty value)"),
            ("cl_whitespace_only", "   ", "Content-Length: whitespace only"),
        ]
        for name, val, desc in cl_mutations:
            _add(name, f"Content-Length: {val}\r\n\r\n".encode() + body, desc)

        # ── Header injection ─────────────────────────────────────────
        _add("header_inject_crlf",
             f"Content-Length: {len(body)}\r\nX-Evil: injected\r\n\r\n".encode() + body,
             "CRLF header injection via Content-Length")
        _add("header_inject_value",
             f"Content-Length: {len(body)}\r\nEvil-Header: pwned\r\n\r\n".encode() + body,
             "Extra header injected after Content-Length")

        # ── Multiple Content-Length headers ───────────────────────────
        _add("multi_cl_same",
             f"Content-Length: {len(body)}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body,
             "Duplicate Content-Length (same value)")
        _add("multi_cl_diff",
             f"Content-Length: {len(body)}\r\nContent-Length: 0\r\n\r\n".encode() + body,
             "Duplicate Content-Length (different values)")
        _add("multi_cl_three",
             f"Content-Length: {len(body)}\r\nContent-Length: 999\r\nContent-Length: 0\r\n\r\n".encode() + body,
             "Triple Content-Length headers")

        # ── Wrong header names ───────────────────────────────────────
        wrong_names = [
            ("wrong_content_size", "Content-Size"),
            ("wrong_length", "Length"),
            ("wrong_cl_lower", "content-length"),
            ("wrong_cl_upper", "CONTENT-LENGTH"),
            ("wrong_cl_mixed", "Content-length"),
            ("wrong_transfer_enc", "Transfer-Encoding"),
        ]
        for name, header_name in wrong_names:
            _add(name,
                 f"{header_name}: {len(body)}\r\n\r\n".encode() + body,
                 f"Wrong header name: {header_name}")

        # ── Separator mutations ──────────────────────────────────────
        _add("sep_lf_only",
             f"Content-Length: {len(body)}\n\n".encode() + body,
             "LF-only line endings (no CR)")
        _add("sep_cr_only",
             f"Content-Length: {len(body)}\r\r".encode() + body,
             "CR-only line endings (no LF)")
        _add("sep_triple",
             f"Content-Length: {len(body)}\r\n\r\n\r\n".encode() + body,
             "Triple CRLF separator")
        _add("sep_quad",
             f"Content-Length: {len(body)}\r\n\r\n\r\n\r\n".encode() + body,
             "Quadruple CRLF separator")

        # ── Missing colon ────────────────────────────────────────────
        _add("no_colon",
             f"Content-Length {len(body)}\r\n\r\n".encode() + body,
             "Header without colon separator")
        _add("double_colon",
             f"Content-Length:: {len(body)}\r\n\r\n".encode() + body,
             "Header with double colon")

        # ── Header with special bytes ────────────────────────────────
        _add("header_null_byte",
             f"Content-Length: {len(body)}\x00\r\n\r\n".encode() + body,
             "Null byte in header line")
        _add("header_unicode",
             f"Content-Length: {len(body)}\r\nX-Héader: válue\r\n\r\n".encode(),
             "Unicode characters in header")
        _add("header_1mb_line",
             f"Content-Length: {len(body)}\r\nX-Huge: {'A' * 1_000_000}\r\n\r\n".encode() + body,
             "1MB header line")

        # ── Chunked transfer (not in MCP spec) ───────────────────────
        chunk_hex = format(len(body), 'x')
        _add("chunked_transfer",
             f"Transfer-Encoding: chunked\r\n\r\n{chunk_hex}\r\n".encode() + body + b"\r\n0\r\n\r\n",
             "HTTP chunked encoding (not in MCP spec)")

        # ── Extra headers ────────────────────────────────────────────
        _add("extra_content_type",
             f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode() + body,
             "Extra Content-Type header (ignored by MCP)")
        _add("extra_auth",
             f"Content-Length: {len(body)}\r\nAuthorization: Bearer evil\r\n\r\n".encode() + body,
             "Extra Authorization header")

    # ── JSONL-specific mutations ─────────────────────────────────────
    if framing == "jsonl":
        _add("jsonl_no_newline", body,
             "JSONL message without trailing newline")
        _add("jsonl_double_newline", body + b"\n\n",
             "JSONL with double trailing newline")
        _add("jsonl_crlf", body + b"\r\n",
             "JSONL with CRLF instead of LF")
        _add("jsonl_null_after", body + b"\x00\n",
             "JSONL with null byte before newline")

    # ── Framing-agnostic mutations ───────────────────────────────────
    _add("raw_bytes_no_frame", body,
         "Raw JSON body with no framing at all")
    _add("double_frame",
         (f"Content-Length: {len(body)}\r\n\r\n".encode() + body) if framing == "clrf"
         else (body + b"\n") + (body + b"\n"),
         "Message sent twice in one payload")

    return cases
