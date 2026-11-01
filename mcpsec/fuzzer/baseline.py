"""
Baseline-differential response analyzer.

Captures per-tool baseline fingerprints from benign calls and produces
differential verdicts (CLEAN, TRANSPORT_REJECT, DEVIATION) for fuzzer responses.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from mcpsec.fuzzer.generators.schema_fuzzer import build_valid_arguments
from mcpsec.scanners.response_classifier import (
    SAFE_JSONRPC_CODES,
    _is_jsonrpc_safe,
    classify_response,
    measure_baseline_latency,
)
from mcpsec.scanners.response_classifier import (
    Verdict as ClassifierVerdict,
)

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    CLEAN = "CLEAN"  # matches baseline, not interesting
    # JSON-RPC parse/validation reject (-32700/-32600/-32602), server alive, not a finding
    TRANSPORT_REJECT = "TRANSPORT_REJECT"
    DEVIATION = "DEVIATION"  # real signal: investigate / feed to oracle


@dataclass
class ToolBaseline:
    tool_name: str
    ok: bool  # did benign calls succeed
    error_codes: set[
        int
    ]  # JSON-RPC error codes seen on benign calls (usually empty or a benign set)
    response_shape: str  # normalized structural signature (keys + value TYPES, not values)
    size_range: tuple[int, int]  # min/max response byte length over benign calls
    baseline_latency_ms: float  # from measure_baseline_latency over benign samples
    error_signature: str  # normalized text shape of any benign error
    benign_samples: list[str] = field(default_factory=list)


def _normalize_obj(obj: Any) -> Any:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "bool"
    if isinstance(obj, int):
        return "int"
    if isinstance(obj, float):
        return "float"
    if isinstance(obj, str):
        return "str"
    if isinstance(obj, list):
        return [_normalize_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _normalize_obj(v) for k, v in sorted(obj.items())}
    return type(obj).__name__


def normalize_shape(response_text: str) -> str:
    """
    Parse JSON, walk it, replace scalar values with their type name,
    sort keys, and return a stable string representation.
    Two responses with the same structure but different values produce the same shape.
    """
    if not response_text:
        return ""

    clean_text = response_text
    if "\r\n\r\n" in clean_text:
        clean_text = clean_text.split("\r\n\r\n", 1)[1]
    clean_text = clean_text.strip()

    try:
        data = json.loads(clean_text)
        normalized = _normalize_obj(data)
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    except (json.JSONDecodeError, TypeError):
        # Fallback for non-JSON or raw text responses
        return f"raw:{clean_text[:100]}"


def build_baseline(tool: dict, send_fn: Callable, framing: str = "clrf") -> ToolBaseline:
    """
    Build a per-tool baseline fingerprint from benign calls.

    Generates valid benign arguments for the tool from its inputSchema,
    calls the tool 3 times via send_fn, and records ok/error codes,
    response shape, size range, latency, and error signature.
    """
    tool_name = tool.get("name", "unknown")
    schema = tool.get("inputSchema", {})
    benign_args = build_valid_arguments(schema)

    results = []
    for i in range(3):
        msg = {
            "jsonrpc": "2.0",
            "id": i + 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": benign_args,
            },
        }
        body = json.dumps(msg).encode("utf-8")
        if framing == "jsonl":
            payload = body + b"\n"
        else:
            payload = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8") + body

        try:
            res = send_fn(payload)
            if res is not None:
                results.append(res)
        except Exception as e:
            logger.debug(f"Exception calling send_fn in build_baseline: {e}")

    elapsed_times = [
        getattr(r, "elapsed_ms", 0.0) for r in results if getattr(r, "elapsed_ms", None) is not None
    ]
    baseline_latency_ms = measure_baseline_latency(elapsed_times) if elapsed_times else 1000.0

    sizes = [len(getattr(r, "response", b"") or b"") for r in results]
    size_range = (min(sizes) if sizes else 0, max(sizes) if sizes else 0)

    error_codes: set[int] = set()
    shapes: list[str] = []
    benign_samples: list[str] = []
    error_sig = ""
    ok_count = 0

    for r in results:
        if getattr(r, "crashed", False) or getattr(r, "timeout", False):
            continue

        resp_bytes = getattr(r, "response", None)
        if not resp_bytes:
            continue

        resp_text = (
            resp_bytes.decode("utf-8", errors="replace")
            if isinstance(resp_bytes, bytes)
            else str(resp_bytes)
        )
        benign_samples.append(resp_text)

        clean_text = resp_text
        if "\r\n\r\n" in clean_text:
            clean_text = clean_text.split("\r\n\r\n", 1)[1]
        clean_text = clean_text.strip()

        is_err = False
        try:
            parsed = json.loads(clean_text)
            if isinstance(parsed, dict) and "error" in parsed:
                is_err = True
                code = parsed["error"].get("code")
                if isinstance(code, int):
                    error_codes.add(code)
                msg_text = str(parsed["error"].get("message", ""))
                if not error_sig:
                    error_sig = msg_text
        except Exception:
            pass

        shape = normalize_shape(resp_text)
        if shape and not is_err:
            shapes.append(shape)
            ok_count += 1
        elif shape and not shapes:
            shapes.append(shape)

    ok = ok_count > 0
    response_shape = shapes[0] if shapes else ""

    return ToolBaseline(
        tool_name=tool_name,
        ok=ok,
        error_codes=error_codes,
        response_shape=response_shape,
        size_range=size_range,
        baseline_latency_ms=baseline_latency_ms,
        error_signature=error_sig,
        benign_samples=benign_samples,
    )


BOILERPLATE_WORDS = {
    "jsonrpc",
    "2.0",
    "tools/call",
    "tools",
    "call",
    "params",
    "arguments",
    "method",
    "id",
    "true",
    "false",
    "null",
    "content",
    "result",
    "text",
    "type",
    "error",
    "code",
    "message",
    "protocolversion",
    "2024-11-05",
    "2026-07-28",
    "content-length",
}


def _collect_strings(obj: Any, out: set[str]):
    if isinstance(obj, str):
        if len(obj) >= 3:
            out.add(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_strings(v, out)


def _extract_payload_tokens(payload: bytes, baseline: ToolBaseline | None) -> set[str]:
    """Extract candidate unique tokens from a payload."""
    if not payload:
        return set()

    try:
        payload_text = (
            payload.decode("utf-8", errors="replace")
            if isinstance(payload, bytes)
            else str(payload)
        )
    except Exception:
        return set()

    tokens: set[str] = set()

    # If payload is JSON, extract arguments
    clean_payload = payload_text
    if "\r\n\r\n" in clean_payload:
        clean_payload = clean_payload.split("\r\n\r\n", 1)[1]
    clean_payload = clean_payload.strip()

    try:
        data = json.loads(clean_payload)
        if isinstance(data, dict):
            params = data.get("params")
            if isinstance(params, dict):
                args = params.get("arguments")
                _collect_strings(args, tokens)
    except Exception:
        pass

    # Extract words/tokens from raw payload (must contain letters, length >= 4)
    word_matches = re.findall(r"[A-Za-z0-9_-]{4,}", payload_text)
    for w in word_matches:
        if re.search(r"[A-Za-z]", w):
            tokens.add(w)

    filtered = set()
    tool_name_lower = baseline.tool_name.lower() if baseline else ""
    benign_text = ""
    if baseline and baseline.benign_samples:
        benign_text = " ".join(baseline.benign_samples).lower()

    for t in tokens:
        t_lower = t.lower()
        if t_lower in BOILERPLATE_WORDS:
            continue
        if tool_name_lower and t_lower == tool_name_lower:
            continue
        if benign_text and t_lower in benign_text:
            continue
        filtered.add(t)

    return filtered


def classify(result: Any, baseline: ToolBaseline | None, payload: bytes) -> tuple[Verdict, str]:
    """
    Score a fuzzed response against a tool baseline fingerprint.

    Returns (Verdict, reason).
    """
    resp_bytes = (
        getattr(result, "response", None)
        if hasattr(result, "response")
        else (result.get("response") if isinstance(result, dict) else None)
    )
    crashed = (
        getattr(result, "crashed", False)
        if hasattr(result, "crashed")
        else (result.get("crashed", False) if isinstance(result, dict) else False)
    )
    timeout = (
        getattr(result, "timeout", False)
        if hasattr(result, "timeout")
        else (result.get("timeout", False) if isinstance(result, dict) else False)
    )
    elapsed_ms = (
        getattr(result, "elapsed_ms", 0.0)
        if hasattr(result, "elapsed_ms")
        else (result.get("elapsed_ms", 0.0) if isinstance(result, dict) else 0.0)
    )

    if crashed:
        err = getattr(result, "error_message", "") if hasattr(result, "error_message") else ""
        return Verdict.DEVIATION, err or "server crashed"

    if timeout:
        return Verdict.DEVIATION, "server timeout"

    if not resp_bytes:
        return Verdict.CLEAN, "empty response"

    resp_text = (
        resp_bytes.decode("utf-8", errors="replace")
        if isinstance(resp_bytes, bytes)
        else str(resp_bytes)
    )

    clean_text = resp_text
    if "\r\n\r\n" in clean_text:
        clean_text = clean_text.split("\r\n\r\n", 1)[1]
    clean_text = clean_text.strip()

    # 1. Real stacktrace signature -> DEVIATION
    resp_lower = resp_text.lower()
    stacktrace_signatures = [
        "traceback (most recent call last)",
        "panic:",
        "stack trace",
        "uncaughtexception",
        "unhandledrejection",
    ]
    if any(sig in resp_lower for sig in stacktrace_signatures):
        return Verdict.DEVIATION, "stacktrace in response"

    # 2. Transport / schema safe rejection:
    # Check JSON-RPC safe error codes and schema validation blocks
    if (
        classify_response(clean_text) == ClassifierVerdict.SAFE
        or classify_response(resp_text) == ClassifierVerdict.SAFE
        or _is_jsonrpc_safe(clean_text, None)
        or _is_jsonrpc_safe(resp_text, None)
    ):
        return Verdict.TRANSPORT_REJECT, "JSON-RPC safe error or schema validation reject"

    try:
        parsed = json.loads(clean_text)
        if isinstance(parsed, dict):
            # Check JSON-RPC error codes
            if "error" in parsed and isinstance(parsed["error"], dict):
                code = parsed["error"].get("code")
                if code in SAFE_JSONRPC_CODES:
                    return Verdict.TRANSPORT_REJECT, f"JSON-RPC safe error code {code}"

            # Check for transport notifications / exception handler logging (e.g. lone surrogate)
            if (
                parsed.get("method") == "notifications/message"
                or "mcp.server.exception_handler" in clean_text
            ):
                return Verdict.TRANSPORT_REJECT, "Transport-layer rejection via exception handler"

            # Check MCP CallToolResult with isError: true and error message
            if parsed.get("result", {}).get("isError") is True:
                content = parsed.get("result", {}).get("content", [])
                for blk in content:
                    txt = blk.get("text", "")
                    if classify_response(txt) == ClassifierVerdict.SAFE:
                        return (
                            Verdict.TRANSPORT_REJECT,
                            "Schema validation rejection in tool result",
                        )
    except Exception:
        pass

    if "mcp.server.exception_handler" in clean_text:
        return Verdict.TRANSPORT_REJECT, "Transport-layer rejection via exception handler"

    # 3. Payload reflected -> DEVIATION
    tokens = _extract_payload_tokens(payload, baseline)
    for token in tokens:
        if token in resp_text:
            return Verdict.DEVIATION, "payload reflected"

    # 4. Response shape deviation
    current_shape = normalize_shape(resp_text)
    if baseline and baseline.response_shape:
        if current_shape != baseline.response_shape:
            return (
                Verdict.DEVIATION,
                f"response shape deviation: {current_shape} != {baseline.response_shape}",
            )

    # 5. Size deviation
    resp_len = len(resp_bytes) if isinstance(resp_bytes, bytes) else len(resp_text)
    if baseline and baseline.size_range:
        min_sz, max_sz = baseline.size_range
        if max_sz > 0 and (resp_len > max(1000, max_sz * 5)):
            return (
                Verdict.DEVIATION,
                f"response size {resp_len} far outside baseline {baseline.size_range}",
            )
    elif resp_len > 100_000:
        return Verdict.DEVIATION, f"oversized response ({resp_len} bytes)"

    # 6. Latency deviation
    baseline_lat = baseline.baseline_latency_ms if baseline else 1000.0
    if elapsed_ms > 2000.0 and elapsed_ms > (baseline_lat * 3.0):
        return (
            Verdict.DEVIATION,
            f"latency spike: {elapsed_ms:.1f}ms (> 3x baseline {baseline_lat:.1f}ms and > 2000ms)",
        )

    # 7. Matches baseline
    return Verdict.CLEAN, "matches baseline"
