"""SQL Injection Oracle — confirms SQL injection vulnerabilities by effect.

Distinguishes genuine SQL injection from search response variations, reflection,
and static errors using:
1. Directional boolean-differential verification:
   Confirms only when TRUE condition preserves the baseline result set and
   FALSE condition collapses it.
2. Scaled time-based confirmation:
   Requires delay to scale across two distinct sleep durations (d1 and d2),
   rejecting one-off slow responses and flat baseline latency.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import math
import re
import secrets
import time
from typing import Any, Callable

from .command_injection import OracleResult

logger = logging.getLogger(__name__)


def _normalize_shape(text: str) -> str:
    """Normalize response shape using baseline.normalize_shape (imported lazily)."""
    from mcpsec.fuzzer.baseline import normalize_shape

    return normalize_shape(text)


VOLATILE_KEYS = {
    "timestamp",
    "time",
    "date",
    "elapsed",
    "latency",
    "request_id",
    "req_id",
    "trace_id",
    "query_time",
    "execution_time",
}

SLEEP_TEMPLATES = [
    "' OR SLEEP({D})-- -",
    "' OR pg_sleep({D})-- -",
    "'; SELECT pg_sleep({D})-- -",
    "'; SELECT SLEEP({D})-- -",
    "1 OR SLEEP({D})",
    "1 OR pg_sleep({D})",
    "' OR DBMS_LOCK.SLEEP({D})-- -",
    "SLEEP({D})",
    "pg_sleep({D})",
    "DBMS_LOCK.SLEEP({D})",
    "'; WAITFOR DELAY '0:0:{D}'-- -",
    "1; WAITFOR DELAY '0:0:{D}'-- -",
]


def _extract_text(val: Any) -> str:
    """Extract plain text string from str, CallToolResult, dict, or object."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if hasattr(val, "content"):
        content = getattr(val, "content", [])
        texts = []
        for block in content:
            t = getattr(block, "text", None)
            if t is not None:
                texts.append(str(t))
        return "\n".join(texts)
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val)
        except Exception:
            return str(val)
    return str(val)


async def _invoke_call_fn(
    call_fn: Callable[..., Any], tool_name: str, args: dict[str, Any]
) -> tuple[str, float]:
    """Invoke call_fn which may be sync or async, returning (response_text, elapsed_seconds)."""
    t0 = time.monotonic()
    res = call_fn(tool_name, args)
    if inspect.isawaitable(res):
        res = await res
    measured_elapsed = time.monotonic() - t0

    if isinstance(res, tuple) and len(res) >= 2:
        return _extract_text(res[0]), float(res[1])

    return _extract_text(res), measured_elapsed


def _clean_volatile(text: str) -> str:
    """Strip known volatile fields before shape normalization if JSON object."""
    if not text:
        return ""
    try:
        data = json.loads(text.strip())
        if isinstance(data, dict):
            cleaned = {k: v for k, v in data.items() if k.lower() not in VOLATILE_KEYS}
            return json.dumps(cleaned)
    except Exception:
        pass
    return text


def _build_boolean_pairs(seed: str, a: str, b: str) -> list[tuple[str, str, str]]:
    """Build TRUE and FALSE payload pairs for string, numeric, and parenthesis syntaxes."""
    return [
        # String-quote syntax
        ("string-quote", f"{seed}' AND '{a}'='{a}", f"{seed}' AND '{a}'='{b}"),
        ("string-quote-comment", f"{seed}' AND '{a}'='{a}'-- -", f"{seed}' AND '{a}'='{b}'-- -"),
        ("string-quote-numeric", f"{seed}' AND 1=1-- -", f"{seed}' AND 1=2-- -"),
        # Numeric / no-quote syntax
        ("numeric", f"{seed} AND 1=1", f"{seed} AND 1=2"),
        ("numeric-comment", f"{seed} AND 1=1-- -", f"{seed} AND 1=2-- -"),
        ("numeric-tokens", f"{seed} AND '{a}'='{a}'", f"{seed} AND '{a}'='{b}'"),
        # Parenthesis syntax
        ("parenthesis-numeric", f"{seed}) AND 1=1-- -", f"{seed}) AND 1=2-- -"),
        ("parenthesis-quote", f"{seed}') AND 1=1-- -", f"{seed}') AND 1=2-- -"),
        ("parenthesis-tokens", f"{seed}) AND '{a}'='{a}'-- -", f"{seed}) AND '{a}'='{b}'-- -"),
    ]


async def confirm_sqli(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    baseline_latency_ms: float = 0.0,
) -> OracleResult:
    """Confirm SQL injection via directional boolean differential or scaled timing.

    Args:
        call_fn: Callable(tool_name, args) -> (response_text, elapsed_seconds)
        tool_name: Target tool name
        param_name: Parameter under test
        base_args: Baseline template arguments dictionary
        baseline_latency_ms: Measured baseline latency in milliseconds

    Returns:
        OracleResult with confirmation status, method, evidence, and payload.
    """
    base_args = dict(base_args or {})

    # ═══════════════════════════════════════════════════════════════
    # METHOD 1: Directional Boolean-Differential Oracle
    # ═══════════════════════════════════════════════════════════════
    user_seed = base_args.get(param_name)
    seed_candidates: list[str] = []
    if user_seed not in (None, ""):
        seed_candidates.append(str(user_seed))
    for fallback in ["alice", "admin", "test", "1"]:
        if fallback not in seed_candidates:
            seed_candidates.append(fallback)

    for seed in seed_candidates:
        test_args = dict(base_args)
        test_args[param_name] = seed

        try:
            baseline_text, _ = await _invoke_call_fn(call_fn, tool_name, test_args)
        except Exception:
            continue

        stripped_base = baseline_text.strip()
        if not stripped_base or stripped_base in ("[]", "{}"):
            # Result set is empty; cannot observe a collapse on FALSE
            continue

        norm_base = _normalize_shape(_clean_volatile(baseline_text))
        if not norm_base or norm_base in ("[]", "{}"):
            continue

        a = secrets.token_hex(4)
        b = secrets.token_hex(4)
        while b == a:
            b = secrets.token_hex(4)

        pairs = _build_boolean_pairs(seed, a, b)

        for syntax_name, true_payload, false_payload in pairs:
            # 1. Send TRUE condition
            args_true = dict(base_args)
            args_true[param_name] = true_payload
            try:
                true_text, _ = await _invoke_call_fn(call_fn, tool_name, args_true)
            except Exception:
                continue

            # Reflection guard on TRUE
            if a in true_text or true_payload.strip() in true_text:
                continue
            if ("1=1" in true_payload and "1=1" in true_text) and "1=1" not in baseline_text:
                continue

            # 2. Send FALSE condition
            args_false = dict(base_args)
            args_false[param_name] = false_payload
            try:
                false_text, _ = await _invoke_call_fn(call_fn, tool_name, args_false)
            except Exception:
                continue

            # Reflection guard on FALSE
            if b in false_text or false_payload.strip() in false_text:
                continue
            if ("1=2" in false_payload and "1=2" in false_text) and "1=2" not in baseline_text:
                continue

            # 3. Directional check:
            # TRUE must preserve the baseline result shape (original result set survives).
            # FALSE must diverge from baseline shape (result set collapses).
            norm_true = _normalize_shape(_clean_volatile(true_text))
            norm_false = _normalize_shape(_clean_volatile(false_text))

            if norm_true == norm_base and norm_false != norm_base:
                return OracleResult(
                    confirmed=True,
                    method="boolean-differential",
                    evidence=(
                        f"Boolean-differential confirmed ({syntax_name}): "
                        f"TRUE payload preserved baseline shape ({norm_true[:120]}), "
                        f"FALSE payload collapsed result ({norm_false[:120]})"
                    ),
                    payload=true_payload,
                )

    # ═══════════════════════════════════════════════════════════════
    # METHOD 2: Scaled Time-Based Differential Oracle
    # ═══════════════════════════════════════════════════════════════
    base_sec = max(0.0, float(baseline_latency_ms) / 1000.0)
    d1 = max(5, int(math.ceil(base_sec)) + 4)
    d2 = d1 + 2

    for tmpl in SLEEP_TEMPLATES:
        p1 = tmpl.format(D=d1)
        args1 = dict(base_args)
        args1[param_name] = p1

        try:
            _, elapsed1 = await _invoke_call_fn(call_fn, tool_name, args1)
        except Exception:
            continue

        # Check if first sleep caused delay
        if elapsed1 >= (base_sec + d1 * 0.8):
            p2 = tmpl.format(D=d2)
            args2 = dict(base_args)
            args2[param_name] = p2

            try:
                _, elapsed2 = await _invoke_call_fn(call_fn, tool_name, args2)
            except Exception:
                continue

            # Confirm scaling between d1 and d2
            if elapsed2 >= (base_sec + d2 * 0.8) and (elapsed2 - elapsed1) >= ((d2 - d1) * 0.7):
                return OracleResult(
                    confirmed=True,
                    method="time-based",
                    evidence=(
                        f"Scaled time-based delay confirmed: {elapsed1:.2f}s (sleep {d1}s) "
                        f"and {elapsed2:.2f}s (sleep {d2}s) against baseline {base_sec:.2f}s"
                    ),
                    payload=p1,
                )

    return OracleResult(
        confirmed=False,
        method=None,
        evidence="No SQL injection confirmed",
        payload="",
    )


def confirm_sqli_sync(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    baseline_latency_ms: float = 0.0,
) -> OracleResult:
    """Synchronous helper for confirm_sqli."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(
                asyncio.run,
                confirm_sqli(call_fn, tool_name, param_name, base_args, baseline_latency_ms),
            ).result()
    else:
        return asyncio.run(
            confirm_sqli(call_fn, tool_name, param_name, base_args, baseline_latency_ms)
        )
