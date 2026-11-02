"""Command Injection Oracle — confirms command injection vulnerabilities by effect.

Distinguishes actual command execution from argument reflection using:
1. Unique random canary nonces with strict reflection-vs-execution guards.
2. Baseline-aware differential time-based confirmation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import inspect
import math
import re
import secrets
from typing import Any, Callable


@dataclass
class OracleResult:
    """Result of an oracle confirmation attempt."""

    confirmed: bool
    method: str | None = None  # "canary" | "timing" | None
    evidence: str = ""
    payload: str = ""


async def _invoke_call_fn(
    call_fn: Callable[..., Any], tool_name: str, args: dict[str, Any]
) -> tuple[str, float]:
    """Invoke call_fn which may be sync or async, returning (response_text, elapsed_seconds)."""
    res = call_fn(tool_name, args)
    if inspect.isawaitable(res):
        res = await res
    if isinstance(res, tuple) and len(res) >= 2:
        return str(res[0]), float(res[1])
    if isinstance(res, str):
        return res, 0.0
    return str(res), 0.0


async def confirm_command_injection(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    baseline_latency_ms: float = 0.0,
) -> OracleResult:
    """Confirm command execution via unique canary echo or baseline-aware timing.

    Args:
        call_fn: Callable(tool_name, args) -> (response_text, elapsed_seconds)
        tool_name: The target MCP tool name
        param_name: The parameter under test
        base_args: Baseline/template arguments dictionary
        baseline_latency_ms: Measured baseline latency of the tool in milliseconds

    Returns:
        OracleResult with confirmation status, method, evidence, and triggering payload.
    """
    base_args = dict(base_args or {})

    # ═══════════════════════════════════════════════════════════════
    # METHOD 1: Unique-canary echo (distinguishes execution from reflection)
    # ═══════════════════════════════════════════════════════════════
    token = "mcpsec_" + secrets.token_hex(6)
    canary_templates = [
        "; echo {token}",
        "| echo {token}",
        "& echo {token}",
        "$(echo {token})",
        "`echo {token}`",
    ]

    for template in canary_payloads_for_token(canary_templates, token):
        test_args = dict(base_args)
        test_args[param_name] = template

        try:
            resp_text, elapsed = await _invoke_call_fn(call_fn, tool_name, test_args)
        except Exception:
            continue

        if token in resp_text:
            # Reflection guard:
            # When a shell executes `echo <token>`, stdout contains only `<token>`.
            # If the response echoes the injected command verbatim or contains
            # `echo <token>`, the argument was reflected as text without execution.
            if template in resp_text or re.search(rf"\becho\s+{re.escape(token)}", resp_text):
                continue

            return OracleResult(
                confirmed=True,
                method="canary",
                evidence=f"Unique canary nonce '{token}' found in output without command syntax",
                payload=template,
            )

    # ═══════════════════════════════════════════════════════════════
    # METHOD 2: Baseline-aware differential time-based confirmation
    # ═══════════════════════════════════════════════════════════════
    base_sec = max(0.0, float(baseline_latency_ms) / 1000.0)
    d1 = max(5, int(math.ceil(base_sec)) + 4)
    d2 = d1 + 2

    timing_templates = [
        "; sleep {D}",
        "$(sleep {D})",
        "& timeout {D}",
        "| sleep {D}",
    ]

    for tmpl in timing_templates:
        p1 = tmpl.format(D=d1)
        args1 = dict(base_args)
        args1[param_name] = p1

        try:
            resp1, elapsed1 = await _invoke_call_fn(call_fn, tool_name, args1)
        except Exception:
            continue

        # Check if elapsed1 is delayed relative to baseline and expected d1
        if elapsed1 >= (base_sec + d1 * 0.8) and elapsed1 >= (base_sec + d1 - 1.0):
            # Verify with d2 to confirm timing scales with sleep duration (differential)
            p2 = tmpl.format(D=d2)
            args2 = dict(base_args)
            args2[param_name] = p2

            try:
                resp2, elapsed2 = await _invoke_call_fn(call_fn, tool_name, args2)
            except Exception:
                continue

            # Confirm scaling: elapsed2 should be at least (d2 - d1) * 0.7 longer than elapsed1
            if elapsed2 >= (base_sec + d2 * 0.8) and (elapsed2 - elapsed1) >= ((d2 - d1) * 0.7):
                return OracleResult(
                    confirmed=True,
                    method="timing",
                    evidence=(
                        f"Baseline-aware differential delay confirmed: {elapsed1:.2f}s (sleep {d1}s) "
                        f"and {elapsed2:.2f}s (sleep {d2}s) against baseline {base_sec:.2f}s"
                    ),
                    payload=p1,
                )

    return OracleResult(
        confirmed=False,
        method=None,
        evidence="No command execution confirmed",
        payload="",
    )


def canary_payloads_for_token(templates: list[str], token: str) -> list[str]:
    """Format template payloads with unique canary token."""
    return [t.format(token=token) for t in templates]


def confirm_command_injection_sync(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    baseline_latency_ms: float = 0.0,
) -> OracleResult:
    """Synchronous helper for confirm_command_injection."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(
                asyncio.run,
                confirm_command_injection(
                    call_fn, tool_name, param_name, base_args, baseline_latency_ms
                ),
            ).result()
    else:
        return asyncio.run(
            confirm_command_injection(
                call_fn, tool_name, param_name, base_args, baseline_latency_ms
            )
        )
