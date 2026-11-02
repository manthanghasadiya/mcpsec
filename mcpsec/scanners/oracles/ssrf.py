"""SSRF Oracle — confirms Server-Side Request Forgery vulnerabilities by out-of-band effect.

Distinguishes actual server fetching from argument reflection by requiring an
inbound HTTP request to a controlled collector.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any, Callable

from .command_injection import OracleResult
from .oob_collector import OOBCollector


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


async def confirm_ssrf(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    collector: OOBCollector | None = None,
    settle_seconds: float = 2.0,
) -> OracleResult:
    """Confirm SSRF execution via out-of-band HTTP interaction.

    Args:
        call_fn: Callable(tool_name, args) -> (response_text, elapsed_seconds) or response_text
        tool_name: The target MCP tool or resource name
        param_name: The parameter under test
        base_args: Baseline/template arguments dictionary
        collector: Active OOBCollector instance (or None to create temporary)
        settle_seconds: Seconds to wait for out-of-band hit after invocation

    Returns:
        OracleResult with confirmation status, method, evidence, and triggering URL.
    """
    owns_collector = False
    if collector is None:
        collector = OOBCollector()
        collector.start()
        owns_collector = True

    try:
        token, url = collector.new_probe()
        test_args = dict(base_args or {})
        test_args[param_name] = url

        try:
            await _invoke_call_fn(call_fn, tool_name, test_args)
        except Exception:
            # Server error may still have occurred after making the outbound request
            pass

        hit = collector.received(token, settle=settle_seconds)
        if hit is not None:
            src_ip = hit.get("source_ip", "unknown")
            method = hit.get("method", "GET")
            path = hit.get("path", f"/{token}")
            ts = hit.get("timestamp", time.time())
            evidence = (
                f"Out-of-band HTTP request received for token '{token}' from {src_ip} "
                f"({method} {path} at {ts})"
            )
            return OracleResult(
                confirmed=True,
                method="oob-http",
                evidence=evidence,
                payload=url,
            )

        return OracleResult(
            confirmed=False,
            method=None,
            evidence="No out-of-band HTTP request received",
            payload=url,
        )
    finally:
        if owns_collector:
            collector.stop()


def confirm_ssrf_sync(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    collector: OOBCollector | None = None,
    settle_seconds: float = 2.0,
) -> OracleResult:
    """Synchronous helper for confirm_ssrf."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(
                asyncio.run,
                confirm_ssrf(
                    call_fn,
                    tool_name,
                    param_name,
                    base_args,
                    collector,
                    settle_seconds,
                ),
            ).result()
    else:
        return asyncio.run(
            confirm_ssrf(
                call_fn,
                tool_name,
                param_name,
                base_args,
                collector,
                settle_seconds,
            )
        )
