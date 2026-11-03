"""Path Traversal Oracle — confirms path traversal vulnerabilities by effect.

Distinguishes actual file access from argument reflection using a sentinel file
planted with unique random contents on disk.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import secrets
import tempfile
from typing import Any, Callable

from .command_injection import OracleResult


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


def _build_candidate_payloads(sentinel_path: str) -> list[str]:
    """Build candidate traversal payloads targeting the sentinel file path."""
    abs_path = os.path.abspath(sentinel_path)
    payloads = [
        abs_path,
        f"file://{abs_path}",
    ]

    # Relative ../ ladders resolving to the sentinel
    rel_base = abs_path.lstrip("/")
    for depth in range(1, 13):
        payloads.append(f"{'../' * depth}{rel_base}")

    # Common encoding / normalization variants
    payloads.extend([
        f"{'..%2f' * 3}{rel_base}",
        f"{'..%252f' * 3}{rel_base}",
        f"{'%2e%2e/' * 3}{rel_base}",
        f"{'....//' * 3}{rel_base}",
    ])

    return payloads


async def confirm_path_traversal(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    sentinel_dir: str | None = None,
) -> OracleResult:
    """Confirm path traversal vulnerability via sentinel file read.

    Args:
        call_fn: Callable(tool_name, args) -> (response_text, elapsed_seconds) or response_text
        tool_name: Target MCP tool name
        param_name: Parameter under test
        base_args: Baseline arguments dictionary
        sentinel_dir: Directory where sentinel file will be created (defaults to tempdir)

    Returns:
        OracleResult with confirmation status, method, evidence, and triggering payload.
    """
    target_dir = sentinel_dir or tempfile.gettempdir()
    path_nonce = secrets.token_hex(8)
    token = secrets.token_hex(16)
    sentinel_filename = f"mcpsec_sentinel_{path_nonce}.txt"
    sentinel_path = os.path.join(target_dir, sentinel_filename)
    sentinel_content = f"MCPSEC_PT_SENTINEL_{token}\n{token}\n"

    # Plant the sentinel file
    with open(sentinel_path, "w", encoding="utf-8") as f:
        f.write(sentinel_content)

    try:
        candidate_payloads = _build_candidate_payloads(sentinel_path)

        for payload in candidate_payloads:
            test_args = dict(base_args or {})
            test_args[param_name] = payload

            try:
                resp_text, _ = await _invoke_call_fn(call_fn, tool_name, test_args)
            except Exception:
                continue

            if token in resp_text:
                evidence = (
                    f"Sentinel file content token '{token}' retrieved via payload: {payload}"
                )
                return OracleResult(
                    confirmed=True,
                    method="sentinel-file",
                    evidence=evidence,
                    payload=payload,
                )

        return OracleResult(
            confirmed=False,
            method=None,
            evidence="No sentinel content retrieved",
            payload="",
        )
    finally:
        if os.path.exists(sentinel_path):
            try:
                os.remove(sentinel_path)
            except OSError:
                pass


def confirm_path_traversal_sync(
    call_fn: Callable[..., Any],
    tool_name: str,
    param_name: str,
    base_args: dict[str, Any] | None = None,
    sentinel_dir: str | None = None,
) -> OracleResult:
    """Synchronous helper for confirm_path_traversal."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(
                asyncio.run,
                confirm_path_traversal(
                    call_fn,
                    tool_name,
                    param_name,
                    base_args,
                    sentinel_dir,
                ),
            ).result()
    else:
        return asyncio.run(
            confirm_path_traversal(
                call_fn,
                tool_name,
                param_name,
                base_args,
                sentinel_dir,
            )
        )
