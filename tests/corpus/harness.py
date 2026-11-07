"""
Corpus test harness for data-driven recall testing of MCP servers.

Provides generic primitives for:
- Checking target runtime availability (requires_target)
- Managing stdio server lifecycles (launch_stdio)
- Running scan campaigns and retrieving findings (run_scan)
- Running fuzzing campaigns and analyzing crashes (run_fuzz)
- Verifying recall assertions (assert_detects)
- Loading local, gitignored target manifests (load_local_targets)
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Any, Callable, Generator, List, Optional

import pytest

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.engine import run_scan as engine_run_scan
from mcpsec.fuzzer.fuzz_engine import FuzzEngine
from mcpsec.models import Finding, ScanResult

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ---------------------------------------------------------------------------
# Skip Helper
# ---------------------------------------------------------------------------


def requires_target(check: Any) -> None:
    """Pytest skip helper.

    Skips cleanly when a target server, runtime, or command is absent,
    ensuring that CI and clean clones remain green without errors.
    """
    if isinstance(check, str):
        # Extract binary or first command argument
        command_str = check.strip()
        if not command_str:
            pytest.skip("Target command is empty")
        parts = shlex.split(command_str, posix=(sys.platform != "win32"))
        if not parts:
            pytest.skip("Target command could not be parsed")
        first = parts[0]
        # Check direct path or resolved executable
        if os.path.exists(first):
            return
        resolved = shutil.which(first)
        if sys.platform == "win32" and not resolved:
            for ext in (".exe", ".cmd", ".bat"):
                resolved = shutil.which(first + ext)
                if resolved:
                    break
        if not resolved:
            pytest.skip(f"Target executable or command not found: {first}")
    elif callable(check):
        try:
            res = check()
            if not res:
                pytest.skip("Target prerequisite check returned falsy")
        except Exception as e:
            pytest.skip(f"Target prerequisite check failed: {e}")
    elif isinstance(check, bool):
        if not check:
            pytest.skip("Target prerequisite check is False")


# ---------------------------------------------------------------------------
# Context Manager: Stdio Launch
# ---------------------------------------------------------------------------


@contextmanager
def launch_stdio(
    cmd: str | list[str], env: dict[str, str] | None = None
) -> Generator[subprocess.Popen, None, None]:
    """Start a target MCP server over stdio and tear it down cleanly."""
    if isinstance(cmd, str):
        parts = shlex.split(cmd, posix=(sys.platform != "win32"))
    else:
        parts = list(cmd)

    if not parts:
        raise ValueError("Cannot launch stdio server with empty command")

    executable = parts[0]
    if sys.platform == "win32":
        resolved = None
        for ext in ("", ".exe", ".cmd", ".bat"):
            candidate = shutil.which(executable + ext)
            if candidate:
                resolved = candidate
                break
        if resolved:
            parts[0] = resolved

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    proc = subprocess.Popen(
        parts,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=merged_env,
        shell=False,
    )
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream and not stream.closed:
                try:
                    stream.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Scan Runner
# ---------------------------------------------------------------------------


def run_scan(
    target: str,
    scanners: list[str] | None = None,
    max_params: int | None = None,
) -> list[Finding]:
    """Connect to a target MCP server over stdio, run scanners, and return findings."""

    async def _execute_scan() -> list[Finding]:
        async with MCPSecClient() as client:
            profile = await client.connect_stdio(target)
            if max_params and max_params > 0:
                for tool in profile.tools:
                    if len(tool.parameters) > max_params:
                        trimmed = dict(list(tool.parameters.items())[:max_params])
                        tool.parameters = trimmed
            scan_result: ScanResult = await engine_run_scan(
                profile=profile,
                client=client,
                scanner_names=scanners,
                target=target,
            )
            return scan_result.findings

    return asyncio.run(_execute_scan())


# ---------------------------------------------------------------------------
# Fuzz Runner and Crash Reporting
# ---------------------------------------------------------------------------


@dataclass
class CrashInfo:
    """Details of a single fuzzer crash event."""

    case_name: str
    generator: str
    payload: bytes
    error_message: str
    real: bool
    returncode: int | None = None
    verdict: str = ""
    verdict_reason: str = ""


@dataclass
class FuzzReport:
    """Summary and details of a fuzzing campaign."""

    total_tests: int
    crashes: list[CrashInfo]
    results: list[Any] = field(default_factory=list)
    raw_summary: dict = field(default_factory=dict)

    @property
    def real_crashes(self) -> list[CrashInfo]:
        """Filter crashes verified as dead server processes."""
        return [c for c in self.crashes if c.real]


def run_fuzz(
    target: str,
    generators: list[str] | None = None,
) -> FuzzReport:
    """Run a fuzzing campaign against the target and return a FuzzReport.

    Each detected crash explicitly distinguishes whether the target process was
    verified dead (real) versus a harness-side pipe break (false crash).
    """
    engine = FuzzEngine(command=target, timeout=2.0)
    summary = engine.run(generators=generators)

    crashes: list[CrashInfo] = []

    # Map interesting cases for case metadata
    case_by_name = {case.name: case for case, _ in engine.interesting}

    for res in engine.results:
        if res.crashed:
            err = (res.error_message or "").lower()
            # Distinguish verified process death from harness pipe break
            # Real crashes produce exit codes (e.g. exit_code_139, exit_code_3221225477)
            # or stacktrace/segfault indications in stderr
            is_real = False
            returncode = None
            if "exit_code_" in err:
                is_real = True
                try:
                    code_str = err.split("exit_code_")[1].split()[0]
                    returncode = int(code_str)
                except (IndexError, ValueError):
                    pass
            elif any(k in err for k in ("crash_with_stacktrace", "sigsegv", "segfault", "access_violation")):
                is_real = True
            elif "broken pipe" in err or "brokenpipe" in err or "errno 32" in err:
                is_real = False
            else:
                # Conservative fallback: if error indicates process death
                is_real = bool(res.error_message and "pipe" not in err)

            c_name = getattr(res, "case_name", "")
            gen_name = res.generator
            c_payload = res.payload
            if not c_name and gen_name:
                c_name = f"{gen_name}_{res.test_id}"
            if c_name in case_by_name:
                matched_case = case_by_name[c_name]
                c_payload = matched_case.payload

            crashes.append(
                CrashInfo(
                    case_name=c_name,
                    generator=gen_name,
                    payload=c_payload,
                    error_message=res.error_message or "",
                    real=is_real,
                    returncode=returncode,
                    verdict=getattr(res, "verdict", ""),
                    verdict_reason=getattr(res, "verdict_reason", ""),
                )
            )

    return FuzzReport(
        total_tests=summary.get("total_tests", len(engine.results)),
        crashes=crashes,
        results=engine.results,
        raw_summary=summary,
    )


# ---------------------------------------------------------------------------
# Recall Assertion
# ---------------------------------------------------------------------------

CONFIDENCE_RANK = {
    "info": 0,
    "suspected": 1,
    "low": 1,
    "medium": 2,
    "likely": 2,
    "high": 3,
    "confirmed": 4,
}


def assert_detects(
    findings: list[Finding],
    scanner: str,
    tool: str = "",
    attack_type: str | None = None,
    min_confidence: str = "suspected",
) -> None:
    """Assert that a scan finding matching the given criteria was detected."""
    min_rank = CONFIDENCE_RANK.get(min_confidence.lower(), 1)

    matching: list[Finding] = []
    for f in findings:
        f_scanner = (f.scanner or "").lower()
        target_scanner = scanner.lower()
        if target_scanner not in f_scanner and f_scanner not in target_scanner:
            continue

        if tool:
            f_tool = (f.tool_name or "").lower()
            f_param = (f.parameter or "").lower()
            target_tool = tool.lower()
            if target_tool != f_tool and target_tool != f_param and target_tool not in (f.title or "").lower():
                continue

        if attack_type:
            target_attack = attack_type.lower()
            content = f"{f.title} {f.description} {f.detail}".lower()
            if target_attack not in content:
                continue

        f_rank = CONFIDENCE_RANK.get((f.confidence or "").lower(), 1)
        if f_rank < min_rank:
            continue

        matching.append(f)

    if not matching:
        finding_summaries = [
            f"[{f.scanner}] tool={f.tool_name} param={f.parameter} conf={f.confidence} title={f.title}"
            for f in findings
        ]
        msg = (
            f"Expected detection not found: scanner='{scanner}', tool='{tool}', "
            f"attack_type='{attack_type}', min_confidence='{min_confidence}'.\n"
            f"Total findings detected: {len(findings)}\n"
            + "\n".join(f"  - {s}" for s in finding_summaries)
        )
        raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Manifest Discovery
# ---------------------------------------------------------------------------


def load_local_targets() -> list[dict]:
    """Discover target manifests from the local gitignored targets_local directory.

    Returns an empty list when the directory does not exist or contains no manifests.
    """
    targets_dir = Path(__file__).parent / "targets_local"
    if not targets_dir.is_dir():
        return []

    manifests: list[dict] = []
    for path in sorted(targets_dir.iterdir()):
        if path.is_file() and path.suffix.lower() in (".yaml", ".yml", ".json"):
            try:
                content = path.read_text(encoding="utf-8")
                if path.suffix.lower() == ".json":
                    data = json.loads(content)
                elif HAS_YAML:
                    data = yaml.safe_load(content)
                else:
                    data = json.loads(content)
                if isinstance(data, dict):
                    if "ref" not in data:
                        data["ref"] = path.stem
                    manifests.append(data)
            except Exception as e:
                # Malformed manifest: skip or log
                continue

    return manifests
