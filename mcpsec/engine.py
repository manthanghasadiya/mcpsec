"""
Scan engine — orchestrates scanner execution.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import ScanResult, ServerProfile, TransportType
from mcpsec.scanners.base import BaseScanner
from mcpsec.scanners.prompt_injection import PromptInjectionScanner
from mcpsec.scanners.auth_audit import AuthAuditScanner
from mcpsec.scanners.path_traversal import PathTraversalScanner
from mcpsec.scanners.command_injection import CommandInjectionScanner
from mcpsec.scanners.ssrf import SSRFScanner
from mcpsec.ui import console, print_finding, print_section, print_summary, get_progress


# ── Scanner Registry ─────────────────────────────────────────────────────────

ALL_SCANNERS: list[BaseScanner] = [
    PromptInjectionScanner(),
    AuthAuditScanner(),
    PathTraversalScanner(),
    CommandInjectionScanner(),
    SSRFScanner(),
]

SCANNER_MAP: dict[str, BaseScanner] = {s.name: s for s in ALL_SCANNERS}


def get_scanners(names: list[str] | None = None) -> list[BaseScanner]:
    """Get scanner instances by name, or all scanners if no names given."""
    if not names:
        return ALL_SCANNERS
    return [SCANNER_MAP[n] for n in names if n in SCANNER_MAP]


# ── Scan Engine ──────────────────────────────────────────────────────────────

async def run_scan(
    profile: ServerProfile,
    client: MCPSecClient | None = None,
    scanner_names: list[str] | None = None,
    target: str = "",
    transport: TransportType = TransportType.STDIO,
) -> ScanResult:
    """Run all selected scanners against a server profile."""

    scanners = get_scanners(scanner_names)

    result = ScanResult(
        scan_id=str(uuid.uuid4())[:8],
        target=target,
        transport=transport,
        server_profile=profile,
    )

    print_section("Running Scanners", "⚡")

    with get_progress() as progress:
        task = progress.add_task("Scanning...", total=len(scanners))

        for scanner in scanners:
            progress.update(task, description=f"[cyan]{scanner.name}[/cyan]")

            try:
                findings = await scanner.scan(profile, client)
                result.findings.extend(findings)
                result.scanners_run.append(scanner.name)
            except Exception as e:
                error_msg = f"Scanner '{scanner.name}' failed: {e}"
                result.errors.append(error_msg)
                console.print(f"  [warning]⚠ {error_msg}[/warning]")

            progress.advance(task)

    # ── Print findings ────────────────────────────────────────────────────
    if result.findings:
        print_section("Findings", "🔍")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.get(f.severity.value, 5)
        )
        for finding in sorted_findings:
            print_finding(
                severity=finding.severity.value,
                scanner=finding.scanner,
                tool_name=finding.tool_name,
                title=finding.title,
                detail=finding.detail[:200] if finding.detail else "",
            )

    # ── Print summary ─────────────────────────────────────────────────────
    print_section("Summary", "📊")
    print_summary(
        total=result.total_count,
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        info=result.info_count,
    )

    result.mark_complete()
    return result
