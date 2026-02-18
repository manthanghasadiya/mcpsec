"""
mcpsec CLI — the main entry point.

Usage:
    mcpsec scan --stdio "npx @anthropic/mcp-server-git --repo /tmp/test"
    mcpsec scan --http http://localhost:3000/mcp
    mcpsec info --stdio "python my_server.py"
    mcpsec list-scanners
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box

from mcpsec.ui import (
    console,
    print_banner,
    print_target_info,
    print_tool_info,
    print_section,
    get_progress,
)
from mcpsec.models import TransportType

app = typer.Typer(
    name="mcpsec",
    help="⚡ MCP Security Scanner — pentest your AI agent's tool connections.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


def _run_async(coro):
    """Run an async function from sync context."""
    return asyncio.run(coro)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """mcpsec — Security scanner for MCP servers."""
    if ctx.invoked_subcommand is None:
        print_banner()


# ─── SCAN COMMAND ────────────────────────────────────────────────────────────

@app.command()
def scan(
    stdio: Optional[str] = typer.Option(
        None,
        "--stdio", "-s",
        help="MCP server command to launch via stdio (e.g. 'npx @modelcontextprotocol/server-filesystem /tmp')",
    ),
    http: Optional[str] = typer.Option(
        None,
        "--http", "-H",
        help="MCP server HTTP URL (e.g. 'http://localhost:3000/mcp')",
    ),
    scanners: Optional[str] = typer.Option(
        None,
        "--scanners", "-S",
        help="Comma-separated list of scanners to run (default: all)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path for JSON report",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Minimal output (no banner, no tool listing)",
    ),
):
    """
    🔍 Scan an MCP server for security vulnerabilities.

    Connect to a running MCP server, enumerate its tools/resources/prompts,
    and run security scanners against them.
    """
    if not stdio and not http:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)

    if stdio and http:
        console.print("[danger]Error: Specify only one of --stdio or --http[/danger]")
        raise typer.Exit(1)

    scanner_names = [s.strip() for s in scanners.split(",")] if scanners else None

    _run_async(_scan_async(
        stdio_cmd=stdio,
        http_url=http,
        scanner_names=scanner_names,
        output_path=output,
        quiet=quiet,
    ))


async def _scan_async(
    stdio_cmd: str | None,
    http_url: str | None,
    scanner_names: list[str] | None,
    output_path: str | None,
    quiet: bool,
):
    from mcpsec.client.mcp_client import MCPSecClient
    from mcpsec.engine import run_scan

    if not quiet:
        print_banner()

    target = stdio_cmd or http_url or ""
    transport = TransportType.STDIO if stdio_cmd else TransportType.HTTP

    print_target_info(
        target_type="MCP Server",
        target=target[:80],
        transport=transport.value,
    )

    # ── Connect ──────────────────────────────────────────────────────────
    print_section("Connecting", "🔌")
    client = MCPSecClient()

    try:
        if stdio_cmd:
            with get_progress() as p:
                task = p.add_task("Connecting via stdio...", total=None)
                profile = await client.connect_stdio(stdio_cmd)
                p.update(task, completed=True)
        else:
            with get_progress() as p:
                task = p.add_task("Connecting via HTTP...", total=None)
                profile = await client.connect_http(http_url)
                p.update(task, completed=True)
    except Exception as e:
        console.print(f"\n  [danger]✗ Connection failed: {e}[/danger]")
        console.print(f"  [muted]Make sure the MCP server is running and accessible.[/muted]")
        raise typer.Exit(1)

    console.print(f"  [success]✔ Connected[/success]")

    # ── Enumerate ────────────────────────────────────────────────────────
    print_section("Attack Surface", "🎯")
    console.print(
        f"  [accent]Tools:[/accent] {len(profile.tools)}  "
        f"[accent]Resources:[/accent] {len(profile.resources)}  "
        f"[accent]Prompts:[/accent] {len(profile.prompts)}"
    )
    console.print()

    if not quiet:
        for tool in profile.tools:
            print_tool_info(tool.name, tool.description, tool.parameters)

    if not profile.tools and not profile.resources:
        console.print("  [muted]No tools or resources found. Nothing to scan.[/muted]")
        await client.close()
        raise typer.Exit(0)

    # ── Scan ─────────────────────────────────────────────────────────────
    result = await run_scan(
        profile=profile,
        client=client,
        scanner_names=scanner_names,
        target=target,
        transport=transport,
    )

    # ── Output ───────────────────────────────────────────────────────────
    if output_path:
        from mcpsec.reporters.json_report import generate_json_report
        if generate_json_report(result, output_path):
            console.print(f"  [success]✔ Report saved to {output_path}[/success]")
        else:
            console.print(f"  [danger]✗ Failed to save report to {output_path}[/danger]")

    await client.close()

    # Exit with non-zero if critical/high findings
    if result.critical_count > 0 or result.high_count > 0:
        raise typer.Exit(1)


# ─── INFO COMMAND ────────────────────────────────────────────────────────────

@app.command()
def info(
    stdio: Optional[str] = typer.Option(None, "--stdio", "-s", help="MCP server stdio command"),
    http: Optional[str] = typer.Option(None, "--http", "-H", help="MCP server HTTP URL"),
):
    """
    ℹ️  Enumerate an MCP server's tools, resources, and prompts (no scanning).
    """
    if not stdio and not http:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)

    _run_async(_info_async(stdio_cmd=stdio, http_url=http))


async def _info_async(stdio_cmd: str | None, http_url: str | None):
    from mcpsec.client.mcp_client import MCPSecClient

    print_banner(small=True)

    target = stdio_cmd or http_url or ""
    transport = "stdio" if stdio_cmd else "http"
    print_target_info("MCP Server", target[:80], transport)

    client = MCPSecClient()
    try:
        if stdio_cmd:
            profile = await client.connect_stdio(stdio_cmd)
        else:
            profile = await client.connect_http(http_url)
    except Exception as e:
        console.print(f"\n  [danger]✗ Connection failed: {e}[/danger]")
        raise typer.Exit(1)

    # ── Tools ────────────────────────────────────────────────────────────
    print_section("Tools", "🔧")
    if profile.tools:
        for tool in profile.tools:
            print_tool_info(tool.name, tool.description, tool.parameters)
            if tool.annotations:
                ann_str = "  ".join(f"{k}={v}" for k, v in tool.annotations.items())
                console.print(f"    [muted]annotations: {ann_str}[/muted]")
            console.print()
    else:
        console.print("  [muted]No tools exposed.[/muted]")

    # ── Resources ────────────────────────────────────────────────────────
    print_section("Resources", "📄")
    if profile.resources:
        for res in profile.resources:
            console.print(f"  [param]{res.uri}[/param]")
            if res.description:
                console.print(f"    [muted]{res.description}[/muted]")
    else:
        console.print("  [muted]No resources exposed.[/muted]")

    # ── Prompts ──────────────────────────────────────────────────────────
    print_section("Prompts", "💬")
    if profile.prompts:
        for prompt in profile.prompts:
            args_str = ", ".join(a["name"] for a in prompt.arguments) if prompt.arguments else "none"
            console.print(f"  [tool_name]{prompt.name}[/tool_name]  args=({args_str})")
            if prompt.description:
                console.print(f"    [muted]{prompt.description}[/muted]")
    else:
        console.print("  [muted]No prompts exposed.[/muted]")

    # ── Stats ────────────────────────────────────────────────────────────
    console.print()
    console.print(
        f"  [accent]Total attack surface:[/accent] "
        f"{len(profile.tools)} tools, "
        f"{len(profile.resources)} resources, "
        f"{len(profile.prompts)} prompts"
    )
    console.print()

    await client.close()


# ─── LIST-SCANNERS COMMAND ───────────────────────────────────────────────────

@app.command("list-scanners")
def list_scanners():
    """📋 List all available security scanners."""
    from mcpsec.engine import ALL_SCANNERS

    print_banner(small=True)
    console.print()

    table = Table(
        box=box.SIMPLE_HEAVY,
        title="[bold cyan]Available Scanners[/bold cyan]",
        border_style="dim cyan",
        padding=(0, 2),
    )
    table.add_column("Scanner", style="bold cyan")
    table.add_column("Description", style="muted")

    for scanner in ALL_SCANNERS:
        table.add_row(scanner.name, scanner.description)

    console.print(table)
    console.print()


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
