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
import shlex
import subprocess
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
    async with MCPSecClient() as client:
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
            if stdio_cmd:
                await _run_connection_diagnostics(stdio_cmd)
            else:
                console.print(f"  [muted]Make sure the MCP server is running and accessible at {http_url}[/muted]")
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

    # Exit with non-zero if critical/high findings
    if result.critical_count > 0 or result.high_count > 0:
        raise typer.Exit(1)


async def _run_connection_diagnostics(command: str):
    """Run the command manually to see why it's failing."""
    console.print("\n  [accent]🔍 Running diagnostics...[/accent]")
    
    try:
        # We run the command with stderr captured
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Give it a few seconds to fail
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            process.kill()
            console.print("  [muted]Server stayed running during diagnostics. Issue might be protocol-related.[/muted]")
            return

        error_out = stderr.decode().strip()
        if error_out:
            console.print("  [bold red]Server Error Output:[/bold red]")
            for line in error_out.splitlines():
                console.print(f"    [dim white]{line}[/dim white]")
            
            # Specific hint for common typo
            if "@anthropic-ai/mcp-server-memory" in command.lower():
                console.print("\n  [tip]💡 Hint: The package name might be @modelcontextprotocol/server-memory[/tip]")
            elif "404" in error_out:
                console.print("\n  [tip]💡 Hint: NPM 404 error indicates the package name is likely incorrect.[/tip]")
        else:
            console.print(f"  [muted]Server exited with code {process.returncode} but no error message.[/muted]")
            
    except Exception as diag_err:
        console.print(f"  [muted]Diagnostics failed: {diag_err}[/muted]")


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

    async with MCPSecClient() as client:
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


# ─── AUDIT COMMAND ───────────────────────────────────────────────────────────

@app.command()
def audit(
    npm: Optional[str] = typer.Option(None, "--npm", help="NPM package to audit"),
    github: Optional[str] = typer.Option(None, "--github", help="GitHub repository URL to audit"),
    path: Optional[str] = typer.Option(None, "--path", help="Local directory path to audit"),
):
    """
    🔬 Audit source code for vulnerabilities (static analysis).
    """
    if not any([npm, github, path]):
        console.print("[danger]Error: Specify --npm, --github, or --path[/danger]")
        raise typer.Exit(1)
    
    if sum([bool(npm), bool(github), bool(path)]) > 1:
        console.print("[danger]Error: Specify only one source (npm, github, or path)[/danger]")
        raise typer.Exit(1)

    _run_async(_audit_async(npm, github, path))

async def _audit_async(npm: str | None, github: str | None, path: str | None):
    from mcpsec.static.audit_engine import run_audit
    from mcpsec.models import Finding
    
    print_banner(small=True)
    print_section("Static Audit", "🔬")
    
    findings = await run_audit(npm, github, path)
    
    if not findings:
        console.print("\n  [success]✔ No vulnerabilities found.[/success]")
        return

    console.print(f"\n  [danger]Found {len(findings)} issues:[/danger]\n")
    
    # Identify critical/high findings
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")

    # Display findings
    for f in findings:
        _print_finding_detail(f)
        
    if critical_count > 0 or high_count > 0:
        raise typer.Exit(1)

def _print_finding_detail(f):
    """Print detailed finding for audit."""
    color = "red" if f.severity in ("critical", "high") else "yellow"
    if f.severity == "info": color = "blue"
    
    console.print(f"  [{color} bold]{f.severity.upper():<8}[/{color} bold]  {f.title}")
    if f.file_path:
        # Show relative path if possible
        try:
             # Just show the name or partial path for cleanliness
             # p = Path(f.file_path).name 
             # But complete path is better for triage
             p = f.file_path
        except:
             p = f.file_path
        console.print(f"            [dim]file={p}  line={f.line_number}[/dim]")
    
    if f.code_snippet:
        # Indent code snippet
        snippet = "\n".join(f"            {line}" for line in f.code_snippet.splitlines())
        console.print(f"[dim]{snippet}[/dim]")
        
    console.print(f"            {f.description}")
    if f.remediation:
        console.print(f"            [dim]Remediation: {f.remediation}[/dim]")
    if f.taint_flow:
        console.print(f"            [cyan]Flow: {f.taint_flow}[/cyan]")
    console.print()

# ─── FUZZ COMMAND ────────────────────────────────────────────────────────────

@app.command()
def fuzz(
    stdio: str = typer.Option(..., "--stdio", "-s", help="MCP server command"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Per-test response timeout in seconds"),
    startup_timeout: float = typer.Option(15.0, "--startup-timeout", help="Server startup/initialization timeout in seconds"),
    framing: str = typer.Option("auto", "--framing", "-f", help="Message framing: 'auto', 'jsonl' (Python), or 'clrf' (Node)"),
    generators: str = typer.Option(None, "--generators", "-g", help="Comma-separated generator names"),
    output: str = typer.Option(None, "--output", "-o", help="Save results to JSON"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print raw responses for debugging"),
):
    """
    🔥 Fuzz an MCP server with malformed protocol messages.
    
    Generates thousands of adversarial JSON-RPC messages to find crashes,
    hangs, and parsing bugs at the protocol level.
    """
    from mcpsec.fuzzer.fuzz_engine import FuzzEngine
    
    print_banner()
    print_target_info("MCP Server (Fuzz)", stdio[:80], "stdio")
    
    gen_list = [g.strip() for g in generators.split(",")] if generators else None
    
    engine = FuzzEngine(stdio, timeout, startup_timeout, framing, debug)
    summary = engine.run(gen_list)
    
    # Print results
    print_section("Fuzz Results", "🔥")
    console.print(f"  [accent]Total tests:[/accent] {summary['total_tests']}")
    console.print(f"  [danger]Crashes:[/danger] {summary['crashes']}" if summary['crashes'] else f"  [success]Crashes:[/success] 0")
    console.print(f"  [warning]Timeouts:[/warning] {summary['timeouts']}" if summary['timeouts'] else f"  [success]Timeouts:[/success] 0")
    console.print(f"  [accent]Interesting:[/accent] {summary['interesting']}" if summary['interesting'] else f"  [muted]Interesting:[/muted] 0")
    
    if summary['interesting_cases']:
        console.print()
        for ic in summary['interesting_cases']:
            icon = "🔴" if ic['crashed'] else "🟡" if ic['timeout'] else "🟠"
            status = "CRASH" if ic['crashed'] else "TIMEOUT" if ic['timeout'] else "ANOMALY"
            console.print(f"  {icon} [{status}] {ic['case_name']} ({ic['generator']})")
            console.print(f"       {ic['description']}")
            if ic['error']:
                console.print(f"       [muted]{ic['error'][:100]}[/muted]")
            console.print()
    
    if output:
        import json
        Path(output).write_text(json.dumps(summary, indent=2))
        console.print(f"  [success]✔ Results saved to {output}[/success]")

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
