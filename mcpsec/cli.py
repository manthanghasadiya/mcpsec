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

from mcpsec import __version__
from mcpsec.ui import (
    console,
    print_banner,
    print_target_info,
    print_tool_info,
    print_section,
    get_progress,
)
from mcpsec.models import TransportType, Severity
from mcpsec.sql_scanner import SQLScanner

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


def _parse_headers(header_list: list[str]) -> dict[str, str]:
    """Parse list of 'Key: Value' strings into a dictionary."""
    headers = {}
    for h in header_list:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()
        else:
            # Invalid format, warn user
            console.print(
                f"[yellow]Warning: Invalid header format '{h}', expected 'Key: Value'[/yellow]"
            )
    return headers


def _version_callback(value: bool):
    if value:
        console.print(f"mcpsec v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit.", callback=_version_callback, is_eager=True),
):
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
        "--http",
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
        help="Output file path for report",
    ),
    format: str = typer.Option(
        "json",
        "--format", "-f",
        help="Output format: json, sarif",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Minimal output (no banner, no tool listing)",
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Use AI to generate custom payloads per tool",
    ),
    header: list[str] = typer.Option(
        [],
        "--header",
        "-H",
        help="HTTP header in 'Key: Value' format. Can be repeated. Example: -H 'Authorization: Bearer token123'",
    ),
    exploit: bool = typer.Option(
        False,
        "--exploit",
        help="Automatically launch interactive exploit session after scanning",
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
        output_format=format.lower(),
        quiet=quiet,
        ai=ai,
        headers=_parse_headers(header),
        exploit=exploit,
    ))


async def _scan_async(
    stdio_cmd: str | None,
    http_url: str | None,
    scanner_names: list[str] | None,
    output_path: str | None,
    output_format: str = "json",
    quiet: bool = False,
    ai: bool = False,
    headers: dict[str, str] | None = None,
    exploit: bool = False,
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
        headers=headers,
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
                    profile = await client.connect_http(http_url, headers=headers)
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
                try:
                    print_tool_info(tool.name, tool.description, tool.parameters)
                except Exception as e:
                    console.print(f"  [warning]⚠ Failed to print tool info for {getattr(tool, 'name', 'unknown')}: {e}[/warning]")

        if not profile.tools and not profile.resources:
            console.print("  [muted]No tools or resources found. Nothing to scan.[/muted]")
            raise typer.Exit(0)

        # ── AI Payload Generation ────────────────────────────────────────────
        findings = []
        if ai:
            from mcpsec.ai.ai_payload_generator import AIPayloadGenerator
            from mcpsec.ai.ai_validator import AIValidator
            
            generator = AIPayloadGenerator()
            validator = AIValidator()
            
            if generator.available:
                console.print("\n  [cyan]🧠 AI generating custom payloads per tool...[/cyan]")
                for tool in profile.tools:
                    try:
                        console.print(f"  [dim]  🧠 AI thinking about {tool.name}...[/dim]")
                        tool_info = {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.raw_schema or {},
                        }
                        try:
                            ai_payloads = await generator.generate_payloads(tool_info)
                        except Exception as e:
                            console.print(f"  [danger]    ✗ AI failed to generate payloads for {tool.name}: {e}[/danger]")
                            ai_payloads = []
                        
                        if ai_payloads:
                            console.print(f"    Executing {len(ai_payloads)} payloads against {tool.name}...")
                            
                            # Execute each AI-generated payload
                            for payload_info in ai_payloads:
                                param = payload_info.get("parameter", "")
                                payload = payload_info.get("payload", "")
                                category = payload_info.get("category", "unknown")
                                success_indicator = payload_info.get("success_indicator", "")

                                console.print(f"    [dim]→ Testing {param}={payload[:40]}...[/dim]")
                                
                                if not param or not payload:
                                    console.print(f"    [dim]→ Skipping malformed payload: param={param}, payload={payload}[/dim]")
                                    continue
                                
                                try:
                                    result = await client.call_tool(tool.name, {param: payload})
                                    response_text = ""
                                    if result and result.content:
                                        for block in result.content:
                                            if hasattr(block, 'text'):
                                                response_text += block.text
                                    
                                    # Debug: Print first 100 chars of response
                                    if response_text:
                                        # console.print(f"  [dim]    Response: {response_text[:100].replace('\n', ' ')}[/dim]")
                                        pass # Reduce noise if user doesn't want it, but maybe keep for now? User asked for specific logs.
                                    
                                    # Check if success indicator is in response (Fuzzy matching)
                                    is_vulnerable = False
                                    if success_indicator and success_indicator.lower() in response_text.lower():
                                        is_vulnerable = True
                                    
                                    # Heuristic Fallback: Flag "interesting" patterns in responses for dangerous categories
                                    if not is_vulnerable and category in ["command-injection", "path-traversal", "sqli", "ssrf"]:
                                        leak_patterns = [
                                            "root:", "uid=", "gid=", "[boot loader]", "etc/passwd", 
                                            "SQLite format 3", "PostgreSQL", "mysql", "Error:",
                                            "127.0.0.1", "localhost", "200 OK", "index of /"
                                        ]
                                        if any(p.lower() in response_text.lower() for p in leak_patterns):
                                            is_vulnerable = True
                                            console.print(f"  [yellow]    ⚠ Potential {category} leak detected (heuristic)[/yellow]")

                                    if is_vulnerable:
                                        from mcpsec.models import Finding, Severity
                                        findings.append(Finding(
                                            severity=Severity.CRITICAL,
                                            scanner=f"ai-{category}",
                                            title=f"AI Exploit: {payload_info.get('description', category)}",
                                            description=f"AI-generated payload confirmed exploitable.\nPayload: {payload}\nResponse: {response_text[:500]}",
                                            tool=tool.name,
                                            parameter=param,
                                        ))
                                        console.print(f"    [green]✓ CONFIRMED: {category} on {tool.name}[/green]")
                                except TimeoutError:
                                    console.print(f"    [yellow]→ Timeout ({tool.name}): tool hung, skipping[/yellow]")
                                    continue
                                except Exception as e:
                                    console.print(f"    [dim]→ Error: {e}[/dim]")
                                    pass
                    except Exception as e:
                        console.print(f"  [danger]    ⚠ Skipped tool {getattr(tool, 'name', 'unknown')} due to error: {e}[/danger]")
                        continue
                
                if findings:
                    # Consolidation: remove duplicates by title+tool+param
                    unique = {}
                    for f in findings:
                        key = (f.title, f.tool_name, f.taint_sink or f.evidence[:50] if f.evidence else "")
                        if key not in unique:
                            unique[key] = f
                        else:
                            # Merge descriptions if they differ
                            if f.description not in unique[key].description:
                                unique[key].description += f"\nAdditional Detail: {f.description}"
                    
                    findings = list(unique.values())
                    
                    console.print(f"  [cyan]🧠 AI validating {len(findings)} findings...[/cyan]")
                    findings = await validator.validate_findings(findings)
            else:
                console.print(
                    "\n  [yellow]⚠ AI analysis requires an API key.[/yellow]"
                    "\n  [dim]Set DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY,"
                    " or run Ollama locally.[/dim]"
                )

        # ── Scan ─────────────────────────────────────────────────────────────
        scan_result = await run_scan(
            profile=profile,
            client=client,
            scanner_names=scanner_names,
            target=target,
            transport=transport,
        )
        
        # Merge AI findings into result
        if findings:
            scan_result.findings.extend(findings)

        if not output_path:
            output_path = "findings.sarif" if output_format == "sarif" else "findings.json"

        if output_format == "sarif":
            from mcpsec.reporters.sarif_report import save_sarif_report
            if save_sarif_report(scan_result, output_path):
                console.print(f"  [success]✔ SARIF report saved to {output_path}[/success]")
            else:
                console.print(f"  [danger]✗ Failed to save SARIF report to {output_path}[/danger]")
        else:
            from mcpsec.reporters.json_report import generate_json_report
            if generate_json_report(scan_result, output_path):
                console.print(f"  [success]✔ Report saved to {output_path}[/success]")
            else:
                console.print(f"  [danger]✗ Failed to save report to {output_path}[/danger]")
            
        if exploit:
            from mcpsec.exploit.session import ExploitSession
            console.print("\n[bold green]Launching Interactive Exploit Session...[/bold green]")
            session = ExploitSession(
                target=target,
                transport=transport,
                findings=scan_result.findings,
                use_ai=ai,
                headers=headers,
                client=client,
                profile=profile
            )
            await session.start()            

    # Exit with non-zero if critical/high findings
    if not exploit and (scan_result.critical_count > 0 or scan_result.high_count > 0):
        raise typer.Exit(1)

# ─── EXPLOIT COMMAND ─────────────────────────────────────────────────────────

@app.command()
def exploit(
    stdio: Optional[str] = typer.Option(None, "--stdio", "-s", help="MCP server stdio command"),
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
    from_scan: Optional[str] = typer.Option(None, "--from-scan", help="Load findings from JSON report"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI payload recommendations"),
    header: list[str] = typer.Option([], "--header", "-H", help="HTTP headers"),
):
    """
    🎯 Interactive MCP Exploitation Session.
    
    Launch a REPL to manually or semi-automatically exploit a running MCP server.
    """
    if not stdio and not http:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)
        
    findings = []
    if from_scan:
        try:
            import json as _json
            from mcpsec.models import Finding, ScanResult
            with open(from_scan, "r") as f:
                data = _json.load(f)
            
            # Handle both formats: raw array or ScanResult wrapper
            if isinstance(data, list):
                findings = [Finding.model_validate(item) for item in data]
            elif isinstance(data, dict) and "findings" in data:
                try:
                    sr = ScanResult.model_validate(data)
                    findings = sr.findings
                except Exception:
                    findings = [Finding.model_validate(item) for item in data["findings"]]
            else:
                sr = ScanResult.model_validate(data)
                findings = sr.findings
        except Exception as e:
            console.print(f"[danger]Failed to load scan results: {e}[/danger]")
            raise typer.Exit(1)

    _run_async(_exploit_async(stdio, http, findings, ai, _parse_headers(header)))

async def _exploit_async(stdio_cmd: str | None, http_url: str | None, findings: list, ai: bool, headers: dict):
    from mcpsec.exploit.session import ExploitSession
    from mcpsec.models import TransportType
    
    target = stdio_cmd or http_url or ""
    transport = TransportType.STDIO if stdio_cmd else TransportType.HTTP
    
    session = ExploitSession(
        target=target,
        transport=transport,
        findings=findings,
        use_ai=ai,
        headers=headers
    )
    await session.start()



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


# ─── SQL COMMAND ─────────────────────────────────────────────────────────────

@app.command()
def sql(
    stdio: Optional[str] = typer.Option(None, "--stdio", "-s", help="MCP server stdio command"),
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
    tool: Optional[str] = typer.Option(None, "--tool", help="Specific tool to test (optional)"),
    level: int = typer.Option(1, "--level", help="Scan depth: 1=quick, 2=thorough, 3=aggressive"),
    fingerprint: bool = typer.Option(False, "--fingerprint", "-f", help="Fingerprint DB type"),
    exploit: bool = typer.Option(False, "--exploit", "-e", help="Attempt data extraction"),
    timeout: float = typer.Option(10.0, "--timeout", help="Request timeout"),
):
    """
    💉 SQL injection scanner for MCP database servers.
    """
    if not stdio and not http:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)

    _run_async(_sql_async(
        stdio_cmd=stdio, 
        http_url=http, 
        tool_name=tool, 
        level=level, 
        fingerprint=fingerprint, 
        exploit=exploit, 
        timeout=timeout
    ))


async def _sql_async(
    stdio_cmd: str | None, 
    http_url: str | None, 
    tool_name: str | None,
    level: int,
    fingerprint: bool,
    exploit: bool,
    timeout: float
):
    from mcpsec.client.mcp_client import MCPSecClient
    from rich.panel import Panel
    from rich.columns import Columns

    print_banner(small=True)

    target = stdio_cmd or http_url or ""
    transport = "stdio" if stdio_cmd else "http"
    
    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n"
        f"[bold white]Transport:[/bold white] [muted]{transport}[/muted]",
        title="[bold blue]SQL Injection Scan[/bold blue]",
        border_style="blue",
        box=box.ROUNDED
    ))

    async with MCPSecClient() as client:
        try:
            if stdio_cmd:
                profile = await client.connect_stdio(stdio_cmd)
            else:
                profile = await client.connect_http(http_url)
        except Exception as e:
            console.print(f"\n  [danger]✗ Connection failed: {e}[/danger]")
            raise typer.Exit(1)

        scanner = SQLScanner(client)
        
        # Filter profile.tools if tool_name is provided
        if tool_name:
            original_tools = profile.tools
            profile.tools = [t for t in profile.tools if t.name == tool_name]
            if not profile.tools:
                console.print(f"[danger]Error: Tool '{tool_name}' not found on server.[/danger]")
                return

        console.print(f"  [cyan]🔍 Scanning {len(profile.tools)} tools...[/cyan]")
        
        findings = await scanner.scan_server(profile, level=level, fingerprint=fingerprint)
        
        # Track which tools were scanned and which are vulnerable
        scanned_tools = [t.name for t in profile.tools]
        vulnerable_tool_names = set(f.tool for f in findings)
        
        for tool_name in scanned_tools:
            tool_findings = [f for f in findings if f.tool == tool_name]
            if tool_findings:
                for f in tool_findings:
                    console.print(f"\n[bold red]🔴 CRITICAL: SQL Injection in tool '{f.tool}'[/bold red]")
                    console.print(f"   [white]Parameter:[/white]   [yellow]{f.parameter}[/yellow]")
                    console.print(f"   [white]Technique:[/white]   [yellow]{f.technique}[/yellow]")
                    console.print(f"   [white]Payload:[/white]     [dim white]{f.payload}[/dim white]")
                    if f.evidence:
                         console.print(f"   [white]Evidence:[/white]    [dim cyan]\"{f.evidence}\"[/dim cyan]")
                    
                    if f.db_type:
                        console.print(f"\n   [white]Database:[/white]    [bold green]{f.db_type.upper()} (fingerprinted)[/bold green]")
                        
                        # RCE Hint based on DB type (v1.2 preview)
                        if f.db_type == "mysql":
                            console.print("   [bold red]💀 RCE Possible: INTO OUTFILE available[/bold red]")
                        elif f.db_type == "postgres":
                            console.print("   [bold red]💀 RCE Possible: COPY FROM PROGRAM available[/bold red]")
            else:
                console.print(f"[bold green]🟢 SECURE:[/bold green] Tool '{tool_name}' - No injection found")

        console.print("\n" + "─" * 60)
        critical_count = len(findings)
        summary_color = "red" if critical_count > 0 else "green"
        console.print(f"[{summary_color}]Summary: {critical_count} CRITICAL, 0 HIGH, 0 MEDIUM | {len(vulnerable_tool_names)}/{len(scanned_tools)} tools vulnerable[/{summary_color}]")


@app.command()
def chains(
    stdio: Optional[str] = typer.Option(None, "--stdio", "-s", help="MCP server stdio command"),
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table, json"),
    min_severity: str = typer.Option("MEDIUM", "--min-severity", help="Minimum severity to report"),
):
    """
    🔗 Analyze MCP server for dangerous tool combinations (attack chains).
    """
    if not stdio and not http:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)

    _run_async(_chains_async(stdio_cmd=stdio, http_url=http, output_format=output, min_severity=min_severity))


async def _chains_async(stdio_cmd: str | None, http_url: str | None, output_format: str, min_severity: str):
    from mcpsec.client.mcp_client import MCPSecClient
    from mcpsec.scanners.toolchain_analyzer import ToolChainAnalyzer
    from rich.panel import Panel

    print_banner(small=True)

    target = stdio_cmd or http_url or ""
    transport = "stdio" if stdio_cmd else "http"
    
    console.print(Panel(
        f"[bold white]Target:[/bold white] [cyan]{target}[/cyan]\n"
        f"[bold white]Transport:[/bold white] [muted]{transport}[/muted]",
        title="[bold blue]Tool Chain Analysis[/bold blue]",
        border_style="blue",
        box=box.ROUNDED
    ))

    async with MCPSecClient() as client:
        try:
            if stdio_cmd:
                profile = await client.connect_stdio(stdio_cmd)
            else:
                profile = await client.connect_http(http_url)
        except Exception as e:
            console.print(f"\n  [danger]✗ Connection failed: {e}[/danger]")
            raise typer.Exit(1)

        analyzer = ToolChainAnalyzer()
        report = analyzer.analyze_server(profile)

        console.print(f"  [cyan]🔍 Analyzed {report.total_tools} tools...[/cyan]\n")

        if report.capabilities_found:
            console.print("📊 [bold]Capabilities Detected:[/bold]")
            for cap in sorted(report.capabilities_found):
                console.print(f" • [dim cyan]{cap}[/dim cyan]")
            console.print()

        severity_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        min_rank = severity_rank.get(min_severity.upper(), 1)

        findings_shown = 0
        for finding in report.chain_findings:
            if severity_rank.get(finding.severity.upper(), 0) < min_rank:
                continue
            
            findings_shown += 1
            sev_color = "red" if finding.severity == "CRITICAL" else "orange3" if finding.severity == "HIGH" else "yellow"
            console.print(f"[bold {sev_color}]{finding.severity}: {finding.name.replace('_', ' ').title()} ({finding.chain_id})[/bold {sev_color}]")
            
            tool_paths = []
            for cap, tools in finding.matching_tools.items():
                tool_paths.append(f"[cyan]{tools[0]}[/cyan]")
            
            console.print(f"Tools:     {' → '.join(tool_paths)}")
            if finding.mitre_attack:
                console.print(f"MITRE:     [dim white]{', '.join(finding.mitre_attack)}[/dim white]")
            if finding.example_attack:
                console.print(f"Attack:    [dim]{finding.example_attack}[/dim]")
            console.print()

        console.print("─" * 60)
        risk_color = "red" if report.risk_score >= 9.0 else "orange3" if report.risk_score >= 7.0 else "yellow" if report.risk_score >= 4.0 else "green"
        risk_label = "CRITICAL" if report.risk_score >= 9.0 else "HIGH" if report.risk_score >= 7.0 else "MEDIUM" if report.risk_score >= 4.0 else "LOW"
        
        console.print(f"Risk Score: [{risk_color}]{report.risk_score:.1f}/10 ({risk_label})[/{risk_color}]")
        
        crit_count = sum(1 for f in report.chain_findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in report.chain_findings if f.severity == "HIGH")
        med_count = sum(1 for f in report.chain_findings if f.severity == "MEDIUM")
        
        console.print(f"Findings: {crit_count} CRITICAL, {high_count} HIGH, {med_count} MEDIUM")
        
        if report.risk_score >= 7.0:
            console.print("\n[bold yellow]Recommendation:[/bold yellow] This server has excessive capabilities. Apply")
            console.print("principle of least privilege.")
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


# ─── SETUP COMMAND ───────────────────────────────────────────────────────────

@app.command()
def setup():
    """
    🧠 Configure AI provider for mcpsec (API key, model).
    
    Saves config to ~/.mcpsec/config.json for all future scans.
    """
    from mcpsec.config import PROVIDERS, save_config, load_config
    
    print_banner(small=True)
    console.print()
    console.print("  [bold cyan]🧠 mcpsec AI Configuration[/bold cyan]")
    console.print()
    console.print("  Select AI provider:")
    console.print()
    
    provider_list = list(PROVIDERS.items())
    for i, (pid, info) in enumerate(provider_list, 1):
        console.print(f"  [bold][{i}][/bold] {info['name']:<12} ({info['description']})")
    console.print(f"  [bold][{len(provider_list) + 1}][/bold] Skip        (no AI features)")
    console.print()
    
    try:
        choice = typer.prompt("  > Enter choice", type=int)
    except (KeyboardInterrupt, typer.Abort):
        console.print("\n  [muted]Setup cancelled.[/muted]")
        raise typer.Exit(0)
    
    if choice < 1 or choice > len(provider_list) + 1:
        console.print("  [danger]Invalid choice.[/danger]")
        raise typer.Exit(1)
    
    if choice == len(provider_list) + 1:
        console.print("  [muted]Skipped. AI features disabled.[/muted]")
        raise typer.Exit(0)
    
    provider_id, provider_info = provider_list[choice - 1]
    
    api_key = ""
    if provider_info.get("env_var"):  # Ollama doesn't need a key
        console.print(f"\n  Get your key at: [link]{provider_info['key_url']}[/link]")
        try:
            api_key = typer.prompt("  > Enter API key", hide_input=True)
        except (KeyboardInterrupt, typer.Abort):
            console.print("\n  [muted]Setup cancelled.[/muted]")
            raise typer.Exit(0)
    
    save_config(provider_id, api_key)
    console.print(f"\n  [success]✔ Saved to ~/.mcpsec/config.json[/success]")
    console.print(f"  AI features enabled for all future scans ({provider_info['name']}, {provider_info['model']}).")
    console.print()


# ─── AUDIT COMMAND ───────────────────────────────────────────────────────────

@app.command()
def audit(
    npm: Optional[str] = typer.Option(None, "--npm", help="NPM package to audit"),
    github: Optional[str] = typer.Option(None, "--github", help="GitHub repository URL to audit"),
    path: Optional[str] = typer.Option(None, "--path", help="Local directory path to audit"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path for report"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, sarif"),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Use AI-powered analysis (requires API key: DEEPSEEK_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY)",
    ),
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

    _run_async(_audit_async(npm, github, path, ai, output, format.lower()))


async def _audit_async(npm: str | None, github: str | None, path: str | None, ai: bool = False, output_path: str | None = None, output_format: str = "json"):
    from mcpsec.static.audit_engine import run_audit
    from mcpsec.models import Finding, ScanResult
    
    print_banner(small=True)
    print_section("Static Audit", "🔬")
    
    findings, source_path = await run_audit(npm, github, path)
    
    if ai:
        from mcpsec.ai.ai_taint_analyzer import AITaintAnalyzer
        from mcpsec.ai.ai_validator import AIValidator
        
        analyzer = AITaintAnalyzer()
        validator = AIValidator()
        
        if analyzer.available and source_path:
            console.print("\n  [cyan]🧠 Running AI-powered taint analysis...[/cyan]")
            ai_findings = await analyzer.analyze_project(Path(source_path))
            
            if ai_findings:
                # Deduplicate: skip AI findings on same file+line as existing
                existing = {(f.file_path, f.line_number) for f in findings if f.line_number}
                new_ai = [f for f in ai_findings if (f.file_path, f.line_number) not in existing]
                findings.extend(new_ai)
                console.print(f"  [cyan]  AI found {len(new_ai)} additional findings[/cyan]")
            
            # Validate ALL findings (remove false positives)
            console.print("  [cyan]🧠 AI validating findings...[/cyan]")
            findings = await validator.validate_findings(findings)
            console.print(f"  [cyan]  {len(findings)} findings after AI validation[/cyan]")
        else:
            console.print(
                "\n  [yellow]⚠ AI analysis requires an API key.[/yellow]"
                "\n  [dim]Set DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY,"
                " or run Ollama locally.[/dim]"
            )

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

    # Save report if output path specified
    if output_path:
        target = npm or github or path or ""
        scan_result = ScanResult(
            target=target,
            findings=findings,
            scanners_run=["semgrep", "ai-taint"] if ai else ["semgrep"],
        )
        scan_result.mark_complete()

        if output_format == "sarif":
            from mcpsec.reporters.sarif_report import save_sarif_report
            if save_sarif_report(scan_result, output_path):
                console.print(f"  [success]✔ SARIF report saved to {output_path}[/success]")
            else:
                console.print(f"  [danger]✗ Failed to save SARIF report[/danger]")
        else:
            from mcpsec.reporters.json_report import generate_json_report
            if generate_json_report(scan_result, output_path):
                console.print(f"  [success]✔ Report saved to {output_path}[/success]")
            else:
                console.print(f"  [danger]✗ Failed to save report[/danger]")

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
    stdio: Optional[str] = typer.Option(None, "--stdio", "-s", help="MCP server command"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Per-test response timeout in seconds"),
    startup_timeout: float = typer.Option(15.0, "--startup-timeout", help="Server startup/initialization timeout in seconds"),
    framing: str = typer.Option("auto", "--framing", "-f", help="Message framing: 'auto', 'jsonl' (Python), or 'clrf' (Node)"),
    generators: str = typer.Option(None, "--generators", "-g", help="Comma-separated generator names"),
    output: str = typer.Option(None, "--output", "-o", help="Save results to file"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print raw responses for debugging"),
    intensity: str = typer.Option("medium", "--intensity", "-i", help="Fuzzing intensity: low, medium, high, insane"),
    ai: bool = typer.Option(False, "--ai", help="Generate custom AI-powered fuzz payloads per tool"),
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
    header: list[str] = typer.Option([], "--header", "-H", help="HTTP header in 'Key: Value' format"),
    chained: bool = typer.Option(False, "--chained", help="Use stateful attack chains (discovery & dependency analysis)"),
    format: str = typer.Option("json", "--format", help="Output format: json, sarif"),
):
    """
    🔥 Fuzz an MCP server with malformed protocol messages.
    
    Generates hundreds of adversarial JSON-RPC messages to find crashes,
    hangs, and parsing bugs at the protocol level.
    
    Intensity levels:
      low    — core protocol tests (~65 cases)
      medium — + session attacks & encoding tests (~150 cases)
      high   — + injection, method/param mutations, timing, headers, JSON, protocol state (~500 cases)
      insane — + resource exhaustion (~550+ cases)
    
    Use --ai to add AI-generated payloads custom to each tool's schema.
    """
    from mcpsec.fuzzer.fuzz_engine import FuzzEngine
    
    print_banner()
    target = stdio or http or ""
    transport = "stdio" if stdio else "http"
    parsed_headers = _parse_headers(header)
    print_target_info("MCP Server (Fuzz)", target[:80], transport, headers=parsed_headers)
    
    if not stdio and not http:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)
    
    gen_list = [g.strip() for g in generators.split(",")] if generators else None
    
    if chained:
        # Delegate to chained engine
        _run_async(_chained_fuzz_async(
            target=target,
            transport_type=transport,
            headers=parsed_headers,
            intensity=intensity,
            use_ai=ai,
            verbose=debug, # Map debug to verbose
        ))
        return

    engine = FuzzEngine(target, timeout, startup_timeout, framing, debug, intensity=intensity, ai=ai, headers=parsed_headers)
    summary = engine.run(gen_list)
    
    # Print results
    print_section("Fuzz Results", "🔥")
    console.print(f"  [accent]Total tests:[/accent] {summary['total_tests']}")
    console.print(f"  [danger]Crashes:[/danger] {summary['crashes']}" if summary['crashes'] else f"  [success]Crashes:[/success] 0")
    console.print(f"  [warning]Timeouts:[/warning] {summary['timeouts']}" if summary['timeouts'] else f"  [success]Timeouts:[/success] 0")
    console.print(f"  [accent]Interesting:[/accent] {summary['interesting']}" if summary['interesting'] else f"  [muted]Interesting:[/muted] 0")
    
    if summary.get('crashes', 0) > 0 and summary.get('error_log'):
        console.print(f"  [muted]Crash Logs:[/muted] {summary['error_log']}")
    
    if summary['interesting_cases']:
        console.print()
        for ic in summary['interesting_cases']:
            if ic['generator'] == 'ai_fuzz':
                icon = "🧠" if not ic['crashed'] and not ic['timeout'] else ("🔴" if ic['crashed'] else "🟡")
                status = "AI-CRASH" if ic['crashed'] else "AI-TIMEOUT" if ic['timeout'] else "AI-ANOMALY"
            else:
                icon = "🔴" if ic['crashed'] else "🟡" if ic['timeout'] else "🟠"
                status = "CRASH" if ic['crashed'] else "TIMEOUT" if ic['timeout'] else "ANOMALY"
            console.print(f"  {icon} [{status}] {ic['case_name']} ({ic['generator']})")
            console.print(f"       {ic['description']}")
            if ic['error']:
                console.print(f"       [muted]{ic['error'][:100]}[/muted]")
            console.print()
    
    if output:
        if format.lower() == "sarif":
            from mcpsec.reporters.sarif_report import save_sarif_from_fuzz
            if save_sarif_from_fuzz(summary, target, output):
                console.print(f"  [success]✔ SARIF report saved to {output}[/success]")
            else:
                console.print(f"  [danger]✗ Failed to save SARIF report[/danger]")
        else:
            import json
            Path(output).write_text(json.dumps(summary, indent=2))
            console.print(f"  [success]✔ Results saved to {output}[/success]")


# ─── CHAINED COMMAND ─────────────────────────────────────────────────────────

@app.command()
def chained(
    stdio: Optional[str] = typer.Option(None, "--stdio", "-s", help="MCP server command"),
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
    ai: bool = typer.Option(True, "--ai/--no-ai", help="Use AI for dependency analysis (recommended)"),
    intensity: str = typer.Option("medium", "--intensity", "-i", help="Fuzzing intensity"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save results to JSON"),
    header: list[str] = typer.Option([], "--header", "-H", help="HTTP header"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    🔗 Execute stateful attack chains against an MCP server.
    
    This engine analyzes tool dependencies, builds multi-step sequences
    (e.g., navigate -> snapshot -> click), and injects payloads while
    maintaining valid application state.
    """
    target = stdio or http
    transport = "stdio" if stdio else "http"
    parsed_headers = _parse_headers(header)
    
    if not target:
        console.print("[danger]Error: Specify either --stdio or --http[/danger]")
        raise typer.Exit(1)
        
    _run_async(_chained_fuzz_async(
        target=target,
        transport_type=transport,
        headers=parsed_headers,
        intensity=intensity,
        use_ai=ai,
        verbose=verbose,
        output_path=output,
    ))


async def _chained_fuzz_async(
    target: str,
    transport_type: str,
    headers: dict[str, str],
    intensity: str,
    use_ai: bool,
    verbose: bool = False,
    output_path: str | None = None,
):
    from mcpsec.fuzzer.chain.chain_engine import ChainEngine, ChainFuzzingConfig
    
    config = ChainFuzzingConfig(
        use_ai=use_ai,
        verbose=verbose,
    )
    
    # Map intensity to payload counts
    intensity_map = {
        "low": 5,
        "medium": 20,
        "high": 50,
        "insane": 100,
    }
    config.max_payloads_per_injection_point = intensity_map.get(intensity.lower(), 20)
    
    engine = ChainEngine(config)
    
    await engine.run(
        server_command=target if transport_type == "stdio" else "",
        transport_type=transport_type,
        http_url=target if transport_type == "http" else None,
        headers=headers,
    )
    
    if output_path:
        engine.reporter.save_json(output_path)
        console.print(f"\n  [success]✔ Chained report saved to {output_path}[/success]")


# ─── ROGUE-SERVER COMMAND ───────────────────────────────────────────────────

@app.command("rogue-server")
def rogue_server(
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on (HTTP mode)"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to (HTTP mode)"),
    stdio: bool = typer.Option(False, "--stdio", help="Use stdio transport instead of HTTP"),
    attack: str = typer.Option(
        "all",
        "--attack",
        "-a",
        help="Attack type(s), comma-separated. Use 'all' for all attacks."
    ),
    auth: Optional[str] = typer.Option(None, "--auth", help="Require Bearer token for HTTP mode"),
    list_attacks: bool = typer.Option(False, "--list", "-l", help="List available attack types"),
):
    """
    🎭 Start a ROGUE MCP server to test CLIENT security.
    
    This flips the attack model: instead of testing MCP servers,
    this tests MCP CLIENTS like Claude Desktop, Cursor, and VS Code.
    """
    from mcpsec.rogue.payloads import ATTACK_TYPES
    from mcpsec.rogue.server import RogueMCPServer

    # Handle --list flag
    if list_attacks:
        print_section("Available Attacks", "🎭")
        for name, func in ATTACK_TYPES.items():
            doc = func.__doc__ or "No description"
            console.print(f"  [accent]{name:<16}[/accent] [muted]{doc}[/muted]")
        console.print()
        return

    # Parse attack types
    if attack == "all":
        attacks = list(ATTACK_TYPES.keys())
    else:
        attacks = [a.strip() for a in attack.split(",")]
        # Validate
        invalid = [a for a in attacks if a not in ATTACK_TYPES]
        if invalid:
            console.print(f"[danger]Error: Invalid attack types: {', '.join(invalid)}[/danger]")
            raise typer.Exit(1)

    server = RogueMCPServer(attacks=attacks, stdio=stdio, auth_token=auth)

    if stdio:
        _run_async(server.run_stdio())
    else:
        _run_async(server.run_http(host, port))

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
