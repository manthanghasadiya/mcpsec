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
        help="Output file path for JSON report",
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
        ai=ai,
        headers=_parse_headers(header),
    ))


async def _scan_async(
    stdio_cmd: str | None,
    http_url: str | None,
    scanner_names: list[str] | None,
    output_path: str | None,
    quiet: bool,
    ai: bool = False,
    headers: dict[str, str] | None = None,
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

        if output_path:
            from mcpsec.reporters.json_report import generate_json_report
            if generate_json_report(scan_result, output_path):
                console.print(f"  [success]✔ Report saved to {output_path}[/success]")
            else:
                console.print(f"  [danger]✗ Failed to save report to {output_path}[/danger]")

    # Exit with non-zero if critical/high findings
    if scan_result.critical_count > 0 or scan_result.high_count > 0:
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
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
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

    _run_async(_audit_async(npm, github, path, ai))


async def _audit_async(npm: str | None, github: str | None, path: str | None, ai: bool = False):
    from mcpsec.static.audit_engine import run_audit
    from mcpsec.models import Finding
    
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
    output: str = typer.Option(None, "--output", "-o", help="Save results to JSON"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Print raw responses for debugging"),
    intensity: str = typer.Option("medium", "--intensity", "-i", help="Fuzzing intensity: low, medium, high, insane"),
    ai: bool = typer.Option(False, "--ai", help="Generate custom AI-powered fuzz payloads per tool"),
    http: Optional[str] = typer.Option(None, "--http", help="MCP server HTTP URL"),
    header: list[str] = typer.Option([], "--header", "-H", help="HTTP header in 'Key: Value' format"),
    chained: bool = typer.Option(False, "--chained", help="Use stateful attack chains (discovery & dependency analysis)"),
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
