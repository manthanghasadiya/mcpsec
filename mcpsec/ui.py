"""
mcpsec terminal UI theme — hacker aesthetic.
"""
from mcpsec import __version__
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

# ── Custom Theme ─────────────────────────────────────────────────────────────

MCPSEC_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "red bold",
    "success": "green bold",
    "muted": "dim white",
    "accent": "bold cyan",
    "vuln.critical": "bold red",
    "vuln.high": "red",
    "vuln.medium": "yellow",
    "vuln.low": "blue",
    "vuln.info": "dim cyan",
    "header": "bold white on rgb(20,30,50)",
    "tool_name": "bold magenta",
    "param": "bold cyan",
    "value": "green",
})

console = Console(theme=MCPSEC_THEME)

# ── ASCII Banner ─────────────────────────────────────────────────────────────

BANNER = f"""[cyan]
                                         
  ███╗   ███╗ ██████╗██████╗ ███████╗███████╗ ██████╗
  ████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
  ██╔████╔██║██║     ██████╔╝███████╗█████╗  ██║     
  ██║╚██╔╝██║██║     ██╔═══╝ ╚════██║██╔══╝  ██║     
  ██║ ╚═╝ ██║╚██████╗██║     ███████║███████╗╚██████╗
  ╚═╝     ╚═╝ ╚═════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
                                                       
[/cyan][dim white]  ──── MCP Security Scanner ── v{__version__} ────[/dim white]
[dim cyan]  Because your AI agents deserve a pentest too.[/dim cyan]
"""

SMALL_BANNER = f"[bold cyan]* mcpsec[/bold cyan] [dim]v{__version__}[/dim]"


def print_banner(small: bool = False):
    """Print the mcpsec banner."""
    try:
        if small:
            console.print(SMALL_BANNER)
        else:
            console.print(BANNER)
    except UnicodeEncodeError:
        # Fallback for legacy Windows consoles
        try:
            console.print(f"--- mcpsec v{__version__} ---")
        except (BrokenPipeError, OSError):
            pass
    except (BrokenPipeError, OSError):
        # Pipe closed early (e.g. output piped through head/Select-Object)
        pass


def print_target_info(target_type: str, target: str, transport: str = "stdio"):
    """Print target connection info box."""
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    table.add_column("key", style="muted", width=12)
    table.add_column("value", style="value")
    table.add_row("TARGET", target)
    table.add_row("TRANSPORT", transport)
    table.add_row("TYPE", target_type)
    
    title = "◉ Target"
    try:
        console.print(Panel(
            table,
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))
    except UnicodeEncodeError:
         try:
             console.print(Panel(
                table,
                title="[bold cyan]Target[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            ))
         except (BrokenPipeError, OSError):
             pass
    except (BrokenPipeError, OSError):
        pass


def print_tool_info(name: str, description: str, params: dict):
    """Print a discovered MCP tool."""
    param_str = ", ".join(
        f"[param]{k}[/param]:[muted]{v}[/muted]"
        for k, v in params.items()
    ) if params else "[muted]none[/muted]"
    
    icon = "o" # Safe fallback
    console.print(f"  [tool_name]{icon} {name}[/tool_name]  ({param_str})")
    if description:
        short = description[:120] + "..." if len(description) > 120 else description
        console.print(f"    [muted]{short}[/muted]")


def print_finding(severity: str, scanner: str, tool_name: str, title: str, detail: str = ""):
    """Print a vulnerability finding."""
    sev_style = f"vuln.{severity.lower()}"
    sev_label = severity.upper().ljust(8)
    # Use ASCII icons for better compatibility
    icon = {"critical": "[!]", "high": "[!]", "medium": "[!]", "low": "[?]", "info": "[i]"}.get(
        severity.lower(), "[i]"
    )
    console.print(
        f"  {icon} [{sev_style}]{sev_label}[/{sev_style}] "
        f"[bold white]{title}[/bold white]"
    )
    console.print(f"           [muted]scanner={scanner}  tool={tool_name}[/muted]")
    if detail:
        for line in detail.split("\n"):
            console.print(f"           [muted]{line}[/muted]")
    console.print()


def print_section(title: str, icon: str = "-"):
    """Print a section divider."""
    console.print()
    try:
        console.rule(f"[bold cyan] {icon} {title} [/bold cyan]", style="dim cyan")
    except UnicodeEncodeError:
        try:
            console.print(f"--- {title} ---")
        except (BrokenPipeError, OSError):
            pass
    except (BrokenPipeError, OSError):
        pass
    console.print()


def print_summary(total: int, critical: int, high: int, medium: int, low: int, info: int):
    """Print scan summary."""
    console.print()
    table = Table(
        box=box.DOUBLE_EDGE,
        title="[bold white]Scan Summary[/bold white]",
        border_style="cyan",
        padding=(0, 2),
    )
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    if critical > 0:
        table.add_row("[vuln.critical]CRITICAL[/vuln.critical]", f"[vuln.critical]{critical}[/vuln.critical]")
    if high > 0:
        table.add_row("[vuln.high]HIGH[/vuln.high]", f"[vuln.high]{high}[/vuln.high]")
    if medium > 0:
        table.add_row("[vuln.medium]MEDIUM[/vuln.medium]", f"[vuln.medium]{medium}[/vuln.medium]")
    if low > 0:
        table.add_row("[vuln.low]LOW[/vuln.low]", f"[vuln.low]{low}[/vuln.low]")
    if info > 0:
        table.add_row("[vuln.info]INFO[/vuln.info]", f"[vuln.info]{info}[/vuln.info]")

    table.add_section()
    table.add_row("[bold white]TOTAL[/bold white]", f"[bold white]{total}[/bold white]")

    try:
        console.print(table)
    except UnicodeEncodeError:
        try:
            console.print(f"Summary: {total} issues ({critical} critical, {high} high)")
        except (BrokenPipeError, OSError):
            pass
    except (BrokenPipeError, OSError):
        pass

    if critical > 0 or high > 0:
        console.print("\n  [danger]!  Critical/High findings require immediate attention.[/danger]")
    elif total == 0:
        console.print("\n  [success]*  No vulnerabilities found. Nice.[/success]")
    else:
        console.print("\n  [warning]! Review findings and remediate as needed.[/warning]")
    console.print()


def get_progress() -> Progress:
    """Get a styled progress bar."""
    return Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="dim cyan", complete_style="cyan"),
        TextColumn("[muted]{task.percentage:>3.0f}%[/muted]"),
        TimeElapsedColumn(),
        console=console,
    )
