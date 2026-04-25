"""
mcpsec terminal UI theme — hacker aesthetic.
"""

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.theme import Theme

from mcpsec import __version__

# ── Custom Theme ─────────────────────────────────────────────────────────────

MCPSEC_THEME = Theme(
    {
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
    }
)

class SafeConsole(Console):
    """A wrapper for rich.console.Console that handles encoding errors on legacy Windows terminals."""
    def print(self, *args, **kwargs):
        try:
            super().print(*args, **kwargs)
        except (UnicodeEncodeError, Exception):
            try:
                import re
                processed_args = []
                for arg in args:
                    if isinstance(arg, str):
                        arg = re.sub(r"\[/?(?:[a-z\._-]+(?:\s*=\s*[^\]]+)?|#[\da-f]{3,6}|rgb\(\d{1,3},\d{1,3},\d{1,3}\))?\]", "", arg)
                    processed_args.append(arg)
                print(*processed_args)
            except Exception:
                pass

    def rule(self, title="", *args, **kwargs):
        try:
            super().rule(title, *args, **kwargs)
        except (UnicodeEncodeError, Exception):
            try:
                print(f"\n--- {title} ---\n")
            except Exception:
                pass

console = SafeConsole(theme=MCPSEC_THEME)

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
            super(SafeConsole, console).print(SMALL_BANNER)
        else:
            super(SafeConsole, console).print(BANNER)
    except (UnicodeEncodeError, Exception):
        # Fallback for legacy Windows consoles or other issues
        try:
            banner_text = f"--- mcpsec v{__version__} ---"
            print(banner_text)
        except Exception:
            pass
    except (BrokenPipeError, OSError):
        pass


def print_target_info(
    target_type: str,
    target: str,
    transport: str,
    headers: dict[str, str] | None = None,
):
    """Print target connection info box."""
    table = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
    table.add_column("key", style="muted", width=12)
    table.add_column("value", style="value")

    table.add_row("TARGET", target)
    table.add_row("TRANSPORT", transport)
    table.add_row("TYPE", target_type)

    if headers:
        for k, v in headers.items():
            table.add_row("HEADER", f"{k}: {_mask_header_value(k, v)}")

    title = "◉ Target"
    try:
        super(SafeConsole, console).print(
            Panel(
                table,
                title=f"[bold cyan]{title}[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )
    except (UnicodeEncodeError, Exception):
        try:
            # Fallback for Windows consoles that don't support unicode boxes
            print("\n--- Target ---")
            print(f"TARGET: {target}")
            print(f"TRANSPORT: {transport}")
            print(f"TYPE: {target_type}")
            if headers:
                for k, v in headers.items():
                    print(f"HEADER: {k}: {_mask_header_value(k, v)}")
            print("-" * 14 + "\n")
        except Exception:
            pass
    except (BrokenPipeError, OSError):
        pass


def _mask_header_value(key: str, value: str) -> str:
    """Mask sensitive header values for display."""
    sensitive_keys = ["authorization", "x-api-key", "api-key", "token", "secret"]
    if any(s in key.lower() for s in sensitive_keys):
        return value[:10] + "..." + value[-4:] if len(value) > 14 else "***"
    return value


def print_tool_info(name: str, description: str, params: dict):
    """Print a discovered MCP tool."""
    param_str = (
        ", ".join(f"[param]{k}[/param]:[muted]{v}[/muted]" for k, v in params.items())
        if params
        else "[muted]none[/muted]"
    )

    icon = "o"  # Safe fallback
    try:
        console.print(f"  [tool_name]{icon} {name}[/tool_name]  ({param_str})")
        if description:
            short = description[:120] + "..." if len(description) > 120 else description
            console.print(f"    [muted]{short}[/muted]")
    except Exception:
        # Fallback for tool info
        try:
            print(f"  o {name} ({', '.join(params.keys()) if params else 'none'})")
        except Exception:
            pass


def print_finding(severity: str, scanner: str, tool_name: str, title: str, detail: str = ""):
    """Print a vulnerability finding."""
    sev_style = f"vuln.{severity.lower()}"
    sev_label = severity.upper().ljust(8)
    icon = {"critical": "[!]", "high": "[!]", "medium": "[!]", "low": "[?]", "info": "[i]"}.get(
        severity.lower(), "[i]"
    )
    try:
        console.print(
            f"  {icon} [{sev_style}]{sev_label}[/{sev_style}] [bold white]{title}[/bold white]"
        )
        console.print(f"           [muted]scanner={scanner}  tool={tool_name}[/muted]")
        if detail:
            for line in detail.split("\n"):
                console.print(f"           [muted]{escape(line)}[/muted]")
        console.print()
    except Exception:
        try:
            print(f"  {icon} {sev_label} {title}")
            print(f"           scanner={scanner}  tool={tool_name}")
        except Exception:
            pass


def print_section(title: str, icon: str = "-"):
    """Print a section divider."""
    try:
        super(SafeConsole, console).print()
        super(SafeConsole, console).rule(f"[bold cyan] {icon} {title} [/bold cyan]", style="dim cyan")
        super(SafeConsole, console).print()
    except (UnicodeEncodeError, Exception):
        try:
            print(f"\n--- {title} ---\n")
        except Exception:
            pass
    except (BrokenPipeError, OSError):
        pass


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
        table.add_row(
            "[vuln.critical]CRITICAL[/vuln.critical]", f"[vuln.critical]{critical}[/vuln.critical]"
        )
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
