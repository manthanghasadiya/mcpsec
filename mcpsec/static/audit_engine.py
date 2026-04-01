"""
Audit engine v3 -- orchestrates static analysis.

Phases:
1. Fetch source
2. Detect framework
3. Scan for sinks (pattern database)
4. Run Semgrep rules (additional coverage)
5. Python AST analysis
6. LLM reachability analysis (if --ai)
7. Deduplicate and rank
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from mcpsec.models import Finding, Severity
from mcpsec.static.source_fetcher import cleanup_temp, fetch_source
from mcpsec.static.framework.detector import detect_framework
from mcpsec.static.analysis.sink_scanner import SinkScanner
from mcpsec.static.analysis.reachability import ReachabilityAnalyzer
from mcpsec.static.semgrep_engine import run_semgrep
from mcpsec.static.py_analyzer import PY_EXTENSIONS, scan_py_file
from mcpsec.ui import console


async def run_audit(
    npm: str | None = None,
    github: str | None = None,
    path: str | None = None,
    ai: bool = False,
) -> tuple[List[Finding], str | None]:
    """
    Run the static audit.
    """

    # Phase 1: Fetch source
    source_path = await fetch_source(npm, github, path)
    if not source_path:
        return [], None

    console.print(f"  [success]Source: {source_path}[/success]")

    findings: List[Finding] = []
    root = Path(source_path)

    try:
        # Phase 2: Detect framework
        console.print("  [cyan]Detecting framework...[/cyan]")
        framework_info = detect_framework(root)
        console.print(f"    Language : {framework_info.language.value}")
        console.print(f"    Framework: {framework_info.framework.value}")

        # Phase 3: Sink scanning (pattern database)
        console.print("  [cyan]Scanning for dangerous sinks...[/cyan]")
        scanner = SinkScanner()
        scan_result = scanner.scan(root, framework_info)
        console.print(f"    Found {len(scan_result.matches)} potential sinks")
        console.print(f"    Scanned {scan_result.files_scanned} files with "
                      f"{scan_result.patterns_applied} patterns")

        # Phase 4: Semgrep rules
        console.print("  [cyan]Running Semgrep rules...[/cyan]")
        try:
            semgrep_findings = run_semgrep(root)
            findings.extend(semgrep_findings)
            console.print(f"    Semgrep found {len(semgrep_findings)} issues")
        except Exception as e:
            console.print(f"    [warning]Semgrep skipped: {e}[/warning]")

        # Phase 5: Python AST analysis
        _scan_py_files(root, findings)

        # Phase 6: LLM reachability
        if scan_result.matches:
            analyzer = ReachabilityAnalyzer()
            if ai and analyzer.available:
                console.print("  [cyan]AI analyzing reachability...[/cyan]")
                ai_findings = await analyzer.analyze_sinks(
                    scan_result.matches,
                    framework_info,
                    root,
                )
                console.print(f"    AI validated {len(ai_findings)} reachable sinks")
                findings.extend(ai_findings)
            else:
                mode = "(use --ai for better results)" if not ai else "(no LLM configured)"
                console.print(f"  [cyan]Heuristic analysis {mode}...[/cyan]")
                heuristic_findings = analyzer._heuristic_analysis(
                    scan_result.matches,
                    framework_info,
                )
                console.print(f"    Heuristic found {len(heuristic_findings)} high-confidence sinks")
                findings.extend(heuristic_findings)

        # Phase 7: Deduplicate and heuristics
        findings = _deduplicate(findings)
        findings = _apply_design_heuristics(findings, root)

    except Exception as e:
        console.print(f"  [danger]Error during audit: {e}[/danger]")
        import traceback
        traceback.print_exc()
    finally:
        if npm or github:
            cleanup_temp(source_path)

    # Sort by severity
    findings.sort(key=lambda f: _severity_rank(f.severity), reverse=True)
    return findings, source_path


# ─── helpers ─────────────────────────────────────────────────────────────────

def _scan_py_files(root: Path, findings: List[Finding]) -> None:
    """Scan Python files with AST analyzer."""
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if fp.suffix.lower() not in PY_EXTENSIONS:
            continue
        if _is_excluded(fp):
            continue
        try:
            findings.extend(scan_py_file(fp))
        except Exception:
            pass


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings by (file, line, title)."""
    seen: set[tuple] = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _apply_design_heuristics(findings: List[Finding], root: Path) -> List[Finding]:
    """Detect intentional shell tools and downgrade command injection severity."""
    is_shell_tool = False

    for readme in ["README.md", "readme.md", "README.rst"]:
        readme_path = root / readme
        if readme_path.exists():
            try:
                content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
                if any(kw in content for kw in [
                    "execute commands", "run shell", "command execution",
                    "terminal access", "shell access", "run arbitrary",
                    "radare2", "debugger",
                ]):
                    is_shell_tool = True
                    break
            except Exception:
                pass

    if not is_shell_tool:
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                content = pkg_json.read_text(encoding="utf-8", errors="ignore").lower()
                if any(kw in content for kw in [
                    "command", "shell", "exec", "terminal",
                    "desktop commander", "run command",
                ]):
                    is_shell_tool = True
            except Exception:
                pass

    if is_shell_tool:
        for f in findings:
            if "command" in f.title.lower() or "exec" in f.title.lower():
                f.severity = Severity.INFO
                f.description += (
                    "\n\nNote: This project appears to be designed for "
                    "command execution. This finding may be expected behavior."
                )

    return findings


def _is_excluded(path: Path) -> bool:
    """Check if file should be excluded from audit (tests, build dirs)."""
    parts = [p.lower() for p in path.parts]
    excluded_dirs = {"tests", "__tests__", "test", "build", "dist", "out", "coverage", "__pycache__"}
    if any(d in parts for d in excluded_dirs):
        return True

    name = path.name.lower()
    if name.endswith((".test.ts", ".test.js", ".spec.ts", ".spec.js",
                       ".test.jsx", ".test.tsx")):
        return True
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    # Exclude the pattern files themselves
    if name in ("patterns.py", "py_analyzer.py", "taint_analyzer.py"):
        return True

    return False


def _severity_rank(severity) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return ranks.get(str(severity).lower(), 0)
