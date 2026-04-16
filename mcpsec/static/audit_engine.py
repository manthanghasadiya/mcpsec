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
from mcpsec.static.semgrep_engine import run_semgrep, run_semgrep_with_categories
from mcpsec.static.py_analyzer import PY_EXTENSIONS, scan_py_file
from mcpsec.ui import console


async def run_audit(
    npm: str | None = None,
    github: str | None = None,
    path: str | None = None,
    ai: bool = False,
    include_tests: bool = False,
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
        # explicit=True: user pointed directly at this path; relax exclusions
        explicit = path is not None
        scan_result = scanner.scan(root, framework_info, explicit=explicit)
        console.print(f"    Found {len(scan_result.matches)} potential sinks")
        console.print(f"    Scanned {scan_result.files_scanned} files with "
                      f"{scan_result.patterns_applied} patterns")

        # Phase 4: Semgrep rules
        console.print("  [cyan]Running Semgrep rules...[/cyan]")
        try:
            if include_tests:
                semgrep_findings = run_semgrep(root, include_tests=True)
                findings.extend(semgrep_findings)
                console.print(f"    Semgrep found {len(semgrep_findings)} issues (test files included)")
            else:
                production_findings, excluded_counts = run_semgrep_with_categories(root)
                findings.extend(production_findings)
                console.print(f"    Semgrep found {len(production_findings)} issues")
                
                # Show exclusion summary
                total_excluded = sum(excluded_counts.values())
                if total_excluded > 0:
                    console.print(f"    [dim]Excluded {total_excluded} findings from non-production code:[/dim]")
                    if excluded_counts.get("test", 0) > 0:
                        console.print(f"      [dim]• Test files: {excluded_counts['test']}[/dim]")
                    if excluded_counts.get("demo", 0) > 0:
                        console.print(f"      [dim]• Demo/example code: {excluded_counts['demo']}[/dim]")
                    if excluded_counts.get("script", 0) > 0:
                        console.print(f"      [dim]• Build scripts: {excluded_counts['script']}[/dim]")
                    console.print(f"    [dim]Use --include-tests to see all findings[/dim]")
        except Exception as e:
            console.print(f"    [warning]Semgrep skipped: {e}[/warning]")

        # Phase 5: Python AST analysis
        _scan_py_files(root, findings, explicit=path is not None)

        # Phase 6: Sink analysis (Heuristic)
        if scan_result.matches:
            from mcpsec.static.analysis.reachability import ReachabilityAnalyzer
            analyzer = ReachabilityAnalyzer()
            
            # We always use heuristic analysis here to avoid making 
            # multiple LLM calls per sink. The final AI step (Phase 8) 
            # will classify these sinks along with Semgrep findings.
            mode = "(use --ai for server-aware classification)" if not ai else "(AI purpose classification pending)"
            console.print(f"  [cyan]Heuristic sink analysis {mode}...[/cyan]")
            
            heuristic_findings = analyzer._heuristic_analysis(
                scan_result.matches,
                framework_info,
            )
            console.print(f"    Heuristic found {len(heuristic_findings)} potential sinks")
            findings.extend(heuristic_findings)

        # Phase 7: Deduplicate
        findings = _deduplicate(findings)

        # Phase 8: AI Classification (Opt-in)
        if ai and findings:
            from mcpsec.ai.finding_classifier import classify_server_and_findings
            from mcpsec.ai.llm_client import LLMClient
            
            console.print("  [cyan]AI classifying findings...[/cyan]")
            try:
                llm_client = LLMClient()
                if llm_client.available:
                    server_profile, findings = await classify_server_and_findings(
                        root,
                        findings,
                        llm_client
                    )
                    
                    # Show server profile summary
                    console.print(f"    [success]Server type: {server_profile.server_type}[/success]")
                    if server_profile.notes:
                        console.print(f"    [dim]Notes: {server_profile.notes}[/dim]")
                    
                    # Count classifications
                    tag_counts = {}
                    for f in findings:
                        for tag_name in ["🔴 VULNERABILITY", "🟠 SUSPICIOUS", "🟡 NEEDS REVIEW", 
                                        "🔵 LIKELY BY DESIGN", "⚪ BY DESIGN"]:
                            if tag_name in f.title:
                                tag_counts[tag_name] = tag_counts.get(tag_name, 0) + 1
                                break
                    
                    tag_line = " ".join([f"{t}: {c}" for t, c in tag_counts.items()])
                    if tag_line:
                        console.print(f"    [dim]AI Summary: {tag_line}[/dim]")
                else:
                    console.print("    [warning]AI skipped: No API key configured[/warning]")
                    findings = _apply_design_heuristics(findings, root)
            except Exception as e:
                console.print(f"    [warning]AI classification failed: {e}[/warning]")
                findings = _apply_design_heuristics(findings, root)
        else:
            # Traditional hardcoded heuristics
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

def _scan_py_files(root: Path, findings: List[Finding], explicit: bool = False) -> None:
    """Scan Python files with AST analyzer."""
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        if fp.suffix.lower() not in PY_EXTENSIONS:
            continue
        # When the user explicitly targeted this directory, always scan
        # direct children; only apply exclusions to deeper descendants.
        if explicit and fp.parent == root:
            pass
        elif _is_excluded(fp):
            continue
        try:
            findings.extend(scan_py_file(fp))
        except Exception:
            pass


def _deduplicate(findings: List[Finding]) -> List[Finding]:
    """Deduplicate findings by file + line + vuln type."""
    seen = set()
    unique = []
    
    for f in findings:
        # Create unique key from location and vuln type
        key = (f.file_path, f.line_number, f.title.split(":")[0] if ":" in f.title else f.title)
        
        if key not in seen:
            seen.add(key)
            unique.append(f)
            
    return unique


def _apply_design_heuristics(findings: List[Finding], source_path: Path) -> List[Finding]:
    """
    Detect if project is a 'by design' tool and adjust severity.
    
    Server types detected:
    - Shell/command tools: exec() is expected
    - Filesystem tools: file operations are expected
    - Fetch/HTTP tools: URL requests are expected
    - Database tools: SQL queries are expected
    """
    from mcpsec.models import Severity
    
    # Detect server type from package.json and README
    server_types = _detect_server_types(source_path)
    
    if not server_types:
        return findings
    
    # Map server types to expected vulnerability patterns
    expected_patterns = {
        "shell": ["command", "exec", "spawn", "shell"],
        "filesystem": ["path", "file", "traversal", "fs-read", "fs-write", "open-non-literal"],
        "fetch": ["ssrf", "url", "http", "request", "fetch", "axios"],
        "database": ["sql", "query", "injection", "kysely", "sequelize"],
    }
    
    for f in findings:
        title_lower = f.title.lower()
        
        for server_type, patterns in expected_patterns.items():
            if server_type in server_types:
                if any(p in title_lower for p in patterns):
                    # Downgrade to INFO and add note
                    if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                        f.severity = Severity.INFO
                        f.description += (
                            f"\n\n⚠️ By Design: This project appears to be a {server_type} server. "
                            f"This finding may be expected behavior for its intended purpose."
                        )
                    break
    
    return findings


def _detect_server_types(source_path: Path) -> set:
    """
    Detect what type of MCP server this is based on package.json and README.
    
    Returns set of: 'shell', 'filesystem', 'fetch', 'database'
    """
    server_types = set()
    
    # Keywords that indicate server type
    type_keywords = {
        "shell": [
            "command", "shell", "exec", "terminal", "commander", 
            "run command", "execute command", "bash", "powershell"
        ],
        "filesystem": [
            "filesystem", "file system", "file-system", "file access",
            "read file", "write file", "directory", "folder"
        ],
        "fetch": [
            "fetch", "http client", "web request", "url fetch",
            "download", "scrape", "crawler"
        ],
        "database": [
            "database", "sql", "sqlite", "postgres", "mysql",
            "mongodb", "redis", "query"
        ],
    }
    
    # Check package.json
    pkg_json = source_path / "package.json"
    if pkg_json.exists():
        try:
            content = pkg_json.read_text(encoding="utf-8", errors="ignore").lower()
            for server_type, keywords in type_keywords.items():
                if any(kw in content for kw in keywords):
                    server_types.add(server_type)
        except Exception:
            pass
    
    # Check pyproject.toml
    pyproject = source_path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore").lower()
            for server_type, keywords in type_keywords.items():
                if any(kw in content for kw in keywords):
                    server_types.add(server_type)
        except Exception:
            pass
    
    # Check README
    for readme_name in ["README.md", "readme.md", "README.rst", "README.txt"]:
        readme_path = source_path / readme_name
        if readme_path.exists():
            try:
                content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
                for server_type, keywords in type_keywords.items():
                    if any(kw in content for kw in keywords):
                        server_types.add(server_type)
            except Exception:
                pass
            break
    
    # Check directory name
    dir_name = source_path.name.lower()
    for server_type, keywords in type_keywords.items():
        if any(kw.replace(" ", "") in dir_name or kw.replace(" ", "-") in dir_name for kw in keywords):
            server_types.add(server_type)
    
    return server_types


def _is_excluded(path: Path) -> bool:
    """Check if file should be excluded from audit (tests, build dirs)."""
    parts = [p.lower() for p in path.parts]
    excluded_dirs = {
        "tests", "__tests__", "test", "build", "dist", "out",
        "coverage", "__pycache__", "patterns",
    }
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
