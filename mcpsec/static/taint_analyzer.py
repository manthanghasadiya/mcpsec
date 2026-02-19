"""
Static Taint Analyzer for MCP Servers (JS/TS Focus).
Traces user input from MCP tool registration parameters to dangerous sinks.
"""

import re
from pathlib import Path
from typing import List, Dict, Set, Any
from mcpsec.models import Finding, Severity

class TaintAnalyzer:
    def __init__(self):
        self.findings = []
        # Sources: Variables that hold user input
        self.tainted_vars: Dict[str, str] = {}  # var_name -> source_description
        
        # Sinks: Dangerous functions -> Vulnerability Type
        self.sinks = {
            "exec": "Command Injection",
            "execSync": "Command Injection",
            "execAsync": "Command Injection",
            "execPromise": "Command Injection",
            "spawn": "Command Injection",
            "eval": "Dangerous Eval",
            "Function": "Dangerous Function",
            "fs.open": "Path Traversal",
            "fs.readFile": "Path Traversal",
            "fs.readFileSync": "Path Traversal",
            "open": "Path Traversal",
        }

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a file for taint vectors."""
        self.findings = []
        self.tainted_vars.clear()
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()
        
        # 1. Identify Sources (MCP Tool Parameters)
        self._identify_sources(content)
        
        # 2. Trace Flow (assignments) & Check Sinks iteratively
        for i, line in enumerate(lines):
            line_no = i + 1
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            # A. Propagate Taint
            self._propagate_taint(stripped)
            
            # B. Check Sinks
            self._check_sinks(file_path, line_no, stripped)

        return self.findings

    def _identify_sources(self, content: str):
        """Identify variables that originate from MCP tool inputs."""
        
        # Pattern A: Destructuring request.params.arguments
        # const { fileKey, format } = request.params.arguments;
        destruct_match = re.search(r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*request\.params\.arguments", content)
        if destruct_match:
            args = destruct_match.group(1).split(",")
            for arg in args:
                # Handle renaming: { prop: alias } -> alias is tainted
                parts = arg.split(":")
                var_name = parts[-1].strip() # Takes alias if present, else prop
                if var_name:
                    self.tainted_vars[var_name] = f"tool parameter '{var_name}'"

        # Pattern B: Direct access request.params.arguments.prop
        # Matches found iter during scanning, but we can pre-seed if we want.
        # Actually, let's detect them on the fly during propagation/sink check too.
        
        # Pattern C: Zod schema definitions with .shape
        # This gives us the *names* of parameters, but not the variables holding them yet.
        # But if we see `args.PARAM_NAME`, we can taint it.
        # For now, Pattern A is the most common in the wild (Figma MCP etc).

    def _propagate_taint(self, line: str):
        """Update tainted_vars based on assignments in the line."""
        
        # 1. Assignment: new_var = old_var
        # const cmd = `git ${args.command}`
        # let url = baseUrl + path
        
        # Check against existing tainted vars
        curr_tainted = list(self.tainted_vars.items())
        
        for var_name, source in curr_tainted:
            # Case 1: Variable used in assignment (RHS)
            # const x = ... var_name ...
            if var_name in line:
                # Extract LHS variable
                # (?:const|let|var)?\s*(\w+)\s*=\s*
                assign_match = re.search(r"(?:const|let|var)?\s*([a-zA-Z_$][\w$]*)\s*=\s*", line)
                if assign_match:
                    new_var = assign_match.group(1)
                    # Avoid self-assignment or re-tainting same var repeatedly logic
                    if new_var != var_name and new_var not in self.tainted_vars:
                         if not self._is_sanitized(line):
                             self.tainted_vars[new_var] = f"{source} -> {new_var}"

        # Case 2: Direct access to request.params.arguments.XYZ
        # const x = request.params.arguments.repo;
        direct_access = re.search(r"(?:const|let|var)?\s*([a-zA-Z_$][\w$]*)\s*=\s*.*request\.params\.arguments\.(\w+)", line)
        if direct_access:
            new_var = direct_access.group(1)
            prop_name = direct_access.group(2)
            if new_var not in self.tainted_vars:
                if not self._is_sanitized(line):
                    self.tainted_vars[new_var] = f"tool parameter '{prop_name}'"

    def _check_sinks(self, file_path: Path, line_no: int, line: str):
        """Check if any tainted variable flows into a sink."""
        
        for sink_func, vuln_type in self.sinks.items():
            if sink_func not in line:
                continue
                
            # Check strictly: sink_func( ... tainted_var ... )
            # or tainted_var inside sink call
            
            for var_name, source in self.tainted_vars.items():
                if var_name in line:
                    # HEURISTIC: precise check is hard with regex. 
                    # If line contains sink_func AND tainted_var, flag it.
                    # Exclude: "const sink_func = ..." (assignment to sink name)
                    if re.search(r"\b" + re.escape(sink_func) + r"\s*\(", line):
                        
                        # Validate var is argument-like (not just a random string match)
                        # e.g. "param" inside "exec(param)" matches
                        # but "param" inside "exec('param')" (string literal) should ideally not match
                        # We'll use word boundary for now
                        if re.search(r"\b" + re.escape(var_name) + r"\b", line):
                            if not self._is_sanitized(line):
                                self._add_finding(file_path, line_no, vuln_type, sink_func, var_name, source, line)

    def _is_sanitized(self, line: str) -> bool:
        """Check for common sanitization patterns on the line."""
        sanitizers = [
            "encodeURIComponent",
            "path.basename",
            "path.resolve", # Sometimes used for safety, though check is needed
            "parseInt",
            "Number(",
            "JSON.stringify",
            "execFile", # Safe alternative
            "spawn",    # Often safer than exec, but check args
        ]
        # Allowlist check heuristic (boring but effective)
        if "whitelist" in line.lower() or "allowlist" in line.lower():
            return True
            
        return any(s in line for s in sanitizers)

    def _add_finding(self, file_path: Path, line: int, vuln_type: str, sink: str, var: str, flow: str, code: str):
        code = code[:200] # Truncate long lines
        finding = Finding(
            severity=Severity.CRITICAL, 
            scanner="mcp-taint-analyzer",
            title=f"Tainted Data Flow: {vuln_type}",
            description=f"User input from '{var}' flows into dangerous sink '{sink}' without sanitization.",
            detail=f"Taint Source: {flow}\nSink: {sink}",
            evidence=code,
            file_path=str(file_path),
            line_number=line,
            code_snippet=code,
            remediation="Validate and sanitize input before using it in dangerous functions.",
            taint_source=flow.split(" -> ")[0],
            taint_sink=f"{sink} at line {line}",
            taint_flow=f"{flow} -> {sink}"
        )
        self.findings.append(finding)

def scan_taint(file_path: Path) -> List[Finding]:
    """Entry point for the audit engine."""
    analyzer = TaintAnalyzer()
    return analyzer.scan_file(file_path)
