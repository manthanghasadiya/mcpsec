"""
Static Taint Analyzer for MCP Servers.
Traces user input from MCP tool registration parameters to dangerous sinks.
"""

import re
from pathlib import Path
from typing import List, Dict, Set, Any
from mcpsec.models import Finding, Severity

class TaintAnalyzer:
    def __init__(self):
        self.findings = []
        # Sources: Variables that hold user input -> Description of source flow
        self.tainted_vars: Dict[str, str] = {}
        
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
            "subprocess.run": "Command Injection",
            "subprocess.call": "Command Injection",
            "subprocess.Popen": "Command Injection",
            "os.system": "Command Injection",
            "os.popen": "Command Injection",
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
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue

            # A. Propagate Taint
            self._propagate_taint(stripped)
            
            # B. Check Sinks
            self._check_sinks(file_path, line_no, stripped, line)

        return self.findings

    def _identify_sources(self, content: str):
        """Identify variables that originate from MCP tool inputs."""
        
        # --- JS/TS Patterns ---
        
        # Pattern A: Destructuring request.params.arguments (and variations)
        # const { fileKey } = request.params.arguments;
        # const { path } = args;
        for destruct_match in re.finditer(r"(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*(?:request\.params\.arguments|args|params|input|toolInput|toolArgs)", content):
            args = destruct_match.group(1).split(",")
            for arg in args:
                # Handle renaming: { prop: alias } -> alias is tainted
                parts = arg.split(":")
                var_name = parts[-1].strip() # Takes alias if present, else prop
                if var_name:
                    self.tainted_vars[var_name] = f"tool parameter '{var_name}'"

        # Pattern B: Direct property access on common arg names
        # args.PROPERTY, params.PROPERTY
        for match in re.finditer(r"\b(?:args|params|input|toolInput|toolArgs)\.([\w]+)", content):
            prop = match.group(1)
            # Heuristic: assume 'prop' is a variable name that might be used
            if prop not in self.tainted_vars:
                self.tainted_vars[prop] = f"tool parameter '{prop}'"

        # --- Python Patterns ---
        
        # Pattern C: @mcp.tool() decorated functions
        for match in re.finditer(
            r"@(?:mcp|server)\.tool\(\)?\s*\n\s*(?:async\s+)?def\s+\w+\(([^)]+)\)",
            content
        ):
            params_str = match.group(1)
            for param in params_str.split(","):
                param = param.strip().split(":")[0].strip()  # Remove type hints
                if param and param not in ("self", "ctx", "context"):
                    self.tainted_vars[param] = f"tool parameter '{param}'"

        # Pattern D: FastMCP / other tool decorators
        for match in re.finditer(
            r"@\w+\.tool\b.*?\ndef\s+\w+\(([^)]+)\)",
            content,
            re.DOTALL
        ):
            params_str = match.group(1)
            for param in params_str.split(","):
                param = param.strip().split(":")[0].strip()
                if param and param not in ("self", "ctx", "context"):
                    self.tainted_vars[param] = f"tool parameter '{param}'"

    def _propagate_taint(self, line: str):
        """Update tainted_vars based on assignments in the line."""
        
        # 1. Assignment from existing tainted var
        # const x = ... tainted ...
        
        # Check against existing tainted vars
        # Copy items to avoid modification during iteration issues
        curr_tainted = list(self.tainted_vars.items())
        
        for var_name, source in curr_tainted:
            if var_name in line:
                # Robust assignment detection
                assign_patterns = [
                    r"(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=",  # JS declaration
                    r"^([a-zA-Z_$][\w$]*)\s*=\s*(?!=)",               # JS/Py assignment
                    r"(?:const|let|var)\s*\{\s*(\w+(?:\s*,\s*\w+)*)\s*\}\s*=", # JS destructuring (simplified)
                ]
                
                for pat in assign_patterns:
                    m = re.search(pat, line)
                    if m:
                        new_var = m.group(1).strip()
                        # Avoid checking if var_name is strictly in RHS logic for now (simple heuristic)
                        # We assume if line has assignment AND contains tainted var, it propagates.
                        if new_var != var_name and new_var not in self.tainted_vars:
                            if not self._is_sanitized(line):
                                self.tainted_vars[new_var] = f"{source} → {new_var}"
                        break # Found assignment

        # 2. Assignment from property access (args.prop)
        # const x = args.fileKey
        args_access = re.search(
            r"(?:const|let|var)?\s*([a-zA-Z_$][\w$]*)\s*=\s*.*\b(?:args|params|input|toolInput|toolArgs)\.([\w]+)",
            line
        )
        if args_access:
            new_var = args_access.group(1)
            prop_name = args_access.group(2)
            if new_var not in self.tainted_vars:
                if not self._is_sanitized(line):
                    self.tainted_vars[new_var] = f"tool parameter '{prop_name}'"

    def _check_sinks(self, file_path: Path, line_no: int, stripped: str, original_line: str):
        """Check if any tainted variable flows into a sink."""
        
        for sink_func, vuln_type in self.sinks.items():
            if sink_func not in stripped:
                continue
                
            for var_name, source in self.tainted_vars.items():
                if var_name in stripped:
                    # HEURISTIC: precise check is hard with regex. 
                    # If line contains sink_func AND tainted_var, flag it.
                    
                    # Validate sink usage: sink_func(...)
                    if re.search(r"\b" + re.escape(sink_func) + r"\s*\(", stripped):
                        
                        # Validate var usage: using word boundary
                        if re.search(r"\b" + re.escape(var_name) + r"\b", stripped):
                            
                            if not self._is_sanitized(stripped):
                                confidence = "high"
                                # Downgrade confidence heuristics
                                if len(var_name) <= 2:
                                    confidence = "medium" # Short vars like 'i', 'x' might be noise
                                if original_line.count("'") >= 4 or original_line.count('"') >= 4:
                                    confidence = "low" # Inside complex string or similar
                                
                                self._add_finding(
                                    file_path, 
                                    line_no, 
                                    vuln_type, 
                                    sink_func, 
                                    var_name, 
                                    source, 
                                    stripped,
                                    confidence
                                )

    def _is_sanitized(self, line: str) -> bool:
        """Check for common sanitization patterns on the line."""
        sanitizers = [
            "encodeURIComponent",
            "path.basename",
            # "path.resolve", - REMOVED: not a sanitizer
            "parseInt",
            "Number(",
            "JSON.stringify",
            "execFile",     # Safe alternative
            "shlex.quote",  # Python
            "shlex.split",  # Python
            "mysql.escape",
            "escape(",
        ]
        # Allowlist check heuristic
        if "whitelist" in line.lower() or "allowlist" in line.lower():
            return True
            
        return any(s in line for s in sanitizers)

    def _add_finding(self, file_path: Path, line: int, vuln_type: str, sink: str, var: str, flow: str, code: str, confidence: str):
        code = code[:200] # Truncate long lines
        sink_desc = f"{sink} at line {line}"
        full_flow = f"{flow} → {sink}()"
        
        finding = Finding(
            severity=Severity.CRITICAL, 
            scanner="mcp-taint-analyzer",
            title=f"Tainted Data Flow: {vuln_type}",
            description=f"User input from '{var}' flows into dangerous sink '{sink}' without sanitization.",
            detail=f"Taint Source: {flow}\nSink: {sink_desc}",
            evidence=code,
            file_path=str(file_path),
            line_number=line,
            code_snippet=code,
            remediation="Validate and sanitize input before using it in dangerous functions.",
            taint_source=flow.split(" → ")[0],
            taint_sink=sink_desc,
            taint_flow=full_flow,
            confidence=confidence
        )
        self.findings.append(finding)

def scan_taint(file_path: Path) -> List[Finding]:
    """Entry point for the audit engine."""
    analyzer = TaintAnalyzer()
    return analyzer.scan_file(file_path)
