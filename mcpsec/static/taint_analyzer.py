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
            # Skip JSDoc/block comment lines: lines starting with * or */ or /**
            if stripped.startswith("*") or stripped.startswith("/*") or stripped.startswith("*/"):
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

            # Special case: "exec" can be RegExp.exec() - not dangerous
            if sink_func == "exec":
                # If it's variable.exec( pattern - it's RegExp, skip
                if re.search(r"\w+\.exec\s*\(", stripped):
                    continue
                # Also skip: .exec( at start of match means method call
                
            for var_name, source in self.tainted_vars.items():
                if var_name in stripped:
                    # Skip if var is being ASSIGNED FROM the sink (destructuring result)
                    if re.search(
                        r"(?:const|let|var)\s*\{[^}]*\b" + re.escape(var_name) + r"\b[^}]*\}\s*=\s*(?:await\s+)?\w*" + re.escape(sink_func),
                        stripped
                    ):
                        continue

                    # HEURISTIC: precise check is hard with regex. 
                    # If line contains sink_func AND tainted_var, flag it.
                    
                    # Validate sink usage: sink_func(...)
                    if re.search(r"\b" + re.escape(sink_func) + r"\s*\(", stripped):
                        
                        # Validate var usage: using word boundary
                        if re.search(r"\b" + re.escape(var_name) + r"\b", stripped):
                            
                            # Phase 9: Skip if variable is an assignment target
                            if self.is_assignment_target(var_name, stripped):
                                continue

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

    def is_assignment_target(self, var_name: str, line: str) -> bool:
        """Check if variable is being assigned FROM the sink (not flowing INTO it)."""
        patterns = [
            rf"(?:const|let|var)\s+{re.escape(var_name)}\s*=",
            rf"{re.escape(var_name)}\s*=\s*(?:await\s+)?(?:spawn|exec|execAsync|execSync|subprocess|os\.system|os\.popen)",
        ]
        return any(re.search(p, line) for p in patterns)

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

class CrossFileTaintAnalyzer:
    """Analyzes taint flow across multiple files in a project."""
    
    def __init__(self):
        # Map: function_name -> file where it's defined + parameter names
        self.exported_functions: Dict[str, dict] = {}
        # Map: file -> set of tainted variables at call sites
        self.tainted_calls: List[dict] = []
        # Map: function_name -> file where dangerous sink exists with param
        self.dangerous_functions: Dict[str, dict] = {}
    
    def analyze_project(self, source_dir: Path) -> List[Finding]:
        """Run cross-file taint analysis on entire project."""
        findings = []
        all_files = []
        
        # Collect all JS/TS and Python files (respecting exclusions)
        for file_path in source_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part.startswith(".") for part in file_path.parts):
                continue
            if "node_modules" in file_path.parts or "dist" in file_path.parts:
                continue
            ext = file_path.suffix.lower()
            if ext in {".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx", ".py"}:
                all_files.append(file_path)
        
        # PASS 1: Catalog all exported functions and their dangerous sinks
        for file_path in all_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            self._catalog_functions(file_path, content)
        
        # PASS 2: Find where tainted data flows into cataloged functions
        for file_path in all_files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            findings.extend(self._trace_cross_file(file_path, content))
        
        return findings
    
    def _catalog_functions(self, file_path: Path, content: str):
        """Pass 1: Find exported functions that contain dangerous sinks."""
        lines = content.splitlines()
        functions = []  # list of (name, start_line, params)
        
        # First, find all function definitions with their line numbers
        for i, line in enumerate(lines):
            # JS/TS and Python function patterns
            match = re.search(
                r"(?:export\s+)?(?:async\s+)?(?:function\s+|def\s+)(\w+)\s*\(([^)]*)\)",
                line
            )
            if match:
                functions.append({
                    "name": match.group(1),
                    "start": i,
                    "params": match.group(2),
                    "file": str(file_path),
                })
        
        # Determine end line for each function (next function start or EOF)
        for idx, func in enumerate(functions):
            if idx + 1 < len(functions):
                func["end"] = functions[idx + 1]["start"]
            else:
                func["end"] = len(lines)
        
        dangerous_sinks = [
            "exec", "execSync", "execAsync", "execPromise", 
            "eval", "os.system", "subprocess.run", "subprocess.call",
            "os.popen", "spawn",
        ]

        # Now check each function body for dangerous sinks
        for func in functions:
            body = "\n".join(lines[func["start"]:func["end"]])
            for sink in dangerous_sinks:
                if re.search(r"\b" + re.escape(sink) + r"\s*\(", body):
                    # This function ACTUALLY calls the sink
                    # Find which param reaches the sink
                    for param in self._parse_params(func["params"]):
                        if param.lower() in body.lower():
                            self.dangerous_functions[func["name"]] = {
                                "file": func["file"],
                                "sink": sink,
                                "param": param,
                                "line": func["start"] + 1,
                            }
                            break
                    if func["name"] in self.dangerous_functions:
                        break

    def _parse_params(self, params_str: str) -> List[str]:
        """Extract parameter names from params string."""
        params = []
        for p in params_str.split(","):
            p = p.strip()
            if not p:
                continue
            # JS: remove type annotations (param: string)
            # Python: remove type hints (param: str) and defaults (param=val)
            param_name = re.split(r"[:\s=?]", p)[0].strip()
            if param_name and param_name != "self":
                params.append(param_name)
        return params
    
    def _trace_cross_file(self, file_path: Path, content: str) -> List[Finding]:
        """Find calls to dangerous functions with tainted arguments."""
        findings = []
        
        # First, identify taint sources in THIS file
        analyzer = TaintAnalyzer()
        analyzer._identify_sources(content)
        
        # Also propagate through the file to catch derived tainted vars
        lines = content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("//") and not stripped.startswith("#"):
                # Also skip JSDoc lines
                if stripped.startswith("*") or stripped.startswith("/*") or stripped.startswith("*/"):
                    continue
                analyzer._propagate_taint(stripped)
        
        tainted = analyzer.tainted_vars
        
        if not tainted:
            return findings
        
        # Now check: does this file call any dangerous function with tainted data?
        for i, line in enumerate(lines):
            line_no = i + 1
            stripped = line.strip()
            
            for func_name, info in self.dangerous_functions.items():
                # Skip if the dangerous function is in THIS same file
                # (intra-file analyzer already handles that)
                if info["file"] == str(file_path):
                    continue
                
                # Check if this line calls the dangerous function
                if re.search(r"\b" + re.escape(func_name) + r"\s*\(", stripped):
                    # Check if any tainted variable is passed as argument
                    for var_name, source in tainted.items():
                        if re.search(r"\b" + re.escape(var_name) + r"\b", stripped):
                            # CROSS-FILE TAINT FLOW DETECTED
                            sink_file = Path(info["file"]).name
                            
                            flow = (
                                f"{source} → {func_name}({var_name}) → "
                                f"{info['sink']}() in {sink_file}"
                            )
                            
                            findings.append(Finding(
                                severity=Severity.CRITICAL,
                                scanner="mcp-taint-analyzer-xfile",
                                title=f"Cross-File Tainted Data Flow: {info['sink']}()",
                                description=(
                                    f"Tool parameter '{var_name}' is passed to "
                                    f"function '{func_name}()' which contains "
                                    f"dangerous sink '{info['sink']}()' in "
                                    f"{sink_file}."
                                ),
                                detail=(
                                    f"Source: {source} (in {file_path.name})\n"
                                    f"Sink: {info['sink']}() (in {sink_file})\n"
                                    f"Via: {func_name}() call"
                                ),
                                evidence=stripped[:200],
                                file_path=str(file_path),
                                line_number=line_no,
                                code_snippet=stripped[:200],
                                remediation=(
                                    f"Sanitize '{var_name}' before passing to "
                                    f"'{func_name}()'. In {sink_file}, use "
                                    f"execFile() instead of {info['sink']}() "
                                    f"or validate input."
                                ),
                                taint_source=source.split(" → ")[0],
                                taint_sink=f"{info['sink']}() in {sink_file}",
                                taint_flow=flow,
                                confidence="high",
                            ))
        
        return findings

def scan_taint_cross_file(source_dir: Path) -> List[Finding]:
    """Run cross-file taint analysis on entire project directory."""
    analyzer = CrossFileTaintAnalyzer()
    return analyzer.analyze_project(source_dir)
