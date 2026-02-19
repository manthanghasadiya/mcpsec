"""
Dangerous patterns for static analysis.
"""

import re

class Pattern:
    def __init__(self, name: str, regex: str, severity: str, cwe: str, description: str, remediation: str):
        self.name = name
        self.regex = re.compile(regex, re.MULTILINE | re.DOTALL)
        self.severity = severity
        self.cwe = cwe
        self.description = description
        self.remediation = remediation

# ─── JavaScript / TypeScript Patterns ────────────────────────────────────────

# ─── JavaScript / TypeScript Patterns ────────────────────────────────────────

JS_PATTERNS = [
    Pattern(
        name="Command Injection (Template Literal)",
        regex=r"(?:child_process\.|exec|execSync|spawn|spawnSync|execAsync|execPromise|execCommand|runCommand|shellExec)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`",
        severity="critical",
        cwe="CWE-78",
        description="Command execution with template literal interpolation used in `exec` or `spawn`.",
        remediation="Use `execFile` or `spawn` with an array of arguments instead of a shell command string. Do not interpolate variables into shell commands.",
    ),
    Pattern(
        name="Command Injection (Async Exec)",
        regex=r"(?:execAsync|execPromise|execCommand|runCommand|shellExec)\s*\(\s*`",
        severity="critical",
        cwe="CWE-78",
        description="Async command execution with backticks/template literal.",
        remediation="Use `execFile` or `spawn` with an array of arguments.",
    ),
    Pattern(
        name="Command Injection (Async Exec Variable)",
        regex=r"(?:execAsync|execPromise|execCommand|runCommand|shellExec)\s*\(\s*(?!`|\"|\')[a-zA-Z]",
        severity="critical",
        cwe="CWE-78",
        description="Async command execution with a variable argument.",
        remediation="Ensure the variable does not contain user input. Use `execFile` if possible.",
    ),
    Pattern(
        name="Dangerous Exec Wrapper Setup",
        regex=r"promisify\s*\(\s*(?:exec|execSync)\s*\)",
        severity="high",
        cwe="CWE-78",
        description="`promisify(exec)` creates an async exec wrapper. Check usages for unsanitized input.",
        remediation="Verify all calls to this wrapper use sanitized inputs.",
    ),
    Pattern(
        name="Command Injection (Concatenation)",
        regex=r"(?:child_process\.|exec|execSync|spawn|spawnSync|execAsync|execPromise)\s*\(\s*(?:[^,\)\n]*\+|[^,\)\n]*\s*\+\s*[^,\)\n]*)",
        severity="critical",
        cwe="CWE-78",
        description="Command execution with string concatenation used in `exec` or `spawn`.",
        remediation="Use `execFile` or `spawn` with an array of arguments. Validate and sanitize all inputs.",
    ),
    Pattern(
        name="Command Injection (Variable Argument)",
        regex=r"(?:exec|execSync|execAsync|execPromise)\s*\(\s*(?!`|\"|\')(?!{)[a-zA-Z_]\w*(?:\s*,|\s*\))",
        severity="high",
        cwe="CWE-78",
        description="exec called with a variable argument. If this variable contains user input, this is command injection.",
        remediation="Ensure the variable is not user-controlled input.",
    ),
    Pattern(
        name="Dangerous Eval",
        regex=r"\beval\s*\(",
        severity="critical",
        cwe="CWE-95",
        description="Use of `eval` allows execution of arbitrary code.",
        remediation="Avoid `eval` entirely. Use standard data parsing (e.g., `JSON.parse`) instead.",
    ),
    Pattern(
        name="Dangerous Function Constructor",
        regex=r"new\s+Function\s*\(",
        severity="critical",
        cwe="CWE-95",
        description="The `Function` constructor works like `eval()` and can execute arbitrary code.",
        remediation="Do not use the `Function` constructor with user input.",
    ),
]

# ─── Python Patterns (Regex Fallback) ────────────────────────────────────────
# Note: Python analysis primarily uses AST, but these regexes catch some cases
# that might be missed or are just simple text matches.

PY_PATTERNS = [
    Pattern(
        name="Command Injection (Shell=True)",
        regex=r"(?:subprocess\.(?:run|call|Popen|check_output)|asyncio\.create_subprocess_shell)\s*\(.*shell\s*=\s*True",
        severity="critical",
        cwe="CWE-78",
        description="Subprocess call with `shell=True`.",
        remediation="Set `shell=False` (default) and pass args as a list. If shell features are needed, strictly sanitize input.",
    ),
    Pattern(
        name="Dangerous OS System",
        regex=r"\bos\.system\s*\(",
        severity="critical",
        cwe="CWE-78",
        description="Use of `os.system` invokes a shell and is prone to injection.",
        remediation="Use `subprocess.run` with `shell=False` and a list of arguments.",
    ),
    Pattern(
        name="Dangerous OS Popen",
        regex=r"\bos\.popen\s*\(",
        severity="critical",
        cwe="CWE-78",
        description="Use of `os.popen` invokes a shell and is prone to injection.",
        remediation="Use `subprocess.run` or `subprocess.Popen` with `shell=False`.",
    ),
    Pattern(
        name="Dangerous Eval/Exec",
        regex=r"\b(eval|exec)\s*\(",
        severity="critical",
        cwe="CWE-95",
        description="Dynamic code execution via `eval` or `exec`.",
        remediation="Avoid dynamic code execution. Use safer alternatives like `ast.literal_eval` for parsing literals.",
    )
]

# ─── Common Patterns (Both Languages) ────────────────────────────────────────

COMMON_PATTERNS = [
    Pattern(
        name="Path Traversal (File Open)",
        # Matches open(var + ...) or readFile(var + ...)
        regex=r"(?:open|readFile|readFileSync|createReadStream)\s*\(\s*(?:[^,\)\n]*\+|[^,\)\n]*\s*\+\s*[^,\)\n]*)",
        severity="medium",
        cwe="CWE-22",
        description="File open with string concatenation, potential path traversal.",
        remediation="Validate paths against an allowlist. Use `path.basename` to restrict to filenames only.",
    ),
    Pattern(
        name="Scan: SQL Injection",
        # Matches query with concat or interpolate
        regex=r"(?:execute|query|raw)\s*\(\s*(?:f[\"']|`|[^,\)\n]*\+)",
        severity="high",
        cwe="CWE-89",
        description="SQL query construction using string concatenation or interpolation.",
        remediation="Use parameterized queries (e.g., `?` or `%s` placeholders) to prevent SQL injection.",
    ),
    Pattern(
        name="Scan: Potential SSRF",
        # Matches fetch(var) or requests.get(var) -- very broad, but useful for audit
        regex=r"(?:\bfetch|requests\.(?:get|post|put|delete|head|patch)|urllib\.request\.urlopen)\s*\(\s*(?![\"'])[^,\)\n]+",
        severity="info",
        cwe="CWE-918",
        description="HTTP request with variable input.",
        remediation="Validate URL schemes and hostnames against an allowlist before making requests.",
    )
]
