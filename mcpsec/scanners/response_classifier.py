"""
Response Classifier — shared module for all dynamic scanners.

Classifies MCP server responses into:
  SAFE       → Server security controls blocked the attack (do NOT report)
  CONFIRMED  → Deterministic proof of exploitation
  LIKELY     → Strong indicators, high confidence
  POSSIBLE   → Pattern match, needs verification

Used by: command_injection, path_traversal, sql_rce, ssrf scanners.
"""

import json
import re
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    SAFE = "SAFE"
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    NONE = "NONE"  # No signal either way


# ─── JSON-RPC Error Codes That Mean "SAFE" ─────────────────────────────────

SAFE_JSONRPC_CODES = {
    -32600,  # Invalid Request
    -32601,  # Method not found
    -32602,  # Invalid params (schema validation blocked it)
    -32603,  # Internal error (server-side error handling)
    -32700,  # Parse error
}


# ─── Sandbox / Access Control Patterns (case-insensitive) ───────────────────
# If ANY of these appear in the response, the attack was BLOCKED → SAFE

SANDBOX_BLOCK_PATTERNS = [
    r"access\s+denied",
    r"permission\s+denied",
    r"not\s+permitted",
    r"not\s+allowed",
    r"path\s+outside\s+allowed",
    r"outside\s+(?:the\s+)?(?:allowed|permitted|sandbox|safe)\s+director",
    r"blocked\s+by\s+(?:security|policy|firewall)",
    r"operation\s+not\s+permitted",
    r"forbidden",
    r"unauthorized",
    r"restricted\s+(?:path|directory|access|operation)",
    r"cannot\s+access",
    r"is\s+not\s+within\s+(?:the\s+)?(?:allowed|permitted)",
    r"path\s+traversal\s+(?:detected|blocked|prevented)",
    r"invalid\s+path",
    r"only\s+select\s+queries\s+are\s+allowed",
    r"only\s+create\s+table\s+statements\s+are\s+allowed",
    r"query\s+type\s+.*\s+not\s+supported",
]

# ─── Schema / Validation Patterns (input was rejected at parse layer) ───────

SCHEMA_REJECTION_PATTERNS = [
    r"zod\s*(?:error|validation|issue)",
    r"schema\s+validation\s+(?:failed|error)",
    r"invalid\s+(?:argument|parameter|input|type)",
    r"expected\s+(?:string|number|boolean|object|array)",
    r"required\s+property",
    r"type\s+mismatch",
    r"validation\s+error",
    r"does\s+not\s+match\s+(?:the\s+)?(?:expected|required)\s+(?:format|pattern|type)",
]


# ─── Command Injection Execution Proofs ─────────────────────────────────────

CMD_INJECTION_CONFIRMED = [
    r"uid=\d+\(?\w*\)?\s+gid=\d+",  # Unix id output
    r"uid=\d+",  # Partial id
    r"gid=\d+",  # Partial id
    r"groups=\d+",  # groups output
    r"NT\s+AUTHORITY\\",  # Windows identity
    r"BUILTIN\\",  # whoami (Windows)
    r"mcpsec_cmd_success",  # generic anchor
    r"\w+\\Administrator",  # Windows admin
    r"MCPSEC_INJECTED",  # Our canary
    r"root:x:0:0:",  # /etc/passwd read via cmd
    r"\[boot\s+loader\]",  # win.ini read via cmd
    r"\[extensions\]",  # win.ini content
]

CMD_INJECTION_LIKELY = [
    r"(?:bash|sh|cmd|powershell):\s+.*:\s+(?:command\s+)?not\s+found",
    r"is\s+not\s+recognized\s+as\s+an?\s+(?:internal|external)\s+command",
    r"'(?:id|whoami|uname)'\s+is\s+not\s+recognized",
    r"cannot\s+execute\s+binary\s+file",
    r"/bin/(?:sh|bash|id|whoami|cat):",
    r"(?:command|cmd)\s+not\s+found",
]


# ─── Path Traversal / LFI Execution Proofs ──────────────────────────────────

PATH_TRAVERSAL_CONFIRMED = [
    r"root:x:0:0:",  # /etc/passwd
    r"root:.*:0:0:",  # /etc/passwd variant
    r"daemon:x:\d+:\d+:",  # /etc/passwd entry
    r"nobody:x:",  # /etc/passwd entry
    r"\[boot\s+loader\]",  # Windows system.ini
    r"\[extensions\]",  # Windows win.ini
    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY",  # SSH/TLS private key
    r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY",  # OpenSSH key
    r"-----BEGIN\s+CERTIFICATE",  # TLS cert
    r"aws_access_key_id\s*=",  # AWS creds
    r"aws_secret_access_key\s*=",  # AWS creds
    r"PRIVATE\s+KEY",  # Generic private key
    r"DB_PASSWORD\s*=",  # Env file
    r"DATABASE_URL\s*=",  # Env file
    r"OPENAI_API_KEY\s*=",  # API key in env
    r"Authorization:\s+Bearer\s+",  # Auth header in config
    r"\"accessKeyId\":",  # Cloud creds JSON
    r"kubernetes\.io/serviceaccount",  # K8s token
]

PATH_TRAVERSAL_LIKELY = [
    r"ENOENT:?\s+no\s+such\s+file",  # Node.js - file doesn't exist but was looked up outside sandbox
    r"FileNotFoundError",  # Python
    r"No\s+such\s+file\s+or\s+directory",  # Generic Unix
    r"java\.io\.FileNotFoundException",  # Java
    r"The\s+system\s+cannot\s+find",  # Windows
    r"Access\s+is\s+denied",  # Windows access denied
]


# ─── SQL Injection Execution Proofs ─────────────────────────────────────────

SQLI_CONFIRMED = [
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",
    r"psycopg2\.(?:DatabaseError|ProgrammingError)",
    r"mysql\.connector\.errors",
    r"You\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax",
    r"syntax\s+error\s+at\s+or\s+near",
    r"unrecognized\s+token",
    r"unterminated\s+quoted\s+string",
    r"unclosed\s+quotation",
    r"ORA-\d{5}",
    r"no\s+such\s+column",
    r"no\s+such\s+table",
]


# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════


def classify_response(response_text: str, raw_result: Any = None) -> Verdict:
    """
    Classify an MCP response as SAFE, CONFIRMED, LIKELY, POSSIBLE, or NONE.

    This should be called BEFORE creating a Finding. If SAFE, skip the finding.

    Args:
        response_text: The extracted text content from the MCP response.
        raw_result: The raw MCP CallToolResult object (for structured parsing).
    """
    # Step 1: Check for JSON-RPC error codes (structured response)
    if _is_jsonrpc_safe(response_text, raw_result):
        return Verdict.SAFE

    # Step 2: Check for schema/validation rejections
    if _matches_any(response_text, SCHEMA_REJECTION_PATTERNS):
        return Verdict.SAFE

    # Step 3: Check for sandbox/access control blocks
    if _matches_any(response_text, SANDBOX_BLOCK_PATTERNS):
        return Verdict.SAFE

    return Verdict.NONE  # No classification — let scanner-specific logic decide


def classify_cmd_injection(response_text: str, raw_result: Any = None) -> tuple[Verdict, str]:
    """Classify response specifically for command injection detection."""
    base = classify_response(response_text, raw_result)
    if base == Verdict.SAFE:
        return Verdict.SAFE, "Server security controls blocked the payload"

    # Check for confirmed execution proofs
    for pattern in CMD_INJECTION_CONFIRMED:
        m = re.search(pattern, response_text, re.IGNORECASE)
        if m:
            return Verdict.CONFIRMED, f"Command execution proof: {m.group()}"

    # Check for likely indicators
    for pattern in CMD_INJECTION_LIKELY:
        m = re.search(pattern, response_text, re.IGNORECASE)
        if m:
            return Verdict.LIKELY, f"Shell error indicates command was attempted: {m.group()}"

    return Verdict.NONE, ""


def classify_path_traversal(response_text: str, raw_result: Any = None) -> tuple[Verdict, str]:
    """Classify response specifically for path traversal detection."""
    base = classify_response(response_text, raw_result)
    if base == Verdict.SAFE:
        return Verdict.SAFE, "Server security controls blocked the payload"

    # Check for confirmed file content
    for pattern in PATH_TRAVERSAL_CONFIRMED:
        m = re.search(pattern, response_text, re.IGNORECASE)
        if m:
            return Verdict.CONFIRMED, f"Sensitive file content detected: {m.group()}"

    # Check for likely indicators (file errors that reveal path existence)
    for pattern in PATH_TRAVERSAL_LIKELY:
        m = re.search(pattern, response_text, re.IGNORECASE)
        if m:
            # Extra check: if ENOENT but path was normalized inside sandbox, it's SAFE
            if _is_normalized_safe(response_text):
                return Verdict.SAFE, "Path was normalized inside allowed directory"
            return Verdict.LIKELY, f"Path access error reveals filesystem state: {m.group()}"

    return Verdict.NONE, ""


def classify_sqli(response_text: str, raw_result: Any = None) -> tuple[Verdict, str]:
    """Classify response specifically for SQL injection detection."""
    base = classify_response(response_text, raw_result)
    if base == Verdict.SAFE:
        return Verdict.SAFE, "Server security controls blocked the payload"

    for pattern in SQLI_CONFIRMED:
        m = re.search(pattern, response_text, re.IGNORECASE)
        if m:
            return Verdict.CONFIRMED, f"SQL error indicates injection: {m.group()}"

    return Verdict.NONE, ""


def is_tool_relevant(tool_name: str, tool_description: str, scanner_type: str) -> bool:
    """
    Check if a scanner is relevant for a given tool based on semantics.

    scanner_type: 'command-injection', 'path-traversal', 'sql-rce', 'ssrf'
    """
    name_lower = tool_name.lower()
    desc_lower = tool_description.lower()
    combined = f"{name_lower} {desc_lower}"

    if scanner_type == "command-injection":
        keywords = [
            r"\bexec\b",
            r"\bexecute(?:d|s)?\b",
            r"\brun(?:ning|s)?\b",
            r"\bcommand(?:s)?\b",
            r"\bshell\b",
            r"\bbash\b",
            r"\bsh\b",
            r"\bcmd\b",
            r"\bpowershell\b",
            r"\bterminal\b",
            r"\bsystem\b",
            r"\bprocess\b",
            r"\bspawn\b",
            r"\bscript(?:s)?\b",
            r"\beval\b",
            r"\bos\b",
            r"\bping\b",
            r"\bnetwork\b",
            r"\bhost\b",
            r"\bservice\b",
            r"\bstatus\b",
        ]
        has_kw = any(re.search(kw, combined) for kw in keywords)

        # Cross-scanner exclusion: if it looks like a DB tool but has NO shell keywords
        db_keywords = [
            r"\bsql\b",
            r"\bquery\b",
            r"\bdatabase\b",
            r"\bsqlite\b",
            r"\bmysql\b",
            r"\bpostgres\b",
        ]
        strict_shell = [
            r"\bshell\b",
            r"\bbash\b",
            r"\bcmd\b",
            r"\bos\b",
            r"\bsystem\b",
            r"\bpowershell\b",
            r"\bcommand\b",
        ]
        looks_like_db = any(re.search(kw, combined) for kw in db_keywords)
        has_strict_shell = any(re.search(kw, combined) for kw in strict_shell)

        if looks_like_db and not has_strict_shell:
            return False

        return has_kw

    elif scanner_type == "path-traversal":
        keywords = [
            r"\bfile(?:s)?\b",
            r"\bpath(?:s)?\b",
            r"\bdirectory\b",
            r"\bdir(?:s)?\b",
            r"\bfolder(?:s)?\b",
            r"\bfs\b",
            r"\bfilesystem\b",
            r"\bdownload\b",
            r"\bupload\b",
            r"\bresource\b",
            r"\buri\b",
            r"\burl\b",
            r"\bdocument\b",
            r"\btemplate\b",
        ]
        return any(re.search(kw, combined) for kw in keywords)

    elif scanner_type == "sql-rce":
        keywords = [
            r"\bsql\b",
            r"\bquery\b",
            r"\bdatabase\b",
            r"\bdb\b",
            r"\bsqlite\b",
            r"\bmysql\b",
            r"\bpostgres\b",
            r"\btable\b",
            r"\bselect\b",
            r"\binsert\b",
            r"\bupdate\b",
            r"\bdelete\b",
            r"\bfetch.*\bdata\b",
        ]
        return any(re.search(kw, combined) for kw in keywords)

    elif scanner_type == "ssrf":
        keywords = [
            r"\burl\b",
            r"\bfetch\b",
            r"\brequest\b",
            r"\bhttp(?:s)?\b",
            r"\bapi\b",
            r"\bendpoint\b",
            r"\bwebhook\b",
            r"\bproxy\b",
            r"\bredirect\b",
            r"\blink\b",
            r"\bdownload\b",
            r"\bconnect\b",
            r"\bremote\b",
        ]
        return any(re.search(kw, combined) for kw in keywords)

    # Unknown scanner type — don't skip
    return True


def measure_baseline_latency(elapsed_times: list[float]) -> float:
    """
    Calculate baseline latency from a list of response times.
    Used for time-based injection detection.
    Returns the 95th percentile response time.
    """
    if not elapsed_times:
        return 1.0  # Default 1s baseline

    sorted_times = sorted(elapsed_times)
    idx = int(len(sorted_times) * 0.95)
    return sorted_times[min(idx, len(sorted_times) - 1)]


# ═══════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════


def _is_jsonrpc_safe(response_text: str, raw_result: Any) -> bool:
    """Check if the response is a JSON-RPC error that indicates SAFE (input blocked)."""

    # Try structured parsing from raw result
    if raw_result is not None:
        # Check if isError flag is set on the MCP result
        is_error = getattr(raw_result, "isError", False)
        if is_error:
            # Try to parse the content for JSON-RPC error codes
            content = getattr(raw_result, "content", [])
            for block in content:
                text = getattr(block, "text", "")
                if text:
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, dict):
                            error_code = parsed.get("error", {}).get("code")
                            if error_code in SAFE_JSONRPC_CODES:
                                return True
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass

    # Fallback: try to parse the response text itself
    try:
        parsed = json.loads(response_text)
        if isinstance(parsed, dict):
            error_code = parsed.get("error", {}).get("code")
            if error_code in SAFE_JSONRPC_CODES:
                return True
    except (json.JSONDecodeError, TypeError):
        pass

    # Check for JSON-RPC error code patterns in text (structured, not string grep)
    # Only match when it appears to be a structured error response
    try:
        # Look for embedded JSON with error codes
        for match in re.finditer(r'\{[^{}]*"error"[^{}]*\}', response_text):
            try:
                obj = json.loads(match.group())
                code = (
                    obj.get("error", {}).get("code")
                    if isinstance(obj.get("error"), dict)
                    else obj.get("code")
                )
                if code in SAFE_JSONRPC_CODES:
                    return True
            except (json.JSONDecodeError, TypeError):
                continue
    except Exception:
        pass

    return False


def _matches_any(text: str, patterns: list[str]) -> bool:
    """Check if text matches any of the given regex patterns (case-insensitive)."""
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _is_normalized_safe(response_text: str) -> bool:
    """
    Check if a path traversal attempt was normalized by the server.
    e.g., ../../../etc/passwd resolved to /allowed/root/etc/passwd → SAFE
    """
    lower = response_text.lower()

    # If the response shows the path was resolved inside a safe directory
    # and the file simply doesn't exist there, it's SAFE
    safe_indicators = [
        # Path was normalized and file wasn't found inside allowed dir
        re.search(r"enoent.*(?:/tmp/|/home/|/var/|c:\\temp|c:\\users)", lower),
        # Server explicitly says path was normalized
        re.search(r"(?:resolved|normalized)\s+(?:to|as|path)", lower),
        # Path stayed inside allowed directory
        re.search(r"not\s+(?:found|exist)\s+(?:in|within|under)", lower),
    ]

    return any(safe_indicators)


"""Response classifier module for mcpsec dynamic scanners."""
