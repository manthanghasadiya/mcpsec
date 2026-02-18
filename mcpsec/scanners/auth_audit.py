"""
Authentication & Authorization Audit Scanner.

Checks whether the MCP server implements any authentication and
evaluates tool permissions (over-privileged tools, missing annotations, etc.).
"""

from __future__ import annotations

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner


# Tools that are inherently dangerous without auth
DANGEROUS_TOOL_PATTERNS = [
    "exec", "execute", "run", "shell", "command", "cmd", "system",
    "eval", "script",
    "write", "delete", "remove", "create", "modify", "update", "put", "patch",
    "upload", "deploy", "install",
    "sql", "query", "database", "db",
    "sudo", "admin", "root", "privilege",
    "send", "email", "message", "notify",
    "transfer", "pay", "transaction",
]

# File system tools that need careful scoping
FS_TOOL_PATTERNS = [
    "read_file", "write_file", "list_dir", "list_files",
    "get_file", "put_file", "delete_file", "move_file",
    "open", "save", "create_file", "mkdir",
]


class AuthAuditScanner(BaseScanner):
    """Audit authentication, authorization, and tool permissions."""

    name = "auth-audit"
    description = "Check authentication mechanisms and tool permission levels"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []

        # ── Check: Did the server even require auth? ─────────────────────
        # If we're here, we connected successfully. If there was no auth
        # challenge, that's a finding.
        findings.extend(self._check_no_auth(profile))

        # ── Check each tool for permission issues ────────────────────────
        for tool in profile.tools:
            findings.extend(self._check_tool_permissions(tool))
            findings.extend(self._check_missing_annotations(tool))

        # ── Check for dangerous tool combinations ────────────────────────
        findings.extend(self._check_dangerous_combos(profile))

        return findings

    def _check_no_auth(self, profile: ServerProfile) -> list[Finding]:
        """Flag if we connected without any authentication."""
        findings = []

        has_dangerous = any(
            any(pattern in tool.name.lower() for pattern in DANGEROUS_TOOL_PATTERNS)
            for tool in profile.tools
        )

        if has_dangerous:
            severity = Severity.HIGH
            title = "No authentication required for dangerous tools"
            desc = (
                "The MCP server accepted our connection without any authentication "
                "and exposes tools that can modify data, execute commands, or access "
                "sensitive resources. Any MCP client can connect and invoke these tools."
            )
        else:
            severity = Severity.MEDIUM
            title = "No authentication required"
            desc = (
                "The MCP server accepted our connection without any authentication. "
                "While the exposed tools appear read-only, any MCP client can connect "
                "and access the server's resources."
            )

        findings.append(Finding(
            severity=severity,
            scanner=self.name,
            tool_name="*",
            title=title,
            description=desc,
            remediation=(
                "Implement OAuth 2.1 authentication as recommended by the MCP spec. "
                "For local stdio servers, ensure the server is only accessible by "
                "authorized processes. For HTTP servers, require token-based auth."
            ),
            cwe="CWE-306",  # Missing Authentication for Critical Function
        ))

        return findings

    def _check_tool_permissions(self, tool: ToolInfo) -> list[Finding]:
        """Check individual tool for over-permissioning."""
        findings = []
        name_lower = tool.name.lower()
        desc_lower = tool.description.lower()

        # Check for shell/command execution tools
        if any(p in name_lower for p in ["exec", "execute", "shell", "command", "cmd", "system", "eval", "run_code"]):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                scanner=self.name,
                tool_name=tool.name,
                title="Tool allows arbitrary code/command execution",
                description=(
                    f"Tool '{tool.name}' appears to allow arbitrary command or code execution. "
                    f"This is the highest-risk tool class — an AI agent could be manipulated "
                    f"into running malicious commands."
                ),
                detail=f"Description: {tool.description[:200]}",
                remediation=(
                    "Restrict command execution to a predefined allowlist. "
                    "Use sandboxing (Docker containers, seccomp). "
                    "Never pass unsanitized AI-generated input to shell commands."
                ),
                cwe="CWE-78",  # Improper Neutralization of Special Elements used in an OS Command
            ))

        # Check for broad file system access
        if any(p in name_lower for p in FS_TOOL_PATTERNS):
            # Check if there's any path restriction mentioned
            has_restriction = any(
                word in desc_lower
                for word in ["restricted", "sandbox", "allowed", "within", "only", "scoped"]
            )
            if not has_restriction:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    scanner=self.name,
                    tool_name=tool.name,
                    title="File system tool without documented restrictions",
                    description=(
                        f"Tool '{tool.name}' provides file system access without "
                        f"mentioning any path restrictions or sandboxing in its description."
                    ),
                    detail=f"Description: {tool.description[:200]}",
                    remediation=(
                        "Restrict file operations to a specific directory. "
                        "Validate all paths against an allowlist. "
                        "Document the allowed scope in the tool description."
                    ),
                    cwe="CWE-22",  # Improper Limitation of a Pathname to a Restricted Directory
                ))

        # Check for SQL/database tools without parameterization hints
        if any(p in name_lower for p in ["sql", "query", "database"]):
            has_safe_hint = any(
                word in desc_lower
                for word in ["parameterized", "prepared", "sanitized", "escaped", "safe"]
            )
            if not has_safe_hint:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    scanner=self.name,
                    tool_name=tool.name,
                    title="Database tool without safety indicators",
                    description=(
                        f"Tool '{tool.name}' provides database access without mentioning "
                        f"parameterized queries or input sanitization."
                    ),
                    detail=f"Description: {tool.description[:200]}",
                    remediation=(
                        "Use parameterized queries exclusively. "
                        "Never construct SQL from AI-generated string concatenation. "
                        "Document the safety measures in the tool description."
                    ),
                    cwe="CWE-89",  # SQL Injection
                ))

        return findings

    def _check_missing_annotations(self, tool: ToolInfo) -> list[Finding]:
        """Check if tool is missing recommended annotations."""
        findings = []

        if not tool.annotations:
            findings.append(Finding(
                severity=Severity.LOW,
                scanner=self.name,
                tool_name=tool.name,
                title="Tool missing annotations",
                description=(
                    f"Tool '{tool.name}' does not provide MCP annotations "
                    f"(readOnlyHint, destructiveHint, etc.). Annotations help MCP clients "
                    f"make informed decisions about tool usage and user consent."
                ),
                remediation=(
                    "Add annotations: readOnlyHint, destructiveHint, "
                    "idempotentHint, openWorldHint."
                ),
                cwe="CWE-1059",  # Insufficient Technical Documentation
            ))

        # Check for destructive tools marked as read-only
        if tool.annotations:
            is_readonly = tool.annotations.get("readOnlyHint", False)
            name_lower = tool.name.lower()
            looks_destructive = any(
                p in name_lower
                for p in ["write", "delete", "remove", "create", "update", "modify", "exec", "send"]
            )
            if is_readonly and looks_destructive:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    scanner=self.name,
                    tool_name=tool.name,
                    title="Destructive tool incorrectly annotated as read-only",
                    description=(
                        f"Tool '{tool.name}' appears to perform write/destructive operations "
                        f"but is annotated with readOnlyHint=true. This could cause MCP clients "
                        f"to skip user consent prompts for dangerous actions."
                    ),
                    remediation="Set readOnlyHint=false and destructiveHint=true for this tool.",
                    cwe="CWE-285",  # Improper Authorization
                ))

        return findings

    def _check_dangerous_combos(self, profile: ServerProfile) -> list[Finding]:
        """Check for dangerous combinations of tools."""
        findings = []
        tool_names = [t.name.lower() for t in profile.tools]

        # read + send/post = potential exfiltration chain
        has_read = any(
            any(p in name for p in ["read", "get", "list", "fetch", "search", "query"])
            for name in tool_names
        )
        has_send = any(
            any(p in name for p in ["send", "post", "write", "upload", "email", "message", "notify"])
            for name in tool_names
        )

        if has_read and has_send:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                scanner=self.name,
                tool_name="*",
                title="Data read + data send tool combination",
                description=(
                    "The server exposes both data-reading and data-sending tools. "
                    "An AI agent could be manipulated (via prompt injection) into "
                    "reading sensitive data with one tool and exfiltrating it with another."
                ),
                remediation=(
                    "Implement data flow controls between tools. "
                    "Require user confirmation for cross-tool data transfers. "
                    "Consider separating read and write capabilities into different servers."
                ),
                cwe="CWE-200",  # Exposure of Sensitive Information
            ))

        return findings
