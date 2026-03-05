"""
Insecure Direct Object Reference (IDOR) Scanner.

Detects if a tool allows unauthenticated retrieval of records by ID.
Since MCP servers usually operate in a local/agent context without a
traditional session cookie, any accessible ID retrieval is a potential risk
if the backing data is multi-tenant or contains sensitive records.
"""

from __future__ import annotations

import re
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner
from mcpsec.scanners.response_classifier import Verdict, classify_response

ID_PARAM_KEYWORDS = [
    "id",
    "user_id",
    "userid",
    "account_id",
    "accountid",
    "org_id",
    "orgid",
    "tenant_id",
    "customer_id",
    "profile_id",
    "uuid",
]


def _extract_response(result: Any) -> str:
    text = ""
    if hasattr(result, "content"):
        for block in result.content:
            text += getattr(block, "text", "")
    return text


class IDORScanner(BaseScanner):
    name = "idor"
    description = "Detect accessible records via Direct Object Reference (IDOR)"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            id_params = []

            # Find integer or string ID parameters
            properties = tool.parameters
            for param_name, param_def in properties.items():
                if any(
                    kw == param_name.lower() or param_name.lower().endswith(f"_{kw}")
                    for kw in ID_PARAM_KEYWORDS
                ):
                    param_type = (
                        param_def if isinstance(param_def, str) else param_def.get("type", "string")
                    )
                    id_params.append((param_name, param_type))

            for param_name, param_type in id_params:
                # Test diverse IDs to see if we get success responses
                test_ids = (
                    [1, 2, 3, 1000]
                    if param_type == "integer"
                    else ["1", "2", "3", "admin", "test", "00000000-0000-0000-0000-000000000000"]
                )

                successful_responses = set()

                for test_id in test_ids:
                    try:
                        result = await client.call_tool(tool.name, {param_name: test_id})
                        response_text = _extract_response(result)
                        is_error = getattr(result, "isError", False)

                        if is_error or classify_response(response_text) == Verdict.SAFE:
                            continue

                        # If response is substantially long and doesn't explicitly look like "not found"
                        if len(response_text) > 10 and not re.search(
                            r"(not found|doesn't exist|no such|invalid id)",
                            response_text,
                            re.IGNORECASE,
                        ):
                            successful_responses.add(response_text)
                    except Exception:
                        pass

                # If we retrieved multiple distinct records, it's a confirmed IDOR/Data Retrieval point
                if len(successful_responses) >= 2:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            scanner=self.name,
                            tool_name=tool.name,
                            parameter=param_name,
                            title=f"Unauthenticated Direct Object Reference (IDOR) [{len(successful_responses)} records]",
                            description=(
                                f"Tool '{tool.name}' allows retrieval of arbitrary records by changing the '{param_name}'. "
                                f"Since no authentication context is bound to the request, an AI agent could be tricked "
                                f"into accessing another user's data if this connects to a multi-tenant backend."
                            ),
                            detail=f"Successfully extracted different records using IDs: {test_ids}",
                            remediation=(
                                "If this server connects to a multi-tenant backend, ensure that the allowed scope "
                                "is strictly tied to the authorized user's credentials rather than blindly trusting the ID parameter."
                            ),
                            cwe="CWE-639",  # Authorization Bypass Through User-Controlled Key
                        )
                    )

        return findings
