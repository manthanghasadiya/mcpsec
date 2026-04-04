"""
AI-powered finding classification.
Adds confidence tags to findings without removing any.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from mcpsec.models import Finding, Severity
from mcpsec.ai.llm_client import LLMClient

logger = logging.getLogger(__name__)


class FindingTag(Enum):
    """Classification tags for findings."""
    CONFIRMED_VULN = "🔴 VULNERABILITY"      # Definitely a security issue
    SUSPICIOUS = "🟠 SUSPICIOUS"              # Likely a vulnerability, needs review
    NEEDS_REVIEW = "🟡 NEEDS REVIEW"          # Could go either way
    LIKELY_BY_DESIGN = "🔵 LIKELY BY DESIGN"  # Probably intended behavior
    BY_DESIGN = "⚪ BY DESIGN"                 # Definitely intended for this server type


@dataclass
class ServerProfile:
    """AI-generated profile of an MCP server's security characteristics."""
    server_type: str                    # e.g., "filesystem server", "fetch proxy", "shell executor"
    description: str                    # Brief description of purpose
    expected_patterns: List[str]        # Vulnerability patterns that are by-design
    suspicious_patterns: List[str]      # Patterns that would be real vulnerabilities
    notes: str                          # Any additional context


def _read_file_safe(path: Path, max_chars: int = 50000) -> str:
    """Read file contents safely, with size limit."""
    if not path.exists():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        if len(content) > max_chars:
            # Keep beginning and end for context
            half = max_chars // 2
            content = content[:half] + "\n\n[... truncated ...]\n\n" + content[-half:]
        return content
    except Exception as e:
        logger.debug(f"Failed to read {path}: {e}")
        return ""


def _find_readme(source_path: Path) -> str:
    """Find and read the README file."""
    readme_names = [
        "README.md", "readme.md", "README.MD",
        "README.rst", "readme.rst",
        "README.txt", "readme.txt",
        "README", "readme"
    ]
    for name in readme_names:
        readme_path = source_path / name
        if readme_path.exists():
            return _read_file_safe(readme_path)
    return ""


def _find_package_info(source_path: Path) -> str:
    """Find and read package metadata (package.json, pyproject.toml, etc.)."""
    # Try package.json
    pkg_json = source_path / "package.json"
    if pkg_json.exists():
        return _read_file_safe(pkg_json, max_chars=5000)
    
    # Try pyproject.toml
    pyproject = source_path / "pyproject.toml"
    if pyproject.exists():
        return _read_file_safe(pyproject, max_chars=5000)
    
    # Try setup.py
    setup_py = source_path / "setup.py"
    if setup_py.exists():
        return _read_file_safe(setup_py, max_chars=3000)
    
    return ""


def _format_findings_for_ai(findings: List[Finding]) -> str:
    """Format findings into a compact representation for AI analysis."""
    lines = []
    for i, f in enumerate(findings, 1):
        # Extract just filename from full path
        filename = Path(f.file_path).name if f.file_path else "unknown"
        parent = Path(f.file_path).parent.name if f.file_path else ""
        short_path = f"{parent}/{filename}" if parent else filename
        
        lines.append(
            f"{i}. [{f.severity.name}] {f.title}\n"
            f"   File: {short_path}:{f.line_number}\n"
            f"   Code: {(f.code_snippet or '')[:150]}"
        )
    return "\n\n".join(lines)


async def classify_server_and_findings(
    source_path: Path,
    findings: List[Finding],
    llm_client: LLMClient,
) -> Tuple[ServerProfile, List[Finding]]:
    """
    Use AI to classify the server type and tag all findings.
    
    Returns:
        Tuple of (ServerProfile, tagged_findings)
        
    Note: This NEVER removes findings. It only adds classification tags.
    """
    
    if not findings:
        return ServerProfile(
            server_type="unknown",
            description="No findings to analyze",
            expected_patterns=[],
            suspicious_patterns=[],
            notes=""
        ), findings
    
    # Gather context
    readme = _find_readme(source_path)
    package_info = _find_package_info(source_path)
    findings_text = _format_findings_for_ai(findings)
    
    # Build the prompt
    prompt = f"""You are a security researcher analyzing an MCP (Model Context Protocol) server.

## Server Documentation

### README
{readme if readme else "[No README found]"}

### Package Info
{package_info if package_info else "[No package.json/pyproject.toml found]"}

## Security Findings

A static analysis tool found these potential vulnerabilities:

{findings_text}

## Your Task

Analyze the server's PURPOSE and classify each finding.

**IMPORTANT RULES:**
1. MCP servers often INTENTIONALLY expose dangerous functionality - that's their purpose
2. A "filesystem" server is SUPPOSED to read/write files - that's not a vulnerability
3. A "fetch" server is SUPPOSED to make HTTP requests to user URLs - SSRF is by-design
4. A "shell" or "terminal" server is SUPPOSED to execute commands - that's the feature
5. A "database" server is SUPPOSED to run SQL queries - that's expected
6. BUT: A filesystem server should NOT have command injection - that's a real bug
7. BUT: A fetch server should NOT have path traversal - that's a real bug

**CLASSIFICATION LEVELS:**
- `CONFIRMED_VULN`: This is definitely a security vulnerability, not intended behavior
- `SUSPICIOUS`: This looks like a vulnerability but needs human review
- `NEEDS_REVIEW`: Ambiguous - could be by-design or a bug depending on context
- `LIKELY_BY_DESIGN`: Probably intended behavior for this server type
- `BY_DESIGN`: Definitely intended - this is core functionality of the server

Respond with valid JSON only (no markdown, no explanation outside JSON):

{{
    "server_profile": {{
        "server_type": "brief type like 'filesystem server' or 'HTTP fetch proxy'",
        "description": "one sentence describing what this server does",
        "expected_patterns": ["list", "of", "vulnerability", "types", "that", "are", "by-design"],
        "suspicious_patterns": ["list", "of", "patterns", "that", "would", "be", "real", "bugs"],
        "notes": "any important context about this specific server"
    }},
    "finding_classifications": [
        {{
            "index": 1,
            "classification": "BY_DESIGN",
            "reason": "brief explanation"
        }},
        {{
            "index": 2,
            "classification": "SUSPICIOUS",
            "reason": "brief explanation"
        }}
    ]
}}

Classify ALL {len(findings)} findings. Do not skip any."""

    try:
        response = await llm_client.complete(
            prompt=prompt,
            system="You are a security expert. Respond only with valid JSON. Be precise and consistent.",
            temperature=0.1,  # Low temperature for consistent classification
        )
        
        # Parse response
        result = _parse_ai_response(response)
        
        if result is None:
            logger.warning("Failed to parse AI response, returning findings untagged")
            return _create_default_profile(source_path), findings
        
        # Build ServerProfile
        profile_data = result.get("server_profile", {})
        server_profile = ServerProfile(
            server_type=profile_data.get("server_type", "unknown"),
            description=profile_data.get("description", ""),
            expected_patterns=profile_data.get("expected_patterns", []),
            suspicious_patterns=profile_data.get("suspicious_patterns", []),
            notes=profile_data.get("notes", "")
        )
        
        # Apply classifications to findings
        classifications = result.get("finding_classifications", [])
        tagged_findings = _apply_classifications(findings, classifications)
        
        return server_profile, tagged_findings
        
    except Exception as e:
        logger.error(f"AI classification failed: {e}")
        return _create_default_profile(source_path), findings


def _parse_ai_response(response: str) -> Optional[dict]:
    """Parse AI response, handling various formats."""
    if not response:
        return None
    
    # Clean up response
    text = response.strip()
    
    # Remove markdown code blocks if present
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (```json and ```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)
    
    # Try to find JSON object
    try:
        # Direct parse
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    # Try to extract JSON from text
    import re
    json_match = re.search(r'\{[\s\S]*\}', text)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    
    return None


def _create_default_profile(source_path: Path) -> ServerProfile:
    """Create a default profile when AI fails."""
    return ServerProfile(
        server_type="unknown",
        description=f"MCP server at {source_path.name}",
        expected_patterns=[],
        suspicious_patterns=[],
        notes="AI classification unavailable"
    )


def _apply_classifications(
    findings: List[Finding],
    classifications: List[dict]
) -> List[Finding]:
    """Apply AI classifications to findings as tags."""
    
    # Build lookup by index
    class_lookup = {}
    for c in classifications:
        idx = c.get("index")
        if idx is not None:
            class_lookup[idx] = c
    
    # Tag mapping
    tag_map = {
        "CONFIRMED_VULN": FindingTag.CONFIRMED_VULN,
        "SUSPICIOUS": FindingTag.SUSPICIOUS,
        "NEEDS_REVIEW": FindingTag.NEEDS_REVIEW,
        "LIKELY_BY_DESIGN": FindingTag.LIKELY_BY_DESIGN,
        "BY_DESIGN": FindingTag.BY_DESIGN,
    }
    
    # Severity adjustments based on classification
    severity_map = {
        FindingTag.CONFIRMED_VULN: None,        # Keep original severity
        FindingTag.SUSPICIOUS: None,             # Keep original severity
        FindingTag.NEEDS_REVIEW: None,           # Keep original severity
        FindingTag.LIKELY_BY_DESIGN: Severity.LOW,
        FindingTag.BY_DESIGN: Severity.INFO,
    }
    
    for i, finding in enumerate(findings, 1):
        classification = class_lookup.get(i, {})
        class_name = classification.get("classification", "NEEDS_REVIEW")
        reason = classification.get("reason", "")
        
        tag = tag_map.get(class_name, FindingTag.NEEDS_REVIEW)
        
        # Add tag to finding title
        finding.title = f"{tag.value} {finding.title}"
        
        # Add AI reasoning to description
        if reason:
            finding.description = f"{finding.description}\n\n🤖 AI Analysis: {reason}"
        
        # Adjust severity if appropriate
        new_severity = severity_map.get(tag)
        if new_severity is not None:
            finding.severity = new_severity
    
    return findings


# ============================================================
# Synchronous wrapper for non-async contexts
# ============================================================

def classify_findings_sync(
    source_path: Path,
    findings: List[Finding],
    llm_client: LLMClient,
) -> Tuple[ServerProfile, List[Finding]]:
    """Synchronous wrapper for classify_server_and_findings."""
    import asyncio
    
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    return loop.run_until_complete(
        classify_server_and_findings(source_path, findings, llm_client)
    )
