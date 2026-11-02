"""Tests for the template injection scanner oracle and reflection guards."""

import re
from unittest.mock import AsyncMock
import pytest

from mcpsec.models import Finding, ServerProfile, Severity, ToolInfo
from mcpsec.scanners.template_injection import TemplateInjectionScanner


def _create_profile(
    tool_name: str,
    param_name: str,
    description: str = "A tool for rendering templates",
) -> ServerProfile:
    tool = ToolInfo(
        name=tool_name,
        description=description,
        parameters={param_name: {"type": "string"}},
        raw_schema={
            "inputSchema": {
                "properties": {param_name: {"type": "string"}},
                "required": [param_name],
            }
        },
    )
    return ServerProfile(server_name="test_server", tools=[tool])


def _create_mock_client(side_effect_fn):
    client = AsyncMock()

    class MockContent:
        def __init__(self, text: str):
            self.type = "text"
            self.text = text

    class MockResult:
        def __init__(self, text: str):
            self.content = [MockContent(text)]

    async def call_tool(tool_name: str, args: dict):
        text = side_effect_fn(tool_name, args)
        return MockResult(text)

    client.call_tool = AsyncMock(side_effect=call_tool)
    return client


@pytest.mark.asyncio
async def test_echoing_tool_not_confirmed_template_inj():
    """Reflection regression: a tool echoing template input verbatim yields NO findings."""
    profile = _create_profile(
        "format_text", "template", description="Format text using template style"
    )

    def echo_handler(tool_name: str, args: dict) -> str:
        tmpl = args.get("template", "")
        return f"Echo template: {tmpl}"

    client = _create_mock_client(echo_handler)
    scanner = TemplateInjectionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 0, f"Expected 0 findings for echoing tool, got {findings}"


@pytest.mark.asyncio
async def test_true_positive_template_inj_confirmed():
    """A tool actually evaluating Jinja/EL/ERB template expressions yields confirmed finding."""
    profile = _create_profile(
        "render_report", "content", description="Render content template report"
    )

    def render_handler(tool_name: str, args: dict) -> str:
        c = args.get("content", "")
        # Simulates a template engine evaluating {{ a * b }} or ${ a * b }
        m = re.search(r"(\d+)\s*\*\s*(\d+)", c)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            return f"Rendered output: {a * b}"
        return "Rendered empty"

    client = _create_mock_client(render_handler)
    scanner = TemplateInjectionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == "confirmed"
    assert "evaluated to" in f.evidence


@pytest.mark.asyncio
async def test_corpus_collision_guard_49_not_confirmed_template_inj():
    """A tool whose response corpus contains '49' without evaluating anything yields NO findings."""
    profile = _create_profile(
        "generate_summary",
        "text",
        description="Generate summary from text format",
    )

    def corpus_49_handler(tool_name: str, args: dict) -> str:
        return "Summary: 49 items rendered successfully."

    client = _create_mock_client(corpus_49_handler)
    scanner = TemplateInjectionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_object_leak_reflection_guard_template_inj():
    """If echoed text contains <class ' or accessKeyId from sent payload, reflection guard skips it."""
    profile = _create_profile(
        "format_report", "text", description="Format report template content"
    )

    def echo_handler(tool_name: str, args: dict) -> str:
        t = args.get("text", "")
        return f"Processed: {t}"

    client = _create_mock_client(echo_handler)
    scanner = TemplateInjectionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 0


@pytest.mark.asyncio
async def test_object_leak_true_positive_template_inj():
    """A template engine leaking internal class information is confirmed."""
    profile = _create_profile(
        "render_page", "template", description="Render template page"
    )

    def leak_handler(tool_name: str, args: dict) -> str:
        t = args.get("template", "")
        if "class" in t or "subclasses" in t:
            return "<class 'jinja2.runtime.Context'>"
        return "Rendered page"

    client = _create_mock_client(leak_handler)
    scanner = TemplateInjectionScanner()
    findings = await scanner.scan(profile, client)

    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert "leaked internal class information" in findings[0].evidence
