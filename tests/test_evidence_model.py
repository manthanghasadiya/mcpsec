"""Tests for the evidence model: confirmed requires effect/structural proof, signatures are suspected."""

from unittest.mock import AsyncMock
import pytest

from mcpsec.models import Finding, HEURISTIC_NOTE, ServerProfile, Severity, ToolInfo, create_finding
from mcpsec.scanners.code_execution import CodeExecutionScanner
from mcpsec.scanners.deserialization import DeserializationScanner
from mcpsec.scanners.path_traversal import PathTraversalScanner
from mcpsec.scanners.sql_rce import SQLiResult, SQLInjectionRCEScanner
from mcpsec.scanners.ssrf import SSRFScanner
from mcpsec.scanners.template_injection import TemplateInjectionScanner
from tests.servers.vulnerable_noname_server import TOOLS, handle_call_tool


def test_evidence_model_create_finding_helper():
    """Central helper and model validator enforce evidence model rules."""
    # 1. Confirmed retains CRITICAL and gets [CONFIRMED]
    f_conf = create_finding(
        severity=Severity.CRITICAL,
        scanner="command-injection",
        tool_name="cmd_tool",
        parameter="cmd",
        title="Command Injection in 'cmd'",
        evidence="Canary evaluated to 42",
        confidence="confirmed",
    )
    assert f_conf.severity == Severity.CRITICAL
    assert f_conf.confidence == "confirmed"
    assert f_conf.title == "Command Injection in 'cmd' [CONFIRMED]"
    assert "Canary evaluated to 42" in f_conf.evidence
    assert HEURISTIC_NOTE not in f_conf.evidence

    # 2. Suspected is capped at HIGH (never CRITICAL), gets [SUSPECTED], and carries heuristic note
    f_susp = create_finding(
        severity=Severity.CRITICAL,
        scanner="code-execution",
        tool_name="eval_tool",
        parameter="code",
        title="Code Execution in 'code'",
        evidence="Matched loose indicator __main__",
        confidence="suspected",
    )
    assert f_susp.severity == Severity.HIGH
    assert f_susp.confidence == "suspected"
    assert f_susp.title == "Code Execution in 'code' [SUSPECTED]"
    assert "Matched loose indicator __main__" in f_susp.evidence
    assert HEURISTIC_NOTE in f_susp.evidence


def test_no_critical_from_unconfirmed_finding_invariant():
    """Global invariant: No finding with confidence != 'confirmed' may ever have severity CRITICAL."""
    # When instantiated with CRITICAL and non-confirmed confidence, validator must cap to HIGH
    for non_confirmed_conf in ["suspected", "heuristic", "low", "high", "", "possible"]:
        f = Finding(
            severity=Severity.CRITICAL,
            scanner="test",
            title="Test Finding",
            confidence=non_confirmed_conf,
        )
        assert f.confidence == "suspected"
        assert f.severity != Severity.CRITICAL
        assert f.severity == Severity.HIGH

    # Confirmed retains CRITICAL
    f_ok = Finding(
        severity=Severity.CRITICAL,
        scanner="test",
        title="Test Confirmed",
        confidence="confirmed",
    )
    assert f_ok.confidence == "confirmed"
    assert f_ok.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_recall_guard_signatures_relabeled_never_dropped():
    """Recall guard: scanners with signature-only matches still surface findings as [SUSPECTED] <= HIGH."""
    class MockResult:
        def __init__(self, text: str):
            class Block:
                def __init__(self, t: str):
                    self.text = t
            self.content = [Block(text)]
            self.isError = False

    # 1. Code execution loose indicator (__main__ without uid=\d+)
    mock_client_code = AsyncMock()
    mock_client_code.call_tool = AsyncMock(return_value=MockResult("<module '__main__'>"))
    code_profile = ServerProfile(
        server_name="code_server",
        tools=[
            ToolInfo(
                name="run_code",
                parameters={"code": {"type": "string"}},
                raw_schema={"inputSchema": {"properties": {"code": {"type": "string"}}}},
            )
        ],
    )
    code_scanner = CodeExecutionScanner()
    code_findings = await code_scanner.scan(code_profile, mock_client_code)
    assert len(code_findings) >= 1
    for f in code_findings:
        assert f.confidence == "suspected"
        assert f.severity <= Severity.HIGH
        assert "[SUSPECTED]" in f.title
        assert HEURISTIC_NOTE in f.evidence

    # 2. Template injection loose indicator (__main__)
    mock_client_tmpl = AsyncMock()
    mock_client_tmpl.call_tool = AsyncMock(return_value=MockResult("module __main__ reference"))
    tmpl_profile = ServerProfile(
        server_name="tmpl_server",
        tools=[
            ToolInfo(
                name="render_template",
                parameters={"template": {"type": "string"}},
                raw_schema={"inputSchema": {"properties": {"template": {"type": "string"}}}},
            )
        ],
    )
    tmpl_scanner = TemplateInjectionScanner()
    tmpl_findings = await tmpl_scanner.scan(tmpl_profile, mock_client_tmpl)
    assert len(tmpl_findings) >= 1
    for f in tmpl_findings:
        assert f.confidence == "suspected"
        assert f.severity <= Severity.HIGH
        assert "[SUSPECTED]" in f.title
        assert HEURISTIC_NOTE in f.evidence

    # 3. Path traversal error-reveal (FileNotFoundError reveals filesystem state)
    mock_client_path = AsyncMock()
    mock_client_path.call_tool = AsyncMock(return_value=MockResult("FileNotFoundError: [Errno 2] No such file: '/etc/passwd'"))
    path_profile = ServerProfile(
        server_name="path_server",
        tools=[
            ToolInfo(
                name="read_file",
                parameters={"path": {"type": "string"}},
                raw_schema={"inputSchema": {"properties": {"path": {"type": "string"}}}},
            )
        ],
    )
    path_scanner = PathTraversalScanner()
    path_findings = await path_scanner.scan(path_profile, mock_client_path)
    assert len(path_findings) >= 1
    for f in path_findings:
        assert f.confidence == "suspected"
        assert f.severity <= Severity.HIGH
        assert "[SUSPECTED]" in f.title
        assert HEURISTIC_NOTE in f.evidence

    # 4. Insecure deserialization secondary signature
    mock_client_deser = AsyncMock()
    mock_client_deser.call_tool = AsyncMock(
        return_value=MockResult("ModuleNotFoundError: No module named 'this_module_does_not_exist_mcpsec'")
    )
    deser_profile = ServerProfile(
        server_name="deser_server",
        tools=[
            ToolInfo(
                name="load_data",
                parameters={"data": {"type": "string"}},
                raw_schema={"inputSchema": {"properties": {"data": {"type": "string"}}}},
            )
        ],
    )
    deser_scanner = DeserializationScanner()
    deser_findings = await deser_scanner.scan(deser_profile, mock_client_deser)
    assert len(deser_findings) >= 1
    for f in deser_findings:
        assert f.confidence == "suspected"
        assert f.severity <= Severity.HIGH
        assert "[SUSPECTED]" in f.title
        assert HEURISTIC_NOTE in f.evidence


@pytest.mark.asyncio
async def test_confirmed_stays_confirmed_non_keyword_fixture():
    """The non-keyword fixture still yields [CONFIRMED] CRITICAL cmdi on payload, [CONFIRMED] path on item, [CONFIRMED] sqli on input."""
    mock_client = AsyncMock()

    class MockResult:
        def __init__(self, text: str):
            class Block:
                def __init__(self, t: str):
                    self.text = t
            self.content = [Block(text)]
            self.isError = False

    async def mock_call_tool(name: str, arguments: dict):
        res = await handle_call_tool(name, arguments)
        return MockResult(res[0].text if res else "")

    mock_client.call_tool = mock_call_tool

    profile = ServerProfile(
        server_name="vulnerable-noname-server",
        tools=[
            ToolInfo(
                name=t.name,
                description=t.description or "",
                parameters=t.inputSchema.get("properties", {}),
                raw_schema={"inputSchema": t.inputSchema},
            )
            for t in TOOLS
        ],
    )

    # 1. Command injection on do_thing(payload)
    from mcpsec.scanners.command_injection import CommandInjectionScanner
    cmdi_scanner = CommandInjectionScanner()
    cmdi_findings = await cmdi_scanner.scan(profile, mock_client)
    cmdi_hits = [f for f in cmdi_findings if f.tool_name == "do_thing" and f.parameter == "payload"]
    assert len(cmdi_hits) == 1
    assert cmdi_hits[0].severity == Severity.CRITICAL
    assert cmdi_hits[0].confidence == "confirmed"
    assert "[CONFIRMED]" in cmdi_hits[0].title

    # 2. Path traversal on process(item)
    path_scanner = PathTraversalScanner()
    path_findings = await path_scanner.scan(profile, mock_client)
    path_hits = [f for f in path_findings if f.tool_name == "process" and f.parameter == "item"]
    assert len(path_hits) == 1
    assert path_hits[0].severity == Severity.CRITICAL
    assert path_hits[0].confidence == "confirmed"
    assert "[CONFIRMED]" in path_hits[0].title

    # 3. SQL injection on handle(input)
    sql_scanner = SQLInjectionRCEScanner()
    sql_findings = await sql_scanner.scan(profile, mock_client)
    sqli_hits = [f for f in sql_findings if f.tool_name == "handle" and f.parameter == "input"]
    assert len(sqli_hits) == 1
    assert sqli_hits[0].severity == Severity.HIGH
    assert sqli_hits[0].confidence == "confirmed"
    assert "[CONFIRMED]" in sqli_hits[0].title

    # 4. Verify no finding in this fixture has confidence != 'confirmed' with severity CRITICAL
    all_findings = cmdi_findings + path_findings + sql_findings
    for f in all_findings:
        if f.confidence != "confirmed":
            assert f.severity != Severity.CRITICAL
