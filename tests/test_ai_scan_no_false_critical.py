import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcpsec.cli import _scan_async
from mcpsec.models import ScanResult, ServerProfile, Severity, ToolInfo
from mcpsec.scanners.response_classifier import Verdict, classify_response


async def _run_ai_scan_with_response(response_text: str):
    tool = ToolInfo(name="test_tool", description="A test tool", parameters={"type": "object"})
    profile = ServerProfile(name="test_server", tools=[tool])

    mock_client = AsyncMock()
    mock_client.connect_stdio.return_value = profile
    mock_client.call_tool.return_value = MagicMock(content=[MagicMock(text=response_text)])

    with patch("mcpsec.client.mcp_client.MCPSecClient") as MockClientClass, \
         patch("mcpsec.ai.ai_payload_generator.AIPayloadGenerator") as MockGenClass, \
         patch("mcpsec.ai.ai_validator.AIValidator") as MockValClass, \
         patch("mcpsec.engine.run_scan") as mock_run_scan:

        MockClientClass.return_value.__aenter__.return_value = mock_client
        mock_gen = MagicMock()
        mock_gen.available = True
        mock_gen.generate_payloads = AsyncMock(
            return_value=[
                {
                    "parameter": "input_param",
                    "payload": "test_payload",
                    "category": "command-injection",
                    "description": "test cmdi",
                }
            ]
        )
        MockGenClass.return_value = mock_gen

        mock_val = MagicMock()
        mock_val.validate_findings = AsyncMock(side_effect=lambda f: f)
        MockValClass.return_value = mock_val

        scan_res = ScanResult(target="test", transport="stdio", findings=[])
        mock_run_scan.return_value = scan_res

        try:
            await _scan_async(
                stdio_cmd="dummy_cmd",
                http_url=None,
                ai=True,
                output_path="nul",
                output_format="json",
                quiet=True,
                scanner_names=[],
                headers=None,
                exploit=False,
                oob_host=None,
                max_params_per_tool=None,
            )
        except (SystemExit, Exception):
            pass

        return scan_res.findings


@pytest.mark.asyncio
async def test_github_mcp_schema_rejection_emits_no_finding():
    rejection = (
        'validating "arguments": validating root: validating /properties/private: '
        'type: test has type "string", want "boolean"'
    )
    assert classify_response(rejection) == Verdict.SAFE

    findings = await _run_ai_scan_with_response(rejection)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_defensive_error_connection_refused_emits_no_finding():
    defensive_resp = "Error: connection refused to localhost"
    findings = await _run_ai_scan_with_response(defensive_resp)
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_genuine_uid_gid_emits_suspected_high_finding():
    genuine_resp = "uid=0(root) gid=0(root)"
    findings = await _run_ai_scan_with_response(genuine_resp)

    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "suspected"
    assert f.severity == Severity.HIGH
    assert f.tool_name == "test_tool"
    assert f.severity != Severity.CRITICAL


@pytest.mark.asyncio
async def test_no_finding_has_critical_severity_from_ai_path():
    for resp in [
        'validating "arguments": validating root: type: test',
        "Error: connection refused to localhost",
        "uid=0(root) gid=0(root)",
    ]:
        findings = await _run_ai_scan_with_response(resp)
        for f in findings:
            assert f.severity != Severity.CRITICAL
