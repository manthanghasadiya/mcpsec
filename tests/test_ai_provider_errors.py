import httpx
import pytest
from typer.testing import CliRunner

from mcpsec.ai.llm_client import LLMClient, LLMError
from mcpsec.cli import app
from mcpsec.config import get_api_key


@pytest.fixture
def llm(monkeypatch):
    monkeypatch.setattr(
        "mcpsec.ai.llm_client.get_api_key",
        lambda: ("openai", "secret-key", "https://example.test/v1", "model"),
    )
    return LLMClient()


@pytest.mark.parametrize("provider", ["openai", "anthropic", "google"])
async def test_provider_http_error_contains_status_and_redacts_key(llm, monkeypatch, provider):
    llm.provider = provider
    original = httpx.AsyncClient
    transport = httpx.MockTransport(
        lambda request: httpx.Response(401, text="invalid secret-key", request=request)
    )
    monkeypatch.setattr(
        "mcpsec.ai.llm_client.httpx.AsyncClient",
        lambda **kwargs: original(transport=transport, **kwargs),
    )
    with pytest.raises(LLMError) as error:
        await llm.chat("system", "message")
    assert "401" in str(error.value)
    assert "invalid [redacted]" in str(error.value)
    assert "secret-key" not in str(error.value)


async def test_network_error_does_not_expose_url(llm, monkeypatch):
    original = httpx.AsyncClient

    def fail(request):
        raise httpx.ConnectError("failed at https://example.test/?key=secret-key", request=request)

    monkeypatch.setattr(
        "mcpsec.ai.llm_client.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(fail), **kwargs),
    )
    with pytest.raises(LLMError, match="ConnectError") as error:
        await llm.chat("system", "message")
    assert "secret-key" not in str(error.value)


async def test_unconfigured_provider_remains_optional(monkeypatch):
    monkeypatch.setattr("mcpsec.ai.llm_client.get_api_key", lambda: (None, None, None, None))
    assert await LLMClient().chat("system", "message") is None


async def test_success_and_malformed_response(llm, monkeypatch):
    original = httpx.AsyncClient
    responses = iter(
        [
            {"choices": [{"message": {"content": "ok"}}]},
            {"choices": []},
        ]
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=next(responses)))
    monkeypatch.setattr(
        "mcpsec.ai.llm_client.httpx.AsyncClient",
        lambda **kwargs: original(transport=transport, **kwargs),
    )
    assert await llm.chat("system", "message") == "ok"
    with pytest.raises(LLMError, match="invalid response"):
        await llm.chat("system", "message")


async def test_classifier_does_not_swallow_provider_failure(tmp_path):
    from mcpsec.ai.finding_classifier import classify_server_and_findings
    from mcpsec.models import Finding, Severity

    class FailedClient:
        async def complete(self, **kwargs):
            raise LLMError("HTTP 429")

    finding = Finding(severity=Severity.HIGH, scanner="test", title="test", description="test")
    with pytest.raises(LLMError, match="429"):
        await classify_server_and_findings(tmp_path, [finding], FailedClient())


async def test_scan_propagates_later_provider_failure_and_closes_client(monkeypatch):
    from types import SimpleNamespace

    from mcpsec.cli import _scan_async

    closed = []

    class ServerClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            closed.append(True)

        async def connect_http(self, *args, **kwargs):
            tool = SimpleNamespace(name="tool", description="", parameters={}, raw_schema={})
            return SimpleNamespace(tools=[tool], resources=[], prompts=[])

    async def fail(*args, **kwargs):
        raise LLMError("HTTP 429")

    monkeypatch.setattr("mcpsec.client.mcp_client.MCPSecClient", ServerClient)
    monkeypatch.setattr("mcpsec.ai.llm_client.get_api_key", lambda: (None, None, None, None))
    monkeypatch.setattr(
        "mcpsec.ai.ai_payload_generator.AIPayloadGenerator.available", property(lambda _: True)
    )
    monkeypatch.setattr("mcpsec.ai.ai_payload_generator.AIPayloadGenerator.generate_payloads", fail)
    with pytest.raises(LLMError, match="429"):
        await _scan_async(None, "http://localhost", None, None, quiet=True, ai=True)
    assert closed == [True]


async def test_audit_propagates_provider_failure_and_cleans_source(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from mcpsec.models import Finding, Severity
    from mcpsec.static.audit_engine import run_audit

    cleaned = []

    async def fetch(*args):
        return str(tmp_path)

    async def fail(*args):
        raise LLMError("HTTP 429")

    class Scanner:
        def scan(self, *args, **kwargs):
            return SimpleNamespace(matches=[], files_scanned=0, patterns_applied=0)

    monkeypatch.setattr("mcpsec.static.audit_engine.fetch_source", fetch)
    monkeypatch.setattr("mcpsec.static.audit_engine.cleanup_temp", cleaned.append)
    monkeypatch.setattr(
        "mcpsec.static.audit_engine.detect_framework",
        lambda _: SimpleNamespace(
            language=SimpleNamespace(value="python"), framework=SimpleNamespace(value="test")
        ),
    )
    monkeypatch.setattr("mcpsec.static.audit_engine.SinkScanner", Scanner)
    finding = Finding(severity=Severity.HIGH, scanner="test", title="test", description="test")
    monkeypatch.setattr(
        "mcpsec.static.audit_engine.run_semgrep_with_categories", lambda _: ([finding], {})
    )
    monkeypatch.setattr("mcpsec.ai.llm_client.LLMClient.available", property(lambda _: True))
    monkeypatch.setattr("mcpsec.ai.llm_client.get_api_key", lambda: (None, None, None, None))
    monkeypatch.setattr("mcpsec.ai.finding_classifier.classify_server_and_findings", fail)
    with pytest.raises(LLMError, match="429"):
        await run_audit(npm="package", ai=True)
    assert cleaned == [str(tmp_path)]


@pytest.mark.parametrize(
    "args", [["scan", "--http", "http://example.test", "--ai"], ["audit", "--path", ".", "--ai"]]
)
def test_commands_fail_on_provider_check(monkeypatch, args):
    async def fail():
        raise LLMError("HTTP 401: invalid key")

    monkeypatch.setattr("mcpsec.cli._check_ai_provider", fail)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert "HTTP 401: invalid key" in result.output


@pytest.mark.parametrize(
    "args", [["scan", "--http", "http://example.test", "--ai"], ["audit", "--path", ".", "--ai"]]
)
def test_commands_report_http_failure_from_real_provider_check(monkeypatch, args):
    monkeypatch.setattr(
        "mcpsec.ai.llm_client.get_api_key",
        lambda: ("openai", "secret-key", "https://example.test/v1", "model"),
    )
    original = httpx.AsyncClient
    transport = httpx.MockTransport(lambda request: httpx.Response(401, text="invalid key"))
    monkeypatch.setattr(
        "mcpsec.ai.llm_client.httpx.AsyncClient",
        lambda **kwargs: original(transport=transport, **kwargs),
    )
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert "HTTP 401: invalid key" in result.output


def test_auto_scan_rejects_unsupported_ai_mode():
    result = CliRunner().invoke(app, ["scan", "--auto", "--ai"])
    assert result.exit_code == 1
    assert "not available with automatic discovery" in result.output


def test_environment_key_uses_configured_model(monkeypatch):
    from mcpsec.config import PROVIDERS

    for info in PROVIDERS.values():
        if info["env_var"]:
            monkeypatch.delenv(info["env_var"], raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "key")
    monkeypatch.setattr(
        "mcpsec.config.load_config", lambda: {"ai_provider": "openai", "model": "custom-model"}
    )
    assert get_api_key()[3] == "custom-model"
