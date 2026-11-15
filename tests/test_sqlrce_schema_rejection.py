"""Tests verifying that sql-rce never confirms RCE or file-read on schema validation rejections."""

from mcpsec.models import Severity
from mcpsec.scanners.response_classifier import Verdict, classify_response
from mcpsec.scanners.sql_rce import SQLInjectionRCEScanner, SqlRceScanner

assert SqlRceScanner is SQLInjectionRCEScanner


GITHUB_SCHEMA_REJECTION = (
    'validating "arguments": validating root: validating /properties/private: '
    'type: test has type "string", want "boolean"'
)


def test_github_schema_rejection_classifies_safe():
    """Go jsonschema validator output must be classified as Verdict.SAFE."""
    verdict = classify_response(GITHUB_SCHEMA_REJECTION)
    assert verdict == Verdict.SAFE


def test_classify_rce_result_ignores_schema_rejection():
    """Schema rejection with 'root:' substring must return (None, '') without false RCE finding."""
    scanner = SQLInjectionRCEScanner()
    severity, evidence = scanner._classify_rce_result(
        GITHUB_SCHEMA_REJECTION, "rce", "'; SELECT 1;--"
    )
    assert severity is None
    assert evidence == ""


def test_classify_rce_result_detects_real_passwd():
    """Genuine passwd line read through _classify_rce_result must still return Severity.CRITICAL."""
    scanner = SQLInjectionRCEScanner()
    severity, evidence = scanner._classify_rce_result(
        "root:x:0:0:root:/root:/bin/bash", "file_read", "'; SELECT 1;--"
    )
    assert severity == Severity.CRITICAL
    assert "RCE confirmed" in evidence


def test_is_sqli_error_detects_real_db_error():
    """Real Postgres syntax error must still make _is_sqli_error return True."""
    scanner = SQLInjectionRCEScanner()
    response = "ERROR: syntax error at or near \"'\""
    assert scanner._is_sqli_error(response, "'") is True


def test_is_sqli_error_rejects_payload_echo_in_schema_rejection():
    """Schema validation rejection echoing quote payload must not be flagged as SQLi error."""
    scanner = SQLInjectionRCEScanner()
    echo_rejection = (
        'validating "arguments": validating root: validating /properties/query: '
        'type: \'"\' has type "string", want "boolean"'
    )
    assert scanner._is_sqli_error(echo_rejection, "'") is False
