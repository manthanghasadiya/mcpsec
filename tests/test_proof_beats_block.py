from mcpsec.scanners.response_classifier import (
    Verdict,
    classify_cmd_injection,
    classify_response,
)


def test_uid_gid_proof_beats_block_phrase():
    resp = "uid=0(root) gid=0(root)\nsome/dir: Permission denied"
    assert classify_response(resp) == Verdict.CONFIRMED


def test_passwd_proof_beats_block_phrase():
    resp = "root:x:0:0:root:/root:/bin/bash\naccess denied for other paths"
    assert classify_response(resp) == Verdict.CONFIRMED


def test_pure_block_without_proof_is_safe():
    resp = "Permission denied"
    assert classify_response(resp) == Verdict.SAFE


def test_schema_rejection_without_proof_is_safe():
    resp = (
        'validating "arguments": validating root: validating /properties/private: '
        'type: test has type "string", want "boolean"'
    )
    assert classify_response(resp) == Verdict.SAFE


def test_classify_cmd_injection_proof_plus_block_is_confirmed():
    resp = "uid=0(root) gid=0(root)\nsome/dir: Permission denied"
    verdict, reason = classify_cmd_injection(resp)
    assert verdict == Verdict.CONFIRMED
    assert "Command execution proof" in reason
