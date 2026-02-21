"""Tests for the protocol fuzzer generators."""
import pytest

from mcpsec.fuzzer.generators.base import FuzzCase


def test_all_generators_importable():
    """All fuzzer generator modules should be importable."""
    from mcpsec.fuzzer.generators import (
        malformed_json,
        type_confusion,
        protocol_violation,
        unicode_attacks,
        boundary_testing,
        session_attacks,
        encoding_attacks,
        injection_payloads,
        method_mutations,
        param_mutations,
        timing_attacks,
        header_mutations,
        json_edge_cases,
        protocol_state,
        resource_exhaustion,
    )


def test_malformed_json_produces_cases():
    """malformed_json.generate() should return multiple FuzzCase objects."""
    from mcpsec.fuzzer.generators import malformed_json

    cases = malformed_json.generate()
    assert len(cases) >= 5
    for case in cases:
        assert isinstance(case, FuzzCase)
        assert case.name
        assert case.payload
        assert case.generator == "malformed_json"


def test_generator_framing_parameter():
    """Generators should accept a framing parameter."""
    from mcpsec.fuzzer.generators import malformed_json

    jsonl_cases = malformed_json.generate(framing="jsonl")
    clrf_cases = malformed_json.generate(framing="clrf")
    assert len(jsonl_cases) >= 1
    assert len(clrf_cases) >= 1


def test_fuzzcase_has_required_fields():
    """FuzzCase dataclass should have all required fields."""
    case = FuzzCase(
        name="test",
        generator="test_gen",
        payload=b"hello",
        description="A test case",
        expected_behavior="Should not crash",
    )
    assert case.name == "test"
    assert case.generator == "test_gen"
    assert case.payload == b"hello"


def test_high_intensity_produces_substantial_cases():
    """High intensity should produce 400+ test cases in aggregate."""
    from mcpsec.fuzzer.generators import (
        malformed_json,
        type_confusion,
        protocol_violation,
        unicode_attacks,
        boundary_testing,
        session_attacks,
        encoding_attacks,
        injection_payloads,
        method_mutations,
        param_mutations,
        timing_attacks,
        header_mutations,
        json_edge_cases,
        protocol_state,
    )

    total = 0
    for gen in [
        malformed_json, type_confusion, protocol_violation,
        unicode_attacks, boundary_testing, session_attacks,
        encoding_attacks, injection_payloads, method_mutations,
        param_mutations, timing_attacks, header_mutations,
        json_edge_cases, protocol_state,
    ]:
        try:
            total += len(gen.generate(framing="clrf"))
        except TypeError:
            total += len(gen.generate())

    assert total >= 400, f"Only {total} cases — expected 400+"
