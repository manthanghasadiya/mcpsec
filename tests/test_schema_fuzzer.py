"""Tests for the schema-aware argument fuzzer generator."""

import json
import pytest

from mcpsec.fuzzer.generators import schema_fuzzer
from mcpsec.fuzzer.generators.base import FuzzCase


def _parse_payload(case: FuzzCase) -> dict:
    """Helper to unframe and parse JSON payload from FuzzCase."""
    raw = case.payload
    if b"\r\n\r\n" in raw:
        body = raw.split(b"\r\n\r\n", 1)[1]
    elif raw.endswith(b"\n"):
        body = raw.rstrip(b"\n")
    else:
        body = raw
    return json.loads(body.decode("utf-8"))


def test_generate_default_empty():
    """Default generate() returns an empty list when tools are not known."""
    cases = schema_fuzzer.generate()
    assert isinstance(cases, list)
    assert len(cases) == 0


def test_schema_fuzzer_all_parameter_types_covered():
    """Given a schema with string, integer, boolean, enum, array, and object params,
    generate_for_tools produces cases for each parameter."""
    tools = [
        {
            "name": "test_multi_param",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "str_param": {"type": "string"},
                    "int_param": {"type": "integer", "minimum": 1, "maximum": 100},
                    "bool_param": {"type": "boolean"},
                    "enum_param": {"type": "string", "enum": ["red", "green", "blue"]},
                    "arr_param": {"type": "array", "items": {"type": "string"}},
                    "obj_param": {
                        "type": "object",
                        "properties": {"nested_key": {"type": "string"}},
                    },
                },
                "required": ["str_param"],
            },
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, framing="clrf", intensity="medium")
    assert len(cases) > 0

    param_names = ["str_param", "int_param", "bool_param", "enum_param", "arr_param", "obj_param"]
    for param in param_names:
        param_cases = [c for c in cases if f"test_multi_param_{param}_" in c.name]
        assert len(param_cases) > 0, f"No cases generated for parameter: {param}"


def test_integer_boundaries_and_type_confusion():
    """Integer params get numeric-boundary mutations and type-confusion (non-numeric) mutations."""
    tools = [
        {
            "name": "calc_tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "minimum": 5, "maximum": 50},
                },
                "required": ["count"],
            },
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, framing="jsonl", intensity="medium")
    int_cases = [c for c in cases if "calc_tool_count_" in c.name]
    assert len(int_cases) > 0

    has_boundary = False
    has_type_confusion = False

    for c in int_cases:
        msg = _parse_payload(c)
        args = msg.get("params", {}).get("arguments", {})
        if "count" not in args:
            continue
        val = args["count"]

        # Numeric boundaries: numbers outside standard range or special boundaries
        if isinstance(val, (int, float)):
            if val in (0, -1, 1, 9223372036854775807, -9223372036854775808, 4, 51):
                has_boundary = True
            elif str(val) in ("nan", "inf", "-inf"):
                has_boundary = True

        # Non-numeric type confusion: string, boolean, list, dict, null
        if isinstance(val, (str, bool, list, dict)) or val is None:
            has_type_confusion = True

    assert has_boundary, "Expected numeric boundary mutations for integer parameter"
    assert has_type_confusion, "Expected non-numeric type confusion mutations for integer parameter"


def test_enum_out_of_enum_mutation():
    """Enum params get at least one out-of-enum value."""
    valid_enum = ["pending", "in_progress", "completed"]
    tools = [
        {
            "name": "status_tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": valid_enum},
                },
                "required": ["status"],
            },
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, framing="jsonl", intensity="medium")
    enum_cases = [c for c in cases if "status_tool_status_" in c.name]
    assert len(enum_cases) > 0

    out_of_enum_found = False
    for c in enum_cases:
        msg = _parse_payload(c)
        args = msg.get("params", {}).get("arguments", {})
        if "status" in args:
            val = args["status"]
            if val not in valid_enum:
                out_of_enum_found = True
                break

    assert out_of_enum_found, "Enum parameter did not receive any out-of-enum mutation"


def test_required_fields_present_in_non_error_cases():
    """Required fields are present in every non-expects_error case."""
    tools = [
        {
            "name": "file_reader",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filepath": {"type": "string"},
                    "offset": {"type": "integer"},
                    "verbose": {"type": "boolean"},
                },
                "required": ["filepath"],
            },
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, framing="clrf", intensity="medium")
    assert len(cases) > 0

    for c in cases:
        msg = _parse_payload(c)
        args = msg.get("params", {}).get("arguments", {})
        if not c.expects_error:
            assert "filepath" in args, (
                f"Required field 'filepath' missing in non-error case: {c.name}"
            )


def test_all_payloads_valid_json_rpc_tools_call():
    """Every payload decodes to valid JSON-RPC with method == 'tools/call'."""
    tools = [
        {
            "name": "execute_cmd",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cmd": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["cmd"],
            },
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, framing="jsonl", intensity="medium")
    assert len(cases) > 0

    for c in cases:
        msg = _parse_payload(c)
        assert msg.get("jsonrpc") == "2.0", f"Invalid jsonrpc in {c.name}"
        assert msg.get("method") == "tools/call", f"Method is not tools/call in {c.name}"
        assert "params" in msg, f"Missing params in {c.name}"
        assert msg["params"].get("name") == "execute_cmd", f"Wrong tool name in {c.name}"
        assert "arguments" in msg["params"], f"Missing arguments in {c.name}"


def test_schemaless_tool_yields_cases():
    """A schema-less tool ({} inputSchema) still yields cases (treated as one untyped string param)."""
    tools = [
        {
            "name": "raw_echo",
            "inputSchema": {},
        }
    ]

    cases = schema_fuzzer.generate_for_tools(tools, framing="jsonl", intensity="medium")
    assert len(cases) > 0

    for c in cases:
        msg = _parse_payload(c)
        assert msg.get("method") == "tools/call"
        assert msg["params"]["name"] == "raw_echo"
        assert "input" in msg["params"]["arguments"]
