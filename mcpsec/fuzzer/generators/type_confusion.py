"""Generate type confusion payloads — wrong types in expected fields."""

import json
from .base import FuzzCase

def _frame(message: dict) -> bytes:
    body = json.dumps(message).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

def generate() -> list[FuzzCase]:
    cases = []
    
    type_mutations = [
        ("method_as_number", "method", 42),
        ("method_as_array", "method", ["tools/list"]),
        ("method_as_null", "method", None),
        ("method_as_bool", "method", True),
        ("method_as_object", "method", {"name": "tools/list"}),
        ("id_as_array", "id", [1, 2, 3]),
        ("id_as_object", "id", {"request": 1}),
        ("id_as_float", "id", 1.5),
        ("id_as_bool", "id", True),
        ("params_as_string", "params", "not an object"),
        ("params_as_number", "params", 42),
        ("params_as_array", "params", [1, 2, 3]),
        ("params_as_null", "params", None),
        ("jsonrpc_as_number", "jsonrpc", 2),
        ("jsonrpc_as_null", "jsonrpc", None),
    ]
    
    base = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
    
    for name, field, value in type_mutations:
        mutated = base.copy()
        mutated[field] = value
        cases.append(FuzzCase(
            name=name,
            generator="type_confusion",
            payload=_frame(mutated),
            description=f"Field '{field}' set to {type(value).__name__}: {repr(value)[:50]}",
            expected_behavior="Server returns type error or handles gracefully"
        ))
    
    # Tool call with wrong argument types
    tool_call_base = {
        "jsonrpc": "2.0", "method": "tools/call", "id": 1,
        "params": {"name": "PLACEHOLDER", "arguments": {}}
    }
    
    arg_mutations = [
        ("args_name_as_number", "name", 12345),
        ("args_name_as_null", "name", None),
        ("args_name_as_array", "name", ["tool1", "tool2"]),
        ("args_arguments_as_string", "arguments", "not_an_object"),
        ("args_arguments_as_array", "arguments", [1, 2]),
        ("args_arguments_as_null", "arguments", None),
    ]
    
    for name, field, value in arg_mutations:
        mutated = json.loads(json.dumps(tool_call_base))
        mutated["params"][field] = value
        cases.append(FuzzCase(
            name=name,
            generator="type_confusion",
            payload=_frame(mutated),
            description=f"tools/call params.{field} set to {type(value).__name__}",
            expected_behavior="Server returns type/validation error"
        ))
    
    return cases
