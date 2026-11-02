"""Schema-aware argument fuzzer generator.

Parses inputSchema of discovered MCP tools and generates per-parameter,
type-targeted mutations (string injection and traversal, integer boundaries,
boolean and type confusion, array and object abuse, enum escape, prototype pollution).
Fills required non-target parameters with valid baseline values.
"""

import json
import math
from typing import Any

from .base import FuzzCase

OMIT_SENTINEL = object()


def _is_transport_payload(val: Any) -> bool:
    """Return True if val contains values that cannot round-trip as strict JSON.

    Specifically:
    - String containing lone surrogate code points (0xD800 to 0xDFFF)
    - Float values of NaN or Infinity (require allow_nan=True, invalid in strict JSON)
    """
    if isinstance(val, str):
        return any(0xD800 <= ord(c) <= 0xDFFF for c in val)
    if isinstance(val, float):
        return math.isnan(val) or math.isinf(val)
    if isinstance(val, dict):
        return any(_is_transport_payload(k) or _is_transport_payload(v) for k, v in val.items())
    if isinstance(val, (list, tuple)):
        return any(_is_transport_payload(x) for x in val)
    return False


def _detect_case_layer(args: dict[str, Any], msg: dict[str, Any]) -> str:
    """Detect whether a case targets the transport layer or the tool handler."""
    if _is_transport_payload(args):
        return "transport"
    try:
        json.dumps(msg, allow_nan=False)
    except (ValueError, TypeError):
        return "transport"
    return "handler"


def _frame(body: bytes, framing: str = "clrf") -> bytes:
    """Apply MCP framing to raw payload."""
    if framing == "jsonl":
        return body + b"\n"
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def generate_baseline_value(prop_schema: dict) -> Any:
    """Generate a deterministic, valid baseline value for a property schema."""
    if not isinstance(prop_schema, dict):
        return "test"

    if "default" in prop_schema:
        return prop_schema["default"]
    if "const" in prop_schema:
        return prop_schema["const"]
    if "enum" in prop_schema and isinstance(prop_schema["enum"], list) and prop_schema["enum"]:
        return prop_schema["enum"][0]

    prop_type = prop_schema.get("type")
    if isinstance(prop_type, list):
        non_null = [t for t in prop_type if t != "null"]
        prop_type = non_null[0] if non_null else "string"
    elif prop_type is None:
        if "properties" in prop_schema:
            prop_type = "object"
        elif "items" in prop_schema:
            prop_type = "array"
        else:
            prop_type = "string"

    if prop_type == "string":
        fmt = prop_schema.get("format", "")
        if fmt in ("uri", "url"):
            val = "https://example.com/test"
        elif fmt == "email":
            val = "user@example.com"
        elif fmt == "uuid":
            val = "123e4567-e89b-12d3-a456-426614174000"
        elif fmt == "date":
            val = "2026-01-01"
        elif fmt == "date-time":
            val = "2026-01-01T00:00:00Z"
        elif fmt == "ipv4":
            val = "127.0.0.1"
        elif fmt == "ipv6":
            val = "::1"
        else:
            val = "test_value"

        min_len = prop_schema.get("minLength")
        if isinstance(min_len, int) and len(val) < min_len:
            val = val + ("x" * (min_len - len(val)))

        max_len = prop_schema.get("maxLength")
        if isinstance(max_len, int) and len(val) > max_len:
            val = val[:max_len]

        return val

    elif prop_type == "integer":
        val = 1
        minimum = prop_schema.get("minimum")
        if isinstance(minimum, (int, float)):
            val = int(minimum)
            if prop_schema.get("exclusiveMinimum"):
                val += 1
        else:
            maximum = prop_schema.get("maximum")
            if isinstance(maximum, (int, float)) and maximum < 1:
                val = int(maximum)

        mult = prop_schema.get("multipleOf")
        if isinstance(mult, (int, float)) and mult > 0:
            val = int(mult)
        return val

    elif prop_type == "number":
        val = 1.0
        minimum = prop_schema.get("minimum")
        if isinstance(minimum, (int, float)):
            val = float(minimum)
            if prop_schema.get("exclusiveMinimum"):
                val += 0.5
        return val

    elif prop_type == "boolean":
        return True

    elif prop_type == "array":
        items_schema = prop_schema.get("items", {})
        item_val = (
            generate_baseline_value(items_schema)
            if isinstance(items_schema, dict)
            else "item"
        )
        min_items = prop_schema.get("minItems", 1)
        count = max(1, min_items if isinstance(min_items, int) else 1)
        return [item_val] * count

    elif prop_type == "object":
        props = prop_schema.get("properties", {})
        req = prop_schema.get("required", [])
        if isinstance(props, dict):
            return {
                k: generate_baseline_value(v)
                for k, v in props.items()
                if isinstance(v, dict) and (not req or k in req)
            }
        return {}

    elif prop_type == "null":
        return None

    return "test"


def build_valid_arguments(schema: dict) -> dict[str, Any]:
    """Build a complete valid arguments dictionary from an inputSchema.

    Iterates over properties in the schema and generates a deterministic,
    valid baseline value for each property using generate_baseline_value.
    """
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    return {
        param_name: generate_baseline_value(prop_schema)
        for param_name, prop_schema in properties.items()
        if isinstance(prop_schema, dict)
    }


def _make_deep_array(depth: int) -> list:
    curr = ["item"]
    for _ in range(depth):
        curr = [curr]
    return curr


def _make_deep_object(depth: int) -> dict:
    curr = {"nested": True}
    for _ in range(depth):
        curr = {"nested": curr}
    return curr


def _get_mutations_for_param(
    param_name: str,
    prop_schema: dict,
    intensity: str,
) -> list[tuple[str, Any, str, bool]]:
    """Return list of (subname, mutation_value, description, expects_error) for parameter."""
    mutations: list[tuple[str, Any, str, bool]] = []

    if intensity == "low":
        str_huge_size = 1_000
        arr_huge_size = 100
        max_depth = 20
    elif intensity in ("high", "insane"):
        str_huge_size = 1_000_000
        arr_huge_size = 100_000
        max_depth = 100
    else:  # medium
        str_huge_size = 10_000
        arr_huge_size = 1_000
        max_depth = 50

    raw_type = prop_schema.get("type")
    if isinstance(raw_type, list):
        non_null = [t for t in raw_type if t != "null"]
        prop_type = non_null[0] if non_null else "string"
    elif raw_type is None:
        if "properties" in prop_schema:
            prop_type = "object"
        elif "items" in prop_schema:
            prop_type = "array"
        elif "enum" in prop_schema:
            first = prop_schema["enum"][0] if prop_schema["enum"] else "test"
            prop_type = type(first).__name__
            if prop_type == "str":
                prop_type = "string"
            elif prop_type == "int":
                prop_type = "integer"
            elif prop_type == "bool":
                prop_type = "boolean"
            else:
                prop_type = "string"
        else:
            prop_type = "string"
    else:
        prop_type = raw_type

    # Enum mutations
    if "enum" in prop_schema and isinstance(prop_schema["enum"], list):
        enum_vals = prop_schema["enum"]
        if "__MCPSEC_OUT_OF_ENUM__" not in enum_vals:
            mutations.append(
                ("enum_out_of_bounds", "__MCPSEC_OUT_OF_ENUM__", "Out of enum string value", True)
            )
        if "" not in enum_vals:
            mutations.append(("enum_empty_str", "", "Empty string not in enum", True))
        if 999999 not in enum_vals:
            mutations.append(("enum_numeric", 999999, "Numeric value not in enum", True))
        if None not in enum_vals:
            mutations.append(("enum_null", None, "Null value not in enum", True))

    if prop_type == "string":
        # Path traversal
        mutations.append(
            ("path_traversal_unix", "../../../../etc/passwd", "Path traversal ../../../../etc/passwd", False)
        )
        if intensity != "low":
            mutations.append(
                ("path_traversal_windows", "..\\..\\..\\windows\\system32\\config\\sam", "Windows path traversal SAM", False)
            )
            mutations.append(
                ("path_traversal_url", "%2e%2e%2fetc%2fpasswd", "URL-encoded path traversal", False)
            )
            mutations.append(
                ("path_traversal_double", "....//....//etc/passwd", "Double dot-slash path traversal", False)
            )
            mutations.append(
                ("path_traversal_null", "/etc/passwd\x00.txt", "Path traversal with null byte poison", False)
            )

        # Command injection
        mutations.append(("cmdi_semicolon", "; id", "Command injection semicolon ; id", False))
        if intensity != "low":
            mutations.append(("cmdi_pipe", "| whoami", "Command injection pipe | whoami", False))
            mutations.append(("cmdi_backticks", "`id`", "Command injection backticks `id`", False))
            mutations.append(("cmdi_subshell", "$(whoami)", "Command injection subshell $(whoami)", False))
            mutations.append(("cmdi_newline", "x\nid", "Command injection newline x\\nid", False))
            mutations.append(("cmdi_and", "&& net user", "Command injection logical AND && net user", False))

        # Template injection
        mutations.append(("ssti_jinja", "{{7*7}}", "Template injection Jinja/Twig {{7*7}}", False))
        if intensity != "low":
            mutations.append(("ssti_dollar", "${7*7}", "Template injection ES6/Bash ${7*7}", False))
            mutations.append(("ssti_erb", "<%= 7*7 %>", "Template injection ERB <%= 7*7 %>", False))
            mutations.append(("ssti_ruby", "#{7*7}", "Template injection Ruby #{7*7}", False))

        # SSRF
        mutations.append(
            ("ssrf_aws_metadata", "http://169.254.169.254/latest/meta-data/", "SSRF AWS metadata endpoint", False)
        )
        if intensity != "low":
            mutations.append(
                ("ssrf_gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/", "SSRF GCP metadata endpoint", False)
            )
            mutations.append(
                ("ssrf_localhost_ssh", "http://127.0.0.1:22", "SSRF localhost internal port probe", False)
            )
            mutations.append(
                ("ssrf_file_uri", "file:///etc/passwd", "SSRF file URI scheme", False)
            )
            mutations.append(
                ("ssrf_gopher_uri", "gopher://127.0.0.1:6379/_INFO", "SSRF gopher protocol injection", False)
            )

        # Length abuse
        mutations.append(("length_empty", "", "Empty string", False))
        mutations.append(("length_single_char", "a", "Single character string", False))
        mutations.append(("length_huge", "A" * str_huge_size, f"{str_huge_size} char long string", False))

        max_len = prop_schema.get("maxLength")
        if isinstance(max_len, int):
            mutations.append(("length_max_plus_1", "A" * (max_len + 1), f"Length {max_len + 1} exceeds maxLength {max_len}", True))
            if intensity != "low":
                mutations.append(("length_max_x10", "A" * (max_len * 10), f"Length {max_len * 10} exceeds maxLength {max_len} by 10x", True))

        min_len = prop_schema.get("minLength")
        if isinstance(min_len, int) and min_len > 0:
            mutations.append(("length_min_minus_1", "A" * (min_len - 1), f"Length {min_len - 1} below minLength {min_len}", True))

        # Constraint violations
        if "pattern" in prop_schema:
            mutations.append(("pattern_violation", "!@#$%^&*()_invalid_pattern", "String violating regex pattern", True))

        fmt = prop_schema.get("format")
        if fmt:
            if fmt == "email":
                mutations.append(("format_malformed_email", "not-an-email@invalid..com", "Malformed email address", True))
            elif fmt in ("date", "date-time"):
                mutations.append(("format_malformed_date", "9999-99-99T99:99:99", "Malformed date/time format", True))
            elif fmt == "uuid":
                mutations.append(("format_malformed_uuid", "not-a-valid-uuid-string", "Malformed UUID format", True))
            elif fmt in ("uri", "url"):
                mutations.append(("format_malformed_uri", "htt p://::invalid", "Malformed URI format", True))
            else:
                mutations.append(("format_malformed", "invalid_format_data", f"Malformed format for {fmt}", True))

        # Unicode / encoding
        mutations.append(("unicode_fullwidth", "＜script＞", "Fullwidth Unicode script tags", False))
        if intensity != "low":
            mutations.append(("unicode_rtl_override", "\u202eadmin", "Right-to-left override character", False))
            mutations.append(("unicode_emoji_4byte", "💥", "4-byte UTF-8 emoji", False))
            mutations.append(("unicode_lone_surrogate", "\ud800", "Lone surrogate Unicode code point", False))
            mutations.append(("unicode_null_byte", "test\x00evil", "Null byte in middle of string", False))

        # Type confusion
        mutations.append(("type_int", 12345, "Integer where string expected", True))
        mutations.append(("type_bool", True, "Boolean where string expected", True))
        if intensity != "low":
            mutations.append(("type_float", 3.14159, "Float where string expected", True))
            mutations.append(("type_array", ["a", "b"], "Array where string expected", True))
            mutations.append(("type_object", {"nested": "value"}, "Object where string expected", True))

    elif prop_type in ("integer", "number"):
        # Boundaries
        mutations.append(("boundary_zero", 0, "Zero boundary value", False))
        mutations.append(("boundary_neg_one", -1, "Negative one boundary value", False))
        mutations.append(("boundary_pos_one", 1, "Positive one boundary value", False))
        mutations.append(("boundary_max_int64", 9223372036854775807, "Maximum 64-bit signed integer (2^63 - 1)", False))
        mutations.append(("boundary_min_int64", -9223372036854775808, "Minimum 64-bit signed integer (-2^63)", False))

        if intensity != "low":
            mutations.append(("boundary_2_pow_63", 9223372036854775808, "2^63 unsigned boundary overflow", False))
            mutations.append(("boundary_2_pow_64", 18446744073709551616, "2^64 unsigned 64-bit integer overflow", False))
            mutations.append(("boundary_neg_2_pow_63_minus_1", -9223372036854775809, "-2^63 - 1 underflow integer", False))

        # Floats
        if prop_type == "integer":
            mutations.append(("float_pi", 3.14159, "Float 3.14159 where integer expected", True))
            if intensity != "low":
                mutations.append(("float_tiny", 1e-10, "Float 1e-10 where integer expected", True))

        mutations.append(("float_zero", 0.0, "Float 0.0", False))
        if intensity != "low":
            mutations.append(("float_neg_zero", -0.0, "Float negative zero -0.0", False))
            mutations.append(("float_large", 1e308, "Very large float 1e308", False))
            mutations.append(("float_small", 1e-308, "Very small float 1e-308", False))

        # Special JSON tokens (allow_nan=True)
        mutations.append(("nan_token", float("nan"), "NaN numeric value", False))
        mutations.append(("infinity_token", float("inf"), "Infinity numeric value", False))
        if intensity != "low":
            mutations.append(("neg_infinity_token", float("-inf"), "-Infinity numeric value", False))

        # Minimum / Maximum violations
        minimum = prop_schema.get("minimum")
        if isinstance(minimum, (int, float)):
            mutations.append(("min_violation", minimum - 1, f"Below minimum {minimum}", True))

        maximum = prop_schema.get("maximum")
        if isinstance(maximum, (int, float)):
            mutations.append(("max_violation", maximum + 1, f"Above maximum {maximum}", True))

        multiple_of = prop_schema.get("multipleOf")
        if isinstance(multiple_of, (int, float)) and multiple_of > 0:
            mutations.append(("multiple_of_violation", multiple_of + 1, f"Non-multiple of {multiple_of}", True))

        # Type confusion
        mutations.append(("type_str", "not_a_number", "String where number expected", True))
        mutations.append(("type_bool", True, "Boolean where number expected", True))
        if intensity != "low":
            mutations.append(("type_array", [1, 2], "Array where number expected", True))
            mutations.append(("type_object", {"num": 1}, "Object where number expected", True))
            mutations.append(("type_null", None, "Null where number expected", True))

    elif prop_type == "boolean":
        # Boolean type confusion
        mutations.append(("bool_str_true", "true", "String 'true' where boolean expected", True))
        mutations.append(("bool_str_false", "false", "String 'false' where boolean expected", True))
        mutations.append(("bool_int_1", 1, "Integer 1 where boolean expected", True))
        mutations.append(("bool_int_0", 0, "Integer 0 where boolean expected", True))
        if intensity != "low":
            mutations.append(("bool_null", None, "Null where boolean expected", True))
            mutations.append(("bool_array", [], "Empty array where boolean expected", True))
            mutations.append(("bool_object", {}, "Empty object where boolean expected", True))
            mutations.append(("bool_str_yes", "yes", "String 'yes' where boolean expected", True))
            mutations.append(("type_str", "not_a_bool", "String where boolean expected", True))
            mutations.append(("type_float", 3.14, "Float where boolean expected", True))

    elif prop_type == "array":
        items_schema = prop_schema.get("items", {})
        item_base = (
            generate_baseline_value(items_schema)
            if isinstance(items_schema, dict)
            else "item"
        )
        min_items = prop_schema.get("minItems", 0)

        mutations.append(("array_empty", [], "Empty array []", True if min_items > 0 else False))
        mutations.append(("array_single", [item_base], "Single element array", False))
        mutations.append(("array_huge", [item_base] * arr_huge_size, f"Huge array of {arr_huge_size} items", False))
        mutations.append(("array_wrong_element_type", [{"invalid_elem": True}], "Array with wrong element type", True))
        mutations.append(("array_deeply_nested", _make_deep_array(max_depth), f"Deeply nested array (depth {max_depth})", False))

        if isinstance(items_schema, dict) and items_schema.get("type") == "string":
            mutations.append(("array_item_traversal", ["../../../../etc/passwd"], "Array with traversal item", False))
            if intensity != "low":
                mutations.append(("array_item_cmdi", ["; id"], "Array with command injection item", False))

        if isinstance(min_items, int) and min_items > 0:
            mutations.append(("array_min_items_violation", [item_base] * (min_items - 1), f"Array below minItems {min_items}", True))

        max_items = prop_schema.get("maxItems")
        if isinstance(max_items, int):
            mutations.append(("array_max_items_violation", [item_base] * (max_items + 1), f"Array exceeding maxItems {max_items}", True))

        # Type confusion
        mutations.append(("type_str", "not_an_array", "String where array expected", True))
        if intensity != "low":
            mutations.append(("type_num", 12345, "Number where array expected", True))
            mutations.append(("type_object", {"arr": []}, "Object where array expected", True))
            mutations.append(("type_bool", False, "Boolean where array expected", True))

    elif prop_type == "object":
        # Prototype pollution
        mutations.append(
            ("object_proto_pollute_1", {"__proto__": {"polluted": True}}, "Prototype pollution via __proto__", False)
        )
        if intensity != "low":
            mutations.append(
                ("object_proto_pollute_2", {"constructor": {"prototype": {"polluted": True}}}, "Prototype pollution via constructor.prototype", False)
            )
            mutations.append(
                ("object_proto_pollute_3", {"__proto__.polluted": True}, "Prototype pollution via __proto__.polluted", False)
            )

        mutations.append(("object_deeply_nested", _make_deep_object(max_depth), f"Deeply nested object (depth {max_depth})", False))
        mutations.append(("object_unexpected_keys", {"__unexpected_fuzz_key__": "unexpected_val"}, "Object with unexpected extra property", False))
        mutations.append(("object_empty", {}, "Empty object {}", False))

        nested_props = prop_schema.get("properties", {})
        if isinstance(nested_props, dict):
            for np_name, np_schema in nested_props.items():
                if isinstance(np_schema, dict) and np_schema.get("type") == "string":
                    nested_obj = {
                        k: generate_baseline_value(v)
                        for k, v in nested_props.items()
                        if isinstance(v, dict)
                    }
                    nested_obj[np_name] = "../../../../etc/passwd"
                    mutations.append(
                        (f"object_nested_traversal_{np_name}", nested_obj, f"Object with nested traversal in {np_name}", False)
                    )
                    break

        # Type confusion
        mutations.append(("type_str", "not_an_object", "String where object expected", True))
        if intensity != "low":
            mutations.append(("type_num", 42, "Number where object expected", True))
            mutations.append(("type_array", [1, 2, 3], "Array where object expected", True))
            mutations.append(("type_bool", True, "Boolean where object expected", True))

    return mutations


def generate_for_tools(
    tools: list[dict],
    framing: str = "clrf",
    intensity: str = "medium",
) -> list[FuzzCase]:
    """Generate per-parameter, type-targeted fuzz cases for discovered tools."""
    cases: list[FuzzCase] = []
    req_id = 1

    for tool in tools:
        if not isinstance(tool, dict):
            continue

        tool_name = tool.get("name") or "unknown_tool"
        raw_schema = tool.get("inputSchema")
        schema = raw_schema if isinstance(raw_schema, dict) else {}

        raw_props = schema.get("properties")
        properties = dict(raw_props) if isinstance(raw_props, dict) else {}

        raw_req = schema.get("required")
        required_keys = set(raw_req) if isinstance(raw_req, list) else set()

        # Handle schema-less tools by treating as a single untyped string param
        if not properties:
            properties = {"input": {"type": "string"}}
            required_keys = set()

        for param_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                prop_schema = {"type": "string"}

            is_required = param_name in required_keys

            param_mutations: list[tuple[str, Any, str, bool]] = []

            # Required field omissions/null tests
            if is_required:
                param_mutations.append(
                    ("omit_required", OMIT_SENTINEL, "Omit required parameter entirely", True)
                )
                param_mutations.append(
                    ("null_required", None, "Send null for required typed field", True)
                )

            # Type-targeted mutations
            param_mutations.extend(
                _get_mutations_for_param(param_name, prop_schema, intensity)
            )

            for subname, val, desc, expects_error in param_mutations:
                # Build arguments: fill required non-target parameters with baselines
                args: dict[str, Any] = {}
                for req_key in required_keys:
                    if req_key != param_name and req_key in properties:
                        args[req_key] = generate_baseline_value(properties[req_key])

                if val is not OMIT_SENTINEL:
                    args[param_name] = val

                msg = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": args,
                    },
                }
                req_id += 1

                try:
                    body = json.dumps(msg, allow_nan=True).encode("utf-8")
                except (TypeError, ValueError, OverflowError):
                    continue

                layer = _detect_case_layer(args, msg)
                case_name = f"schema_{tool_name}_{param_name}_{subname}"
                cases.append(
                    FuzzCase(
                        name=case_name,
                        generator="schema_fuzzer",
                        payload=_frame(body, framing),
                        description=f"[{tool_name}.{param_name}] {desc}",
                        expected_behavior=(
                            "Rejection or graceful error handling"
                            if expects_error
                            else "Handled cleanly without crash"
                        ),
                        expects_error=expects_error,
                        crash_indicates_bug=True,
                        layer=layer,
                    )
                )

    return cases


def generate(framing: str = "clrf", intensity: str = "medium") -> list[FuzzCase]:
    """Default generator entry point when tools have not yet been discovered."""
    return []
