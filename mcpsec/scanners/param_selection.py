"""
Unified candidate parameter selection for oracle-backed scanners.

Probes every string-typed and untyped parameter, prioritizing parameters with
sink-related name or format hints (e.g. uri, path, query, cmd, data), without
excluding any parameter by name.
"""

from __future__ import annotations

from typing import Any

HINT_KEYWORDS = (
    "uri",
    "url",
    "path",
    "file",
    "cmd",
    "command",
    "query",
    "sql",
    "data",
    "config",
    "yaml",
    "template",
)

NON_STRING_PRIMITIVES = {"integer", "number", "boolean", "null"}


def candidate_injectable_params(tool: Any, max_params: int = 25) -> list[str]:
    """All parameters worth probing with an effect-oracle: every string-typed
    parameter (and untyped, which many servers leave schema-less). Returns param
    names ordered so schema/name hints (uri, path, query, command, data) come
    first, but NONE are excluded by name. Capped at max_params for cost."""
    # 1. Extract raw properties dict
    raw_schema = getattr(tool, "raw_schema", None)
    if raw_schema is None and isinstance(tool, dict):
        raw_schema = tool.get("raw_schema", {})
    raw_schema = raw_schema or {}

    schema_dict: dict[str, Any] = {}
    if isinstance(raw_schema, dict):
        if "inputSchema" in raw_schema and isinstance(raw_schema["inputSchema"], dict):
            schema_dict = raw_schema["inputSchema"]
        else:
            schema_dict = raw_schema

    props = schema_dict.get("properties", {})
    if not isinstance(props, dict):
        props = {}

    # 2. Extract tool.parameters dict
    tool_params = getattr(tool, "parameters", None)
    if tool_params is None and isinstance(tool, dict):
        tool_params = tool.get("parameters", {})
    tool_params = tool_params or {}
    if not isinstance(tool_params, dict):
        tool_params = {}

    # 3. Collect unique parameter names preserving order
    all_param_names: list[str] = []
    for p in list(tool_params.keys()) + list(props.keys()):
        if p not in all_param_names:
            all_param_names.append(p)

    def is_injectable(p_name: str) -> bool:
        p_def = props.get(p_name)
        p_type = None
        if isinstance(p_def, dict):
            p_type = p_def.get("type")

        if p_type is None:
            param_val = tool_params.get(p_name)
            if isinstance(param_val, str):
                p_type = param_val
            elif isinstance(param_val, dict):
                p_type = param_val.get("type")

        if p_type is None:
            # Untyped / schema-less: include
            return True

        if isinstance(p_type, list):
            types_lower = [t.lower() for t in p_type if isinstance(t, str)]
            if "string" in types_lower or "any" in types_lower:
                return True
            if any(t in ("array", "object") for t in types_lower):
                return True
            if all(t in NON_STRING_PRIMITIVES for t in types_lower):
                return False
            return True

        if isinstance(p_type, str):
            p_type_lower = p_type.lower()
            if p_type_lower in ("string", "any", ""):
                return True
            if p_type_lower in ("array", "object"):
                return True
            if p_type_lower in NON_STRING_PRIMITIVES:
                return False
            return True

        return True

    def has_hint(p_name: str) -> bool:
        name_lower = p_name.lower()
        if any(kw in name_lower for kw in HINT_KEYWORDS):
            return True
        p_def = props.get(p_name)
        if isinstance(p_def, dict):
            fmt = str(p_def.get("format", "")).lower()
            if any(kw in fmt for kw in ("uri", "url", "path", "file")):
                return True
        return False

    candidate_params = [p for p in all_param_names if is_injectable(p)]
    hinted = [p for p in candidate_params if has_hint(p)]
    unhinted = [p for p in candidate_params if not has_hint(p)]

    ordered = hinted + unhinted
    return ordered[:max_params]
