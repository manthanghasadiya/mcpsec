"""Mutate the JSON-RPC 'method' field — typos, case, homoglyphs, traversal."""

import json
from .base import FuzzCase

# All valid MCP methods
MCP_METHODS = [
    "initialize", "ping", "tools/list", "tools/call",
    "resources/list", "resources/read", "resources/subscribe",
    "resources/unsubscribe", "prompts/list", "prompts/get",
    "completion/complete", "logging/setLevel",
    "notifications/initialized", "notifications/cancelled",
]

def _rpc(method: str, params=None, req_id=1) -> bytes:
    msg: dict = {"jsonrpc": "2.0", "method": method, "id": req_id}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg).encode()


def generate(framing: str = "clrf") -> list[FuzzCase]:
    cases: list[FuzzCase] = []

    def _frame(body: bytes) -> bytes:
        if framing == "jsonl":
            return body + b"\n"
        return f"Content-Length: {len(body)}\r\n\r\n".encode() + body

    def _add(name: str, payload: bytes, desc: str, expected: str = "Error or reject"):
        cases.append(FuzzCase(name=name, generator="method_mutations",
                              payload=_frame(payload), description=desc,
                              expected_behavior=expected))

    # ── Typos for every slash-method ─────────────────────────────────
    typo_pairs = [
        ("tools/list", ["tools/listt", "tool/list", "tols/list", "tools/lis"]),
        ("tools/call", ["tools/cal", "tools/calll", "tool/call"]),
        ("resources/list", ["resource/list", "resources/listt"]),
        ("resources/read", ["resources/reed", "resource/read"]),
        ("prompts/list", ["prompt/list", "prompts/listt"]),
        ("prompts/get", ["prompts/gett", "prompt/get"]),
        ("completion/complete", ["completion/complet", "completions/complete"]),
    ]
    for correct, typos in typo_pairs:
        for t in typos:
            _add(f"typo_{t.replace('/', '_')}", _rpc(t),
                 f"Typo of '{correct}': '{t}'")

    # ── Case variations ──────────────────────────────────────────────
    case_variants = [
        "TOOLS/LIST", "Tools/List", "tOOLS/lIST", "TOOLS/CALL",
        "INITIALIZE", "Initialize", "PING", "Ping",
        "RESOURCES/LIST", "Resources/Read",
    ]
    for v in case_variants:
        _add(f"case_{v.replace('/', '_').lower()}", _rpc(v),
             f"Case variation: '{v}'")

    # ── Unicode homoglyphs for slash ─────────────────────────────────
    FAKE_SLASHES = ["\u2215", "\u2044", "\u29F8", "\uFF0F"]  # ∕ ⁄ ⧸ ／
    for i, fs in enumerate(FAKE_SLASHES):
        _add(f"homoglyph_slash_{i}", _rpc(f"tools{fs}list"),
             f"Unicode homoglyph slash (U+{ord(fs):04X}) in method")

    # ── Path traversal in method ─────────────────────────────────────
    traversals = [
        "../../tools/list",
        "tools/../list",
        "tools/./list",
        "../../../etc/passwd",
        "tools/%2e%2e/list",
        "tools\\list",
        "tools\\..\\list",
    ]
    for i, t in enumerate(traversals):
        _add(f"method_traversal_{i}", _rpc(t),
             f"Path traversal in method: '{t}'")

    # ── Method with whitespace ───────────────────────────────────────
    ws_variants = [
        ("leading_space", " tools/list"),
        ("trailing_space", "tools/list "),
        ("inner_space", "tools / list"),
        ("tab", "tools\t/list"),
        ("newline_in_method", "tools\nlist"),
        ("crlf_in_method", "tools\r\nlist"),
    ]
    for name, m in ws_variants:
        _add(f"ws_{name}", _rpc(m), f"Whitespace in method: {repr(m)}")

    # ── Method injection (CRLF) ──────────────────────────────────────
    injections = [
        ("crlf_inject", "tools/list\r\ntools/call"),
        ("url_encoded_crlf", "tools/list%0d%0atools/call"),
        ("null_terminate", "tools/list\x00tools/call"),
    ]
    for name, m in injections:
        _add(f"inject_{name}", _rpc(m), f"Method injection: {repr(m)}")

    # ── Very long method paths ───────────────────────────────────────
    _add("long_method_segments", _rpc("tools/" + "a/" * 500 + "list"),
         "Method with 500 path segments")
    _add("long_method_10k", _rpc("x" * 10_000),
         "10KB method name")

    # ── Empty / missing segments ─────────────────────────────────────
    empty_segs = [
        "tools//list", "//tools/list", "tools/list//",
        "/", "//", "", "///tools///list///",
    ]
    for i, s in enumerate(empty_segs):
        _add(f"empty_seg_{i}", _rpc(s), f"Empty path segments: '{s}'")

    # ── Dot segments ─────────────────────────────────────────────────
    dot_segs = [
        "tools/./list", "tools/../tools/list",
        "./tools/list", "tools/list/.", "tools/list/..",
    ]
    for i, s in enumerate(dot_segs):
        _add(f"dot_seg_{i}", _rpc(s), f"Dot segments in method: '{s}'")

    # ── Special / exotic method names ────────────────────────────────
    specials = [
        ("star", "*"),
        ("question", "?"),
        ("hash", "#"),
        ("at", "@"),
        ("dollar", "$rpc.system"),
        ("internal", "__proto__"),
        ("constructor", "constructor"),
        ("toString", "toString"),
        ("emoji_method", "🔧/list"),
    ]
    for name, m in specials:
        _add(f"special_{name}", _rpc(m), f"Special method name: '{m}'")

    # ── URL-encoded method names ─────────────────────────────────────
    url_encoded = [
        ("url_tools_list", "tools%2Flist", "URL-encoded slash in tools/list"),
        ("url_tools_call", "tools%2Fcall", "URL-encoded slash in tools/call"),
        ("url_resources_list", "resources%2Flist", "URL-encoded slash in resources/list"),
        ("url_resources_read", "resources%2Fread", "URL-encoded slash in resources/read"),
        ("url_prompts_list", "prompts%2Flist", "URL-encoded slash in prompts/list"),
        ("url_prompts_get", "prompts%2Fget", "URL-encoded slash in prompts/get"),
        ("url_double_encode", "tools%252Flist", "Double URL-encoded slash"),
        ("url_full_encode", "%74%6F%6F%6C%73%2F%6C%69%73%74", "Fully URL-encoded tools/list"),
    ]
    for name, m, desc in url_encoded:
        _add(name, _rpc(m), desc)

    # ── Reversed / shuffled methods ──────────────────────────────────
    reversed_methods = [
        ("reversed_tools_list", "tsil/sloot", "Reversed tools/list"),
        ("reversed_resources_read", "daer/secruoser", "Reversed resources/read"),
        ("swapped_tools_list", "list/tools", "Swapped segments: list/tools"),
        ("swapped_resources_read", "read/resources", "Swapped segments: read/resources"),
    ]
    for name, m, desc in reversed_methods:
        _add(name, _rpc(m), desc)

    # ── Method as non-string types ───────────────────────────────────
    wrong_method_types = [
        ("method_int", 42),
        ("method_float", 3.14),
        ("method_bool", True),
        ("method_null", None),
        ("method_array", ["tools", "list"]),
        ("method_object", {"name": "tools/list"}),
    ]
    for name, val in wrong_method_types:
        msg = {"jsonrpc": "2.0", "method": val, "id": 1}
        _add(name, json.dumps(msg).encode(),
             f"Method as {type(val).__name__}: {val}")

    # ── LSP / other protocol methods ─────────────────────────────────
    lsp_methods = [
        "textDocument/didOpen", "textDocument/completion",
        "workspace/symbol", "window/showMessage",
        "$/progress", "$/cancelRequest",
        "shutdown", "exit",
        "textDocument/hover", "textDocument/definition",
    ]
    for i, m in enumerate(lsp_methods):
        _add(f"lsp_method_{i}", _rpc(m), f"LSP method name: {m}")

    # ── Numeric / integer methods ────────────────────────────────────
    for num in [0, 1, -1, 999, 2147483647, -2147483648]:
        _add(f"numeric_method_{abs(num)}",
             json.dumps({"jsonrpc": "2.0", "method": str(num), "id": 1}).encode(),
             f"Numeric method name: {num}")

    # ── Method with SQL/command injection ────────────────────────────
    inject_methods = [
        ("sqli_method", "tools/list' OR '1'='1", "SQL injection in method"),
        ("cmd_method", "tools/list; ls -la", "Command injection in method"),
        ("xpath_method", "tools/list[1=1]", "XPath injection in method"),
        ("template_method", "tools/{{list}}", "Template injection in method"),
        ("eval_method", "tools/list\"; eval(\"1+1", "Eval injection in method"),
    ]
    for name, m, desc in inject_methods:
        _add(name, _rpc(m), desc)

    # ── Every valid method with extra prefix/suffix ──────────────────
    for method in ["tools/list", "tools/call", "resources/list", "ping"]:
        _add(f"prefix_slash_{method.replace('/', '_')}",
             _rpc(f"/{method}"), f"Leading slash: /{method}")
        _add(f"suffix_slash_{method.replace('/', '_')}",
             _rpc(f"{method}/"), f"Trailing slash: {method}/")

    return cases
