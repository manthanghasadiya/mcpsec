"""
MCP framework source patterns -- identify user input entry points.

These patterns find where MCP tool parameters enter the code.
"""

from mcpsec.static.patterns.base import SourcePattern, Language

PATTERNS: list[SourcePattern] = [
    # ── MCP TypeScript SDK ──────────────────────────────────────────────────
    SourcePattern(
        id="mcp-ts-sdk-001",
        framework="mcp-typescript-sdk",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"server\.tool\s*\(\s*['\"](\w+)['\"]",
        param_pattern=r"(?:request\.params\.)?arguments\.(\w+)",
        description="MCP TypeScript SDK server.tool() handler",
    ),
    SourcePattern(
        id="mcp-ts-sdk-002",
        framework="mcp-typescript-sdk",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"server\.setRequestHandler\s*\(\s*CallToolRequestSchema",
        param_pattern=r"request\.params\.arguments\.(\w+)",
        description="MCP TypeScript SDK setRequestHandler",
    ),
    SourcePattern(
        id="mcp-ts-sdk-003",
        framework="mcp-typescript-sdk",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"const\s*\{\s*(\w+)(?:\s*,\s*\w+)*\s*\}\s*=\s*(?:request\.params\.)?arguments",
        param_pattern=r"(\w+)",
        description="MCP TypeScript SDK destructured arguments",
    ),
    SourcePattern(
        id="mcp-ts-sdk-004",
        framework="mcp-typescript-sdk",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"McpServer\s*\(",
        param_pattern=r"input\.(\w+)",
        description="McpServer high-level API input",
    ),
    SourcePattern(
        id="mcp-ts-sdk-005",
        framework="mcp-typescript-sdk",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"server\.addTool\s*\(\s*\{",
        param_pattern=r"input\.(\w+)|args\.(\w+)",
        description="MCP TypeScript addTool input",
    ),
    SourcePattern(
        id="mcp-ts-sdk-006",
        framework="mcp-typescript-sdk",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"\.register(?:Tool|Handler)\s*\(",
        param_pattern=r"(?:params|args|arguments)\.(\w+)",
        description="Generic registerTool pattern",
    ),

    # ── MCP Python SDK (official) ────────────────────────────────────────
    SourcePattern(
        id="mcp-py-sdk-001",
        framework="mcp-python-sdk",
        languages=[Language.PYTHON],
        entry_pattern=r"@(?:mcp|server)\.tool(?:\s*\(\s*\))?",
        param_pattern=r"arguments\[['\"](\w+)['\"]\]",
        description="MCP Python SDK @mcp.tool decorator",
    ),
    SourcePattern(
        id="mcp-py-sdk-002",
        framework="mcp-python-sdk",
        languages=[Language.PYTHON],
        entry_pattern=r"@(?:mcp|server)\.tool",
        param_pattern=r"arguments\.get\s*\(\s*['\"](\w+)['\"]",
        description="MCP Python SDK arguments.get()",
    ),
    SourcePattern(
        id="mcp-py-sdk-003",
        framework="mcp-python-sdk",
        languages=[Language.PYTHON],
        entry_pattern=r"async\s+def\s+(\w+)\s*\([^)]*ctx",
        param_pattern=r"ctx\.arguments\.(\w+)",
        description="MCP Python SDK context arguments",
    ),
    SourcePattern(
        id="mcp-py-sdk-004",
        framework="mcp-python-sdk",
        languages=[Language.PYTHON],
        entry_pattern=r"@server\.call_tool_handler",
        param_pattern=r"request\.params\.arguments\.get\s*\(\s*['\"](\w+)['\"]",
        description="MCP Python SDK call_tool_handler",
    ),

    # ── FastMCP ──────────────────────────────────────────────────────────
    SourcePattern(
        id="fastmcp-001",
        framework="fastmcp",
        languages=[Language.PYTHON],
        entry_pattern=r"@mcp\.tool\s*(?:\(\s*\))?",
        param_pattern=r"def\s+\w+\s*\([^)]*(\w+)\s*:",
        description="FastMCP tool function parameters",
    ),
    SourcePattern(
        id="fastmcp-002",
        framework="fastmcp",
        languages=[Language.PYTHON],
        entry_pattern=r"FastMCP\s*\(",
        param_pattern=r"def\s+\w+\s*\([^)]*(\w+)\s*:\s*(?:str|int|float|dict|list|Any)",
        description="FastMCP typed tool function parameters",
    ),
    SourcePattern(
        id="fastmcp-003",
        framework="fastmcp",
        languages=[Language.PYTHON],
        entry_pattern=r"@tool\s*(?:\(\s*\))?",
        param_pattern=r"def\s+\w+\s*\([^)]*(\w+)\s*:",
        description="FastMCP @tool shorthand",
    ),

    # ── MCP Go SDK ───────────────────────────────────────────────────────
    SourcePattern(
        id="mcp-go-sdk-001",
        framework="mcp-go-sdk",
        languages=[Language.GO],
        entry_pattern=r"func\s+(\w+)Handler\s*\(",
        param_pattern=r"req\.Params\.Arguments\[['\"](\w+)['\"]\]",
        description="MCP Go SDK handler function",
    ),
    SourcePattern(
        id="mcp-go-sdk-002",
        framework="mcp-go-sdk",
        languages=[Language.GO],
        entry_pattern=r"RegisterTool\s*\(\s*['\"](\w+)['\"]",
        param_pattern=r"args\[['\"](\w+)['\"]\]",
        description="MCP Go SDK RegisterTool",
    ),
    SourcePattern(
        id="mcp-go-sdk-003",
        framework="mcp-go-sdk",
        languages=[Language.GO],
        entry_pattern=r"mcp\.NewServer\s*\(",
        param_pattern=r"request\.Params\.Arguments\.(\w+)",
        description="MCP Go NewServer arguments",
    ),

    # ── Custom C implementations (r2mcp style) ───────────────────────────
    SourcePattern(
        id="mcp-c-custom-001",
        framework="mcp-c-custom",
        languages=[Language.C],
        entry_pattern=r"(?:static\s+)?(?:int|void|char\s*\*)\s+(\w*(?:tool|handle|cmd)\w*)\s*\(",
        param_pattern=r"json_object_get[^(]*\([^,]+,\s*['\"](\w+)['\"]",
        description="Custom C MCP handler with json-c",
    ),
    SourcePattern(
        id="mcp-c-custom-002",
        framework="mcp-c-custom",
        languages=[Language.C],
        entry_pattern=r"tools_call",
        param_pattern=r"params\[['\"](\w+)['\"]\]",
        description="Custom C MCP tools_call",
    ),
    SourcePattern(
        id="mcp-c-custom-003",
        framework="mcp-c-custom",
        languages=[Language.C],
        entry_pattern=r"mcp_handle_request\s*\(",
        param_pattern=r"cJSON_GetObjectItem\s*\([^,]+,\s*['\"](\w+)['\"]",
        description="Custom C MCP with cJSON",
    ),

    # ── .NET MCP ─────────────────────────────────────────────────────────
    SourcePattern(
        id="mcp-dotnet-001",
        framework="mcp-dotnet",
        languages=[Language.CSHARP],
        entry_pattern=r"\[McpTool\s*\(\s*['\"](\w+)['\"]\s*\)\]",
        param_pattern=r"request\.Arguments\[['\"](\w+)['\"]\]",
        description=".NET MCP McpTool attribute",
    ),
    SourcePattern(
        id="mcp-dotnet-002",
        framework="mcp-dotnet",
        languages=[Language.CSHARP],
        entry_pattern=r"\[Tool\s*\(\s*Name\s*=\s*['\"](\w+)['\"]\s*\)\]",
        param_pattern=r"arguments\[\"(\w+)\"\]|GetArgument<[^>]+>\(\"(\w+)\"",
        description=".NET MCP Tool attribute",
    ),

    # ── Rust MCP ─────────────────────────────────────────────────────────
    SourcePattern(
        id="mcp-rust-001",
        framework="mcp-rust-sdk",
        languages=[Language.RUST],
        entry_pattern=r"#\[tool\s*\(\s*name\s*=\s*['\"](\w+)['\"]\s*\)\]",
        param_pattern=r"args\.get\s*\(\s*['\"](\w+)['\"]",
        description="Rust MCP tool attribute",
    ),
    SourcePattern(
        id="mcp-rust-002",
        framework="mcp-rust-sdk",
        languages=[Language.RUST],
        entry_pattern=r"impl\s+Tool\s+for\s+\w+",
        param_pattern=r"params\.get\s*\(\s*['\"](\w+)['\"]",
        description="Rust MCP Tool trait implementation",
    ),

    # ── Generic patterns (fallback) ───────────────────────────────────────
    SourcePattern(
        id="mcp-generic-001",
        framework="mcp-generic",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT, Language.PYTHON],
        entry_pattern=r"(?:tool|handle|dispatch)_?(?:call|request|handler)",
        param_pattern=r"(?:params|arguments|args)\[?['\"](\w+)",
        description="Generic MCP tool invocation pattern",
    ),
    SourcePattern(
        id="mcp-generic-002",
        framework="mcp-generic",
        languages=[Language.TYPESCRIPT, Language.JAVASCRIPT],
        entry_pattern=r"tools\s*=\s*\[",
        param_pattern=r"handler\s*:\s*async\s*\([^)]*\{(\w+)",
        description="Generic tools array handler",
    ),
]

PATTERN_COUNT = len(PATTERNS)
