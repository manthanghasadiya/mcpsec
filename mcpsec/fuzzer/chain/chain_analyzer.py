"""
ChainAnalyzer - AI-powered analysis of tool dependencies.

Uses LLM to understand:
1. Which tools require state from other tools
2. What state each tool provides
3. The correct order of tool calls
"""

import json
from dataclasses import dataclass
from typing import Any

from rich.console import Console

console = Console()


@dataclass
class ToolDependency:
    """Represents dependencies for a single tool."""
    tool_name: str
    requires: list[str]           # State keys this tool requires
    provides: list[str]           # State keys this tool provides
    required_tools: list[str]     # Tools that must be called first
    optional_tools: list[str]     # Tools that may enhance functionality
    execution_order: int          # Suggested order in chain (1 = first)


class ChainAnalyzer:
    """Analyzes MCP tools to understand their dependencies and state flow."""
    
    ANALYSIS_PROMPT = '''You are an expert security researcher analyzing MCP (Model Context Protocol) tools for stateful dependencies.

Given the following MCP tools, analyze their dependencies and state flow:

TOOLS:
{tools_json}

For EACH tool, determine:

1. **requires**: What state/data does this tool need that must come from another tool's response?
   - Look for parameters like "ref", "id", "sessionId", "token", "cursor", "pageToken"
   - Look for parameters that reference outputs from other tools
   
2. **provides**: What state/data does this tool return that other tools might need?
   - Look at what the tool description says it returns
   - Common outputs: refs, IDs, tokens, cursors, file handles, session data

3. **required_tools**: Which other tools MUST be called before this one?
   - e.g., "browser_click" requires "browser_snapshot" to get valid refs
   - e.g., "file_read" might require "file_open" first

4. **execution_order**: What order should this tool be called? (1 = can be called first, 2 = needs setup, etc.)

5. **injection_points**: Which parameters accept user-controlled input that could be injection targets?
   - Focus on: text, content, query, path, url, command, code, script, html, sql, selector

Respond with ONLY a JSON object in this exact format:
{{
  "tool_name_1": {{
    "requires": ["state_key_1", "state_key_2"],
    "provides": ["state_key_3"],
    "required_tools": ["other_tool_name"],
    "optional_tools": ["another_tool"],
    "execution_order": 2,
    "injection_points": ["param_name"],
    "injection_point_types": {{"param_name": "text"}}
  }},
  "tool_name_2": {{
    ...
  }}
}}

Important rules:
- If a tool can be called first with no dependencies, set execution_order to 1
- If a tool's parameter descriptions mention "ref", "id", or "from snapshot", it likely requires prior state
- Browser/DOM tools almost always require a snapshot/navigate step first
- Database tools might require connection/session setup
- File tools might require path validation or directory listing first

Analyze ALL tools provided. Be thorough - missing a dependency will cause attack chains to fail.
'''

    def __init__(self, use_ai: bool = True):
        self.use_ai = use_ai
        self._llm_client = None
        
    async def analyze_tools(self, tools: list[dict]) -> dict[str, ToolDependency]:
        """
        Analyze tools and return dependency graph.
        
        Args:
            tools: List of MCP tool definitions
            
        Returns:
            Dictionary mapping tool names to their dependencies
        """
        if self.use_ai:
            return await self._analyze_with_ai(tools)
        else:
            return self._analyze_heuristically(tools)
    
    async def _analyze_with_ai(self, tools: list[dict]) -> dict[str, ToolDependency]:
        """Use AI to analyze tool dependencies."""
        from mcpsec.ai.llm_client import LLMClient
        from mcpsec.config import get_ai_config
        
        console.print("  Using AI to analyze tool dependencies...")
        
        config = get_ai_config()
        if not config:
            console.print("  [yellow]No AI config found, falling back to heuristics[/yellow]")
            return self._analyze_heuristically(tools)
        
        self._llm_client = LLMClient(
            provider=config.provider,
            api_key=config.api_key,
            model=config.model,
            base_url=config.base_url,
        )
        
        # Prepare tools JSON (only essential fields to save tokens)
        tools_simplified = []
        for tool in tools:
            tools_simplified.append({
                "name": tool.get("name"),
                "description": tool.get("description", "")[:500],  # Truncate long descriptions
                "inputSchema": tool.get("inputSchema", {}),
            })
        
        prompt = self.ANALYSIS_PROMPT.format(tools_json=json.dumps(tools_simplified, indent=2))
        
        try:
            response = await self._llm_client.complete(prompt)
            
            # Parse JSON from response
            # Handle cases where AI wraps in ```json blocks
            response_text = response.strip()
            if response_text.startswith("```"):
                # Extract JSON from code block
                lines = response_text.split("\n")
                json_lines = []
                in_json = False
                for line in lines:
                    if line.startswith("```json"):
                        in_json = True
                        continue
                    elif line.startswith("```"):
                        in_json = False
                        continue
                    if in_json:
                        json_lines.append(line)
                response_text = "\n".join(json_lines)
            
            analysis = json.loads(response_text)
            
            # Convert to ToolDependency objects
            result = {}
            for tool_name, data in analysis.items():
                result[tool_name] = ToolDependency(
                    tool_name=tool_name,
                    requires=data.get("requires", []),
                    provides=data.get("provides", []),
                    required_tools=data.get("required_tools", []),
                    optional_tools=data.get("optional_tools", []),
                    execution_order=data.get("execution_order", 1),
                )
                # Store injection points in the dependency object as extra data
                result[tool_name].injection_points = data.get("injection_points", [])
                result[tool_name].injection_point_types = data.get("injection_point_types", {})
            
            console.print(f"  AI analyzed [cyan]{len(result)}[/cyan] tools")
            return result
            
        except json.JSONDecodeError as e:
            console.print(f"  [yellow]AI response was not valid JSON: {e}[/yellow]")
            console.print("  Falling back to heuristic analysis")
            return self._analyze_heuristically(tools)
            
        except Exception as e:
            console.print(f"  [yellow]AI analysis failed: {e}[/yellow]")
            return self._analyze_heuristically(tools)
    
    def _analyze_heuristically(self, tools: list[dict]) -> dict[str, ToolDependency]:
        """Analyze tools using pattern matching heuristics."""
        console.print("  Using heuristic analysis...")
        
        result = {}
        
        # Known patterns for browser/playwright MCP servers
        BROWSER_SETUP_TOOLS = ['browser_navigate', 'browser_snapshot']
        BROWSER_STATE_CONSUMERS = ['browser_click', 'browser_type', 'browser_hover', 
                                   'browser_drag', 'browser_select_option', 'browser_evaluate']
        
        tool_names = [t.get("name", "") for t in tools]
        is_browser_server = any("browser_" in name for name in tool_names)
        
        # Keywords that indicate state requirements
        ref_keywords = ["ref", "reference", "element", "node"]
        id_keywords = ["id", "identifier", "handle", "cursor", "token", "session"]
        path_keywords = ["path", "file", "directory", "folder"]
        url_keywords = ["url", "uri", "href", "src", "link", "endpoint", "host", "domain", "address"]
        
        # Keywords that indicate setup tools
        setup_keywords = ["navigate", "open", "connect", "init", "start", "create", "snapshot", "list"]
        
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "").lower()
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            
            requires = []
            provides = []
            required_tools = []
            injection_points = []
            injection_point_types = {}
            execution_order = 1
            
            # Browser-specific handling
            if is_browser_server:
                if name in BROWSER_STATE_CONSUMERS:
                    # These tools almost always need a selector or ref from a snapshot
                    if "selector" in properties or "ref" in properties:
                        requires.extend([p for p in ["selector", "ref"] if p in properties])
                        if "browser_snapshot" in tool_names:
                            required_tools.append("browser_snapshot")
                        execution_order = max(execution_order, 3)
                
                if name == "browser_snapshot":
                    # Snapshot needs a page to be navigated first
                    if "browser_navigate" in tool_names:
                        required_tools.append("browser_navigate")
                    provides.extend(["ref", "element", "id", "node"])
                    execution_order = max(execution_order, 2)
            
            # Analyze each parameter
            for param_name, param_def in properties.items():
                param_desc = param_def.get("description", "").lower()
                param_type = param_def.get("type", "string")
                
                # Check if this param requires state from another tool
                if any(kw in param_name.lower() or kw in param_desc for kw in ref_keywords):
                    if param_name not in requires:
                        requires.append(param_name)
                    execution_order = max(execution_order, 2)
                    
                if any(kw in param_name.lower() or kw in param_desc for kw in id_keywords):
                    if "from" in param_desc or "returned" in param_desc or "snapshot" in param_desc:
                        if param_name not in requires:
                            requires.append(param_name)
                        execution_order = max(execution_order, 2)
                
                # Check if this param is an injection point
                if param_type == "string":
                    if any(kw in param_name.lower() for kw in ["text", "content", "value", "input", "query", "command", "code", "script", "html", "sql", "label", "body", "message"]):
                        injection_points.append(param_name)
                        injection_point_types[param_name] = "text"
                    elif any(kw in param_name.lower() for kw in path_keywords):
                        injection_points.append(param_name)
                        injection_point_types[param_name] = "path"
                    elif any(kw in param_name.lower() for kw in url_keywords):
                        injection_points.append(param_name)
                        injection_point_types[param_name] = "url"
                    elif any(kw in param_name.lower() for kw in ["ref", "id", "node", "element"]):
                        # These are also potential injection points if they are user-controlled
                        injection_points.append(param_name)
                        injection_point_types[param_name] = "text"
            
            # Check if this is a setup tool (provides state)
            if any(kw in name.lower() or kw in description for kw in setup_keywords):
                provides.append(f"{name}_result")
                # Add specific common state keys based on tool type
                if "snapshot" in name.lower() or "list" in name.lower():
                    provides.extend([p for p in ["ref", "id", "node", "element"] if p not in provides])
                execution_order = 1
            
            # Look for tools this one might depend on
            for other_tool in tools:
                other_name = other_tool.get("name", "")
                if other_name == name:
                    continue
                    
                # Check if description mentions needing another tool
                if other_name.lower() in description:
                    if other_name not in required_tools:
                        required_tools.append(other_name)
                    execution_order = max(execution_order, 2)
                
                # Heuristic: if we require something like 'ref' and other tool provides it
                if any(r in ["ref", "id", "node", "element"] for r in requires):
                    if any(kw in other_name.lower() for kw in ["snapshot", "list", "view", "get"]):
                        if other_name not in required_tools:
                            required_tools.append(other_name)
                            execution_order = max(execution_order, 2)
            
            result[name] = ToolDependency(
                tool_name=name,
                requires=requires,
                provides=provides,
                required_tools=required_tools,
                optional_tools=[],
                execution_order=execution_order,
            )
            result[name].injection_points = injection_points
            result[name].injection_point_types = injection_point_types
        
        return result
