"""
InjectionPointIdentifier - Identifies injection points in MCP tools.

Analyzes tool schemas to find parameters that accept
user-controlled input suitable for payload injection.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class InjectionPoint:
    """Represents an identified injection point."""
    tool_name: str
    parameter_name: str
    parameter_type: str
    injection_type: str  # "command", "path", "sql", "url", "text", "code"
    risk_level: str      # "critical", "high", "medium", "low"
    description: str


class InjectionPointIdentifier:
    """Identifies injection points in MCP tool schemas."""
    
    # Parameter names that suggest specific injection types
    INJECTION_PATTERNS = {
        "command": {
            "keywords": ["command", "cmd", "exec", "execute", "shell", "bash", "script", "run"],
            "risk": "critical",
        },
        "code": {
            "keywords": ["code", "script", "javascript", "python", "eval", "expression", "func"],
            "risk": "critical",
        },
        "sql": {
            "keywords": ["query", "sql", "where", "select", "filter", "search"],
            "risk": "critical",
        },
        "path": {
            "keywords": ["path", "file", "filename", "filepath", "directory", "dir", "folder", "location"],
            "risk": "high",
        },
        "url": {
            "keywords": ["url", "uri", "href", "src", "link", "endpoint", "host", "domain", "address"],
            "risk": "high",
        },
        "template": {
            "keywords": ["template", "format", "render", "markup", "html"],
            "risk": "high",
        },
        "text": {
            "keywords": ["text", "content", "body", "message", "input", "value", "data", "payload", "name", "title", "description", "label", "id", "ref", "query"],
            "risk": "medium",
        },
    }
    
    def identify(self, tools: list[dict]) -> dict[str, list[InjectionPoint]]:
        """
        Identify injection points across all tools.
        
        Args:
            tools: List of MCP tool definitions
            
        Returns:
            Dictionary mapping tool names to lists of injection points
        """
        result = {}
        
        for tool in tools:
            tool_name = tool.get("name", "")
            points = self._analyze_tool(tool)
            
            if points:
                result[tool_name] = points
        
        return result
    
    def _analyze_tool(self, tool: dict) -> list[InjectionPoint]:
        """Analyze a single tool for injection points."""
        points = []
        
        tool_name = tool.get("name", "")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        
        for param_name, param_def in properties.items():
            param_type = param_def.get("type", "string")
            param_desc = param_def.get("description", "")
            
            # Only string parameters are injection candidates
            if param_type != "string":
                continue
            
            # Check each injection pattern
            for injection_type, pattern_info in self.INJECTION_PATTERNS.items():
                keywords = pattern_info["keywords"]
                risk = pattern_info["risk"]
                
                # Check parameter name and description
                name_lower = param_name.lower()
                desc_lower = param_desc.lower()
                
                if any(kw in name_lower or kw in desc_lower for kw in keywords):
                    points.append(InjectionPoint(
                        tool_name=tool_name,
                        parameter_name=param_name,
                        parameter_type=param_type,
                        injection_type=injection_type,
                        risk_level=risk,
                        description=f"Parameter '{param_name}' may be vulnerable to {injection_type} injection"
                    ))
                    break  # Only identify once per parameter
        
        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        points.sort(key=lambda p: risk_order.get(p.risk_level, 4))
        
        return points
