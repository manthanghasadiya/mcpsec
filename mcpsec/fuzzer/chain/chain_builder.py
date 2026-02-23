"""
ChainBuilder - Builds attack chains from dependency analysis.

Creates multi-step attack sequences that:
1. Set up required state
2. Extract necessary refs/IDs
3. Inject payloads at identified injection points
"""

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from .chain_analyzer import ToolDependency

console = Console()


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    tool_name: str
    arguments: dict[str, Any]
    purpose: str  # "setup", "extract_state", "inject"
    expected_state_keys: list[str] = field(default_factory=list)


@dataclass
class AttackChain:
    """A complete attack chain targeting a specific injection point."""
    chain_id: str
    target_tool: str
    injection_point: str
    injection_point_type: str
    setup_steps: list[ChainStep]
    target_arguments: dict[str, Any]
    description: str
    
    @property
    def depth(self) -> int:
        return len(self.setup_steps) + 1


class ChainBuilder:
    """Builds attack chains from tool dependency analysis."""
    
    # Default argument values for common parameter types
    DEFAULT_ARGS = {
        "url": "http://example.com",
        "path": "/tmp/test",
        "file": "/tmp/test.txt",
        "directory": "/tmp",
        "query": "test query",
        "text": "test text",
        "content": "test content",
        "name": "test",
        "id": "1",
        "limit": 10,
        "offset": 0,
        "page": 1,
        "timeout": 5000,
        "width": 1920,
        "height": 1080,
    }
    
    def __init__(self):
        self._chain_counter = 0
    
    def build_chains(
        self,
        tools: list[dict],
        dependency_graph: dict[str, ToolDependency],
        injection_points: dict[str, list[str]],
        max_depth: int = 5,
        max_chains_per_tool: int = 10,
    ) -> list[AttackChain]:
        """
        Build attack chains for all identified injection points.
        
        Args:
            tools: List of MCP tool definitions
            dependency_graph: Tool dependency analysis
            injection_points: Mapping of tool names to injection point parameter names
            max_depth: Maximum chain depth
            max_chains_per_tool: Maximum chains to generate per tool
            
        Returns:
            List of AttackChain objects ready for execution
        """
        chains = []
        tools_by_name = {t["name"]: t for t in tools}
        
        for tool_name, dep in dependency_graph.items():
            if tool_name not in tools_by_name:
                continue
                
            tool = tools_by_name[tool_name]
            tool_injection_points = getattr(dep, 'injection_points', [])
            injection_types = getattr(dep, 'injection_point_types', {})
            
            if not tool_injection_points:
                continue
            
            chains_for_tool = 0
            
            for injection_point in tool_injection_points:
                if chains_for_tool >= max_chains_per_tool:
                    break
                
                # Build the setup chain for this tool
                setup_steps = self._build_setup_chain(
                    tool_name=tool_name,
                    tools_by_name=tools_by_name,
                    dependency_graph=dependency_graph,
                    max_depth=max_depth,
                )
                
                # Create target arguments template
                target_args = self._create_argument_template(tool, dep)
                
                # Create the attack chain
                chain = AttackChain(
                    chain_id=f"chain_{self._chain_counter}",
                    target_tool=tool_name,
                    injection_point=injection_point,
                    injection_point_type=injection_types.get(injection_point, "text"),
                    setup_steps=setup_steps,
                    target_arguments=target_args,
                    description=f"Attack {tool_name}.{injection_point} ({injection_types.get(injection_point, 'unknown')} type)"
                )
                
                chains.append(chain)
                self._chain_counter += 1
                chains_for_tool += 1
        
        return chains
    
    def _build_setup_chain(
        self,
        tool_name: str,
        tools_by_name: dict[str, dict],
        dependency_graph: dict[str, ToolDependency],
        max_depth: int,
        visited: set | None = None,
    ) -> list[ChainStep]:
        """Build the setup steps needed before calling the target tool."""
        if visited is None:
            visited = set()
        
        if tool_name in visited or len(visited) >= max_depth:
            return []
        
        visited.add(tool_name)
        
        dep = dependency_graph.get(tool_name)
        if not dep:
            return []
        
        setup_steps = []
        
        # Recursively build setup for required tools
        for required_tool in dep.required_tools:
            if required_tool in tools_by_name and required_tool not in visited:
                # Get setup for the required tool first
                sub_steps = self._build_setup_chain(
                    tool_name=required_tool,
                    tools_by_name=tools_by_name,
                    dependency_graph=dependency_graph,
                    max_depth=max_depth,
                    visited=visited.copy(),
                )
                setup_steps.extend(sub_steps)
                
                # Add the required tool itself
                required_dep = dependency_graph.get(required_tool)
                required_tool_def = tools_by_name[required_tool]
                
                step = ChainStep(
                    tool_name=required_tool,
                    arguments=self._create_argument_template(required_tool_def, required_dep),
                    purpose="setup",
                    expected_state_keys=required_dep.provides if required_dep else [],
                )
                setup_steps.append(step)
        
        return setup_steps
    
    def _create_argument_template(
        self, 
        tool: dict, 
        dep: ToolDependency | None
    ) -> dict[str, Any]:
        """Create an argument template for a tool."""
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        args = {}
        
        for param_name, param_def in properties.items():
            param_type = param_def.get("type", "string")
            param_default = param_def.get("default")
            param_enum = param_def.get("enum")
            
            # Check if this param should come from state
            if dep and param_name in dep.requires:
                args[param_name] = f"$state.{param_name}"
                continue
            
            # Use enum value if available
            if param_enum:
                args[param_name] = param_enum[0]
                continue
            
            # Use default if available
            if param_default is not None:
                args[param_name] = param_default
                continue
            
            # Use our default values
            if param_name.lower() in self.DEFAULT_ARGS:
                args[param_name] = self.DEFAULT_ARGS[param_name.lower()]
                continue
            
            # Generate based on type
            if param_type == "string":
                args[param_name] = "test"
            elif param_type == "integer":
                args[param_name] = 1
            elif param_type == "number":
                args[param_name] = 1.0
            elif param_type == "boolean":
                args[param_name] = True
            elif param_type == "array":
                args[param_name] = []
            elif param_type == "object":
                args[param_name] = {}
            else:
                args[param_name] = "test"
        
        return args
