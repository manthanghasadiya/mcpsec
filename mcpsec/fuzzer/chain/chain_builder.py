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
    requires_state: list[str] = field(default_factory=list)  # NEW: State keys required
    
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
        injection_points: dict[str, list[str]] = None, # Not strictly needed if in dep
        max_depth: int = 5,
        max_chains_per_tool: int = 10,
    ) -> list[AttackChain]:
        """Build attack chains for all identified injection points."""
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
                
                # Skip if injection point is a STATE FIELD (like ref, id)
                # We want to inject into OTHER fields while using valid state
                if injection_point.lower() in ['ref', 'element', 'id', 'node', 'handle', 'cursor', 'token', 'session']:
                    continue
                
                # Build setup steps to satisfy this tool's requirements
                setup_steps = []
                requires_state = list(dep.requires) if dep.requires else []
                
                # Find tools that PROVIDE what this tool REQUIRES
                if requires_state:
                    for state_key in requires_state:
                        provider_tool = self._find_state_provider(state_key, dependency_graph, tools_by_name)
                        if provider_tool:
                            # Check if provider itself needs setup
                            provider_dep = dependency_graph.get(provider_tool)
                            if provider_dep and provider_dep.requires:
                                # Add provider's dependencies first (recursive)
                                for sub_req in provider_dep.requires:
                                    sub_provider = self._find_state_provider(sub_req, dependency_graph, tools_by_name)
                                    if sub_provider and sub_provider != provider_tool:
                                        setup_steps.append(ChainStep(
                                            tool_name=sub_provider,
                                            arguments=self._create_argument_template(tools_by_name[sub_provider], dependency_graph.get(sub_provider)),
                                            purpose="setup",
                                            expected_state_keys=[sub_req],
                                        ))
                            
                            # Add the provider tool
                            setup_steps.append(ChainStep(
                                tool_name=provider_tool,
                                arguments=self._create_argument_template(tools_by_name[provider_tool], provider_dep),
                                purpose="extract_state",
                                expected_state_keys=[state_key],
                            ))
                
                # Create target arguments with state placeholders
                target_args = self._create_argument_template(tool, dep)
                
                # Replace required state fields with $state.X placeholders
                for state_key in requires_state:
                    if state_key in target_args:
                        target_args[state_key] = f"$state.{state_key}"
                
                chain = AttackChain(
                    chain_id=f"chain_{self._chain_counter}",
                    target_tool=tool_name,
                    injection_point=injection_point,
                    injection_point_type=injection_types.get(injection_point, "text"),
                    setup_steps=setup_steps,
                    target_arguments=target_args,
                    description=f"Chain: {' → '.join([s.tool_name for s in setup_steps] + [tool_name])} | Inject: {injection_point}",
                    requires_state=requires_state,
                )
                
                chains.append(chain)
                self._chain_counter += 1
                chains_for_tool += 1
        
        return chains

    def _find_state_provider(
        self,
        state_key: str,
        dependency_graph: dict[str, ToolDependency],
        tools_by_name: dict[str, dict],
    ) -> str | None:
        """Find a tool that provides the given state key."""
        for tool_name, dep in dependency_graph.items():
            if tool_name not in tools_by_name:
                continue
            provides = dep.provides if dep.provides else []
            # Check if this tool provides what we need
            if state_key in provides:
                return tool_name
            # Also check for generic ref/id providers
            if state_key in ['ref', 'element', 'id', 'node'] and any(p in ['ref', 'id', 'node', 'element'] for p in provides):
                return tool_name
        return None
    
    def _create_argument_template(
        self, 
        tool: dict, 
        dep: ToolDependency | None
    ) -> dict[str, Any]:
        """Create an argument template for a tool."""
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        
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
