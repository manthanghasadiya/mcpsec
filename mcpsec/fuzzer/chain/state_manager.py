"""
StateManager - Tracks state across chain execution.

Stores extracted refs, IDs, tokens, and other state
that needs to be passed between chain steps.
"""

from typing import Any
from dataclasses import dataclass, field


@dataclass
class StateSnapshot:
    """A snapshot of state at a particular point in chain execution."""
    step_number: int
    tool_name: str
    extracted_values: dict[str, Any]


class StateManager:
    """
    Manages state across attack chain execution.
    
    State is extracted from tool responses and used to
    populate subsequent tool calls.
    """
    
    def __init__(self):
        self._state: dict[str, Any] = {}
        self._history: list[StateSnapshot] = []
        self._step_counter = 0
    
    def reset(self) -> None:
        """Reset all state for a new chain execution."""
        self._state = {}
        self._history = []
        self._step_counter = 0
    
    def update(self, new_state: dict[str, Any], tool_name: str = "unknown") -> None:
        """
        Update state with newly extracted values.
        
        Args:
            new_state: Dictionary of extracted state values
            tool_name: Name of the tool that produced this state
        """
        # Save snapshot
        self._history.append(StateSnapshot(
            step_number=self._step_counter,
            tool_name=tool_name,
            extracted_values=new_state.copy(),
        ))
        self._step_counter += 1
        
        # Merge into current state
        self._state.update(new_state)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a state value.
        
        Args:
            key: State key to retrieve
            default: Default value if key not found
            
        Returns:
            The state value or default
        """
        return self._state.get(key, default)
    
    def get_all(self) -> dict[str, Any]:
        """Get all current state."""
        return self._state.copy()
    
    def has(self, key: str) -> bool:
        """Check if a state key exists."""
        return key in self._state
    
    def get_history(self) -> list[StateSnapshot]:
        """Get the history of state changes."""
        return self._history.copy()
    
    def get_refs(self) -> list[str]:
        """Get all ref-like values from state."""
        refs = []
        for key, value in self._state.items():
            if any(kw in key.lower() for kw in ["ref", "id", "element", "node"]):
                if isinstance(value, str):
                    refs.append(value)
                elif isinstance(value, list):
                    refs.extend([v for v in value if isinstance(v, str)])
        return refs
