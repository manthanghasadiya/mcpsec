"""
StateExtractor - Extracts refs, IDs, and other state from tool responses.

Parses MCP tool responses to find values that should be
saved for use in subsequent tool calls.
"""

import re
from typing import Any


class StateExtractor:
    """
    Extracts state values from MCP tool responses.
    
    Looks for:
    - Explicit refs/IDs in structured responses
    - Patterns that look like refs (e.g., "e21", "node_123")
    - URLs, paths, and other values that might be needed
    """
    
    # Patterns for common ref/ID formats
    REF_PATTERNS = [
        r'\b(e\d+)\b',           # e21, e35 (Playwright refs)
        r'\b(ref_[a-zA-Z0-9]+)\b',  # ref_abc123
        r'\b(node_[a-zA-Z0-9]+)\b', # node_xyz
        r'\b(elem_[a-zA-Z0-9]+)\b', # elem_123
        r'\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',  # UUIDs
    ]
    
    # Keys that likely contain state values
    STATE_KEYS = [
        "ref", "refs", "reference", "references",
        "id", "ids", "identifier", "identifiers",
        "element", "elements", "node", "nodes",
        "cursor", "nextCursor", "pageToken", "nextPageToken",
        "token", "sessionId", "session_id",
        "handle", "handles", "file", "path",
    ]
    
    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        self._compiled_patterns = [re.compile(p) for p in self.REF_PATTERNS]
    
    def extract(self, response: dict) -> dict[str, Any]:
        """
        Extract state values from a tool response.
        
        Args:
            response: The MCP tool response
            
        Returns:
            Dictionary of extracted state values
        """
        extracted = {}
        
        # Get the result content
        result = response.get("result", {})
        content = result.get("content", [])
        
        # Process structured content
        for item in content:
            if isinstance(item, dict):
                item_type = item.get("type")
                
                if item_type == "text":
                    text = item.get("text", "")
                    extracted.update(self._extract_from_text(text))
                    
                elif item_type == "resource":
                    resource = item.get("resource", {})
                    extracted.update(self._extract_from_dict(resource))
        
        # Also check the raw result for nested state
        extracted.update(self._extract_from_dict(result, depth=0))
        
        return extracted
    
    def _extract_from_dict(self, data: dict, depth: int = 0) -> dict[str, Any]:
        """Recursively extract state from a dictionary."""
        if depth > self.max_depth:
            return {}
        
        extracted = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if this key is a known state key
            if any(sk in key_lower for sk in self.STATE_KEYS):
                extracted[key] = value
                
                # If it's a list, also store individual items
                if isinstance(value, list) and value:
                    for i, item in enumerate(value[:10]):  # Limit to first 10
                        extracted[f"{key}_{i}"] = item
            
            # Recurse into nested dicts
            if isinstance(value, dict):
                nested = self._extract_from_dict(value, depth + 1)
                extracted.update(nested)
            
            # Recurse into lists of dicts
            elif isinstance(value, list):
                for i, item in enumerate(value[:10]):
                    if isinstance(item, dict):
                        nested = self._extract_from_dict(item, depth + 1)
                        # Prefix nested keys with index
                        for nk, nv in nested.items():
                            extracted[f"{key}_{i}_{nk}"] = nv
        
        return extracted
    
    def _extract_from_text(self, text: str) -> dict[str, Any]:
        """Extract ref-like patterns from text content."""
        extracted = {}
        
        # Apply regex patterns
        for i, pattern in enumerate(self._compiled_patterns):
            matches = pattern.findall(text)
            if matches:
                # Store all matches
                extracted[f"text_ref_{i}"] = matches[0] if len(matches) == 1 else matches
                
                # Also store first match with generic key
                if "ref" not in extracted:
                    extracted["ref"] = matches[0]
        
        # Look for key-value patterns in text (e.g., "ref: e21")
        # Ensure we don't capture trailing punctuation like ) or .
        kv_pattern = r'(\w+)\s*[:=]\s*["\']?([^"\'\s,\]\)]+?)["\']?(?=[ \t\n\r,\]\).!?;]|$)'
        kv_matches = re.findall(kv_pattern, text)
        
        for key, value in kv_matches:
            if any(sk in key.lower() for sk in self.STATE_KEYS):
                extracted[key] = value
        
        return extracted
    
    def extract_refs_from_snapshot(self, snapshot_text: str) -> list[str]:
        """
        Extract all ref IDs from a Playwright-style DOM snapshot.
        
        Args:
            snapshot_text: The text content of a browser_snapshot response
            
        Returns:
            List of ref IDs found
        """
        refs = []
        
        # Playwright snapshots have refs like "- ref=e21: button 'Click me'"
        ref_pattern = r'ref=([a-zA-Z0-9]+)'
        matches = re.findall(ref_pattern, snapshot_text)
        refs.extend(matches)
        
        return list(set(refs))  # Deduplicate
