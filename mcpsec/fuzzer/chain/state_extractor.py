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
        r'\b(e\d{1,5})\b',             # e21, e353 (Playwright refs)
        r'ref[=:][\s"\']*([a-zA-Z0-9_-]+)', # ref=e21, "ref": "e21"
        r'\b(ref_[a-zA-Z0-9_-]+)\b',   # ref_abc123
        r'\b(node_[a-zA-Z0-9_-]+)\b',  # node_xyz
        r'\b(elem_[a-zA-Z0-9_-]+)\b',  # elem_123
        r'\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b',  # UUIDs
        r'\b(id_[a-zA-Z0-9_-]{8,})\b', # Long specific IDs
    ]
    
    # Keys that likely contain state values
    STATE_KEYS = [
        "ref", "refs", "reference", "references",
        "id", "ids", "identifier", "identifiers",
        "element", "elements", "node", "nodes",
        "cursor", "nextCursor", "pageToken", "nextPageToken",
        "token", "sessionId", "session_id", "session_token",
        "handle", "handles", "file", "path", "uuid", "guid",
        "selector", "selector_id", "target_id",
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
        if not text or not isinstance(text, str):
            return {}
            
        extracted = {}
        
        # 1. Apply dedicated ref patterns
        for i, pattern in enumerate(self._compiled_patterns):
            matches = pattern.findall(text)
            if matches:
                # Store all matches
                extracted[f"text_ref_{i}"] = matches[0] if len(matches) == 1 else matches
                
                # Also store first match with generic key
                if "ref" not in extracted:
                    extracted["ref"] = matches[0]
                if "id" not in extracted:
                    extracted["id"] = matches[0]
        
        # 2. Look for key-value patterns in text (e.g., "ref: e21")
        # Ensure we don't capture trailing punctuation
        kv_pattern = r'(\w+)\s*[:=]\s*["\']?([^"\'\s,\]\)]+?)["\']?(?=[ \t\n\r,\]\).!?;]|$)'
        kv_matches = re.findall(kv_pattern, text)
        
        for key, value in kv_matches:
            key_lower = key.lower()
            if any(sk in key_lower for sk in self.STATE_KEYS):
                # Clean value (remove trailing period if it's not part of it)
                clean_value = value.rstrip('.')
                extracted[key] = clean_value
        
        # 3. Dedicated Playwright ref extraction
        playwright_refs = self.extract_refs_from_text(text)
        extracted.update(playwright_refs)
        
        return extracted

    def extract_refs_from_text(self, text: str) -> dict[str, Any]:
        """
        Extract refs and IDs from text content.
        Handles various formats:
        - ref=e21
        - (ref=e21)
        - "ref": "e21"
        - [ref=e21]
        - element e21
        """
        extracted = {}
        
        # Pattern 1: ref=XXX or ref:XXX
        ref_matches = re.findall(r'ref[=:][\s"\']*([a-zA-Z0-9_-]+)', text, re.IGNORECASE)
        if ref_matches:
            extracted["ref"] = ref_matches[0]
            
        # Pattern 2: element XXX
        elem_matches = re.findall(r'element\s+([a-zA-Z0-9_-]+)', text, re.IGNORECASE)
        if elem_matches:
            extracted["element"] = elem_matches[0]
            
        # Pattern 3: node XXX
        node_matches = re.findall(r'node\s+([a-zA-Z0-9_-]+)', text, re.IGNORECASE)
        if node_matches:
            extracted["node"] = node_matches[0]

        # Pattern 4: any "e" followed by numbers at end of line or in brackets
        # Common in Playwright snapshots: "... [e21]" or "... (e21)"
        e_refs = re.findall(r'[\(\[\s](e\d{1,5})[\)\]\s\:]', text)
        if e_refs:
            if "ref" not in extracted:
                extracted["ref"] = e_refs[0]
            extracted["e_ref"] = e_refs[0]
            
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
