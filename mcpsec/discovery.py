"""
MCP configuration auto-discovery.

Discovers locally installed MCP server configurations from known clients:
- Claude Desktop (macOS/Windows/Linux)
- Cursor
- VS Code (with MCP extension)
- Windsurf
- Gemini CLI
- Claude Code
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DiscoveredServer:
    """A discovered MCP server configuration."""
    name: str
    command: Optional[str] = None  # For stdio servers
    args: list[str] = field(default_factory=list)
    url: Optional[str] = None  # For HTTP/SSE servers
    env: dict[str, str] = field(default_factory=dict)
    source_client: str = ""  # e.g., "Claude Desktop", "Cursor"
    config_path: str = ""  # Path to the config file
    
    @property
    def transport(self) -> str:
        """Return 'stdio' or 'http' based on config."""
        if self.url:
            return "http"
        return "stdio"
    
    @property
    def stdio_command(self) -> Optional[str]:
        """Return full stdio command string."""
        if not self.command:
            return None
        parts = [str(self.command)] + self.args
        return " ".join(parts)


@dataclass
class DiscoveryResult:
    """Result of MCP config discovery."""
    servers: list[DiscoveredServer] = field(default_factory=list)
    configs_found: list[str] = field(default_factory=list)
    configs_not_found: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def get_config_paths() -> dict[str, list[Path]]:
    """
    Return known MCP config paths for each client, per platform.
    """
    system = platform.system()
    home = Path.home()
    
    paths: dict[str, list[Path]] = {}
    
    if system == "Darwin":  # macOS
        paths["Claude Desktop"] = [
            home / "Library/Application Support/Claude/claude_desktop_config.json",
        ]
        paths["Cursor"] = [
            home / ".cursor/mcp.json",
            home / "Library/Application Support/Cursor/User/globalStorage/mcp.json",
        ]
        paths["VS Code"] = [
            home / ".vscode/mcp.json",
            home / "Library/Application Support/Code/User/globalStorage/mcp.json",
        ]
        paths["Windsurf"] = [
            home / ".windsurf/mcp.json",
            home / "Library/Application Support/Windsurf/User/globalStorage/mcp.json",
        ]
        paths["Claude Code"] = [
            home / ".claude/settings.json",
            home / ".claude.json",
        ]
        paths["Gemini CLI"] = [
            home / ".config/gemini/mcp.json",
        ]
        
    elif system == "Windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        localappdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        
        paths["Claude Desktop"] = [
            appdata / "Claude/claude_desktop_config.json",
        ]
        paths["Cursor"] = [
            home / ".cursor/mcp.json",
            appdata / "Cursor/User/globalStorage/mcp.json",
        ]
        paths["VS Code"] = [
            home / ".vscode/mcp.json",
            appdata / "Code/User/globalStorage/mcp.json",
        ]
        paths["Windsurf"] = [
            home / ".windsurf/mcp.json",
            appdata / "Windsurf/User/globalStorage/mcp.json",
        ]
        paths["Claude Code"] = [
            home / ".claude/settings.json",
            home / ".claude.json",
        ]
        paths["Gemini CLI"] = [
            home / ".config/gemini/mcp.json",
        ]
        
    else:  # Linux
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        
        paths["Claude Desktop"] = [
            config_home / "Claude/claude_desktop_config.json",
            home / ".config/Claude/claude_desktop_config.json",
        ]
        paths["Cursor"] = [
            home / ".cursor/mcp.json",
            config_home / "Cursor/User/globalStorage/mcp.json",
        ]
        paths["VS Code"] = [
            home / ".vscode/mcp.json",
            config_home / "Code/User/globalStorage/mcp.json",
        ]
        paths["Windsurf"] = [
            home / ".windsurf/mcp.json",
            config_home / "Windsurf/User/globalStorage/mcp.json",
        ]
        paths["Claude Code"] = [
            home / ".claude/settings.json",
            home / ".claude.json",
        ]
        paths["Gemini CLI"] = [
            config_home / "gemini/mcp.json",
        ]
    
    return paths


def parse_mcp_config(config_path: Path, client_name: str) -> list[DiscoveredServer]:
    """
    Parse an MCP config file and extract server definitions.
    
    Handles multiple config formats:
    - Standard: {"mcpServers": {"name": {...}}}
    - Claude Code: {"mcpServers": {...}} in settings.json
    """
    servers = []
    
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    except Exception as e:
        raise ValueError(f"Could not read file: {e}")
    
    # Find mcpServers section
    mcp_servers = data.get("mcpServers", {})
    if not mcp_servers:
        # Some configs might have servers at root level
        if "command" in data or "url" in data:
            mcp_servers = {"default": data}
    
    for name, config in mcp_servers.items():
        if not isinstance(config, dict):
            continue
            
        server = DiscoveredServer(
            name=name,
            source_client=client_name,
            config_path=str(config_path),
        )
        
        # Handle stdio servers
        if "command" in config:
            server.command = config["command"]
            server.args = config.get("args", [])
            server.env = config.get("env", {})
            
        # Handle HTTP/SSE servers
        elif "url" in config:
            server.url = config["url"]
            
        # Handle type-specified servers
        elif "type" in config:
            if config["type"] in ("stdio", "npx", "node", "python", "uv", "uvx"):
                server.command = config.get("command", config["type"])
                server.args = config.get("args", [])
                server.env = config.get("env", {})
            elif config["type"] in ("http", "sse", "streamable-http"):
                server.url = config.get("url")
        
        # Skip invalid entries
        if not server.command and not server.url:
            continue
            
        servers.append(server)
    
    return servers


def discover_mcp_servers(
    config_path: Optional[str] = None,
    client_filter: Optional[list[str]] = None,
) -> DiscoveryResult:
    """
    Discover all locally configured MCP servers.
    
    Args:
        config_path: If provided, only parse this specific config file
        client_filter: If provided, only check these clients (e.g., ["Claude Desktop", "Cursor"])
    
    Returns:
        DiscoveryResult with all discovered servers and metadata
    """
    result = DiscoveryResult()
    
    # If specific config path provided, parse just that
    if config_path:
        path = Path(config_path).expanduser()
        if path.exists():
            try:
                servers = parse_mcp_config(path, "Custom")
                result.servers.extend(servers)
                result.configs_found.append(str(path))
            except Exception as e:
                result.errors.append(f"{path}: {e}")
        else:
            result.configs_not_found.append(str(path))
        return result
    
    # Auto-discover from known paths
    all_paths = get_config_paths()
    
    for client_name, paths in all_paths.items():
        # Apply client filter if specified
        if client_filter and client_name not in client_filter:
            continue
            
        for path in paths:
            if path.exists():
                try:
                    servers = parse_mcp_config(path, client_name)
                    result.servers.extend(servers)
                    if str(path) not in result.configs_found:
                        result.configs_found.append(str(path))
                except Exception as e:
                    result.errors.append(f"{path}: {e}")
            else:
                result.configs_not_found.append(str(path))
    
    return result


def get_server_display_name(server: DiscoveredServer) -> str:
    """Return a display-friendly name for a server."""
    return f"{server.name} ({server.source_client})"
