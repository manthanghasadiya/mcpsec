"""mcpsec — Security scanner for MCP server implementations."""

__version__ = "2.7.2"


import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
