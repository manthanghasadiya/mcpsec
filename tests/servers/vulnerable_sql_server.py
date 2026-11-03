"""Test MCP server with vulnerable, parameterized, reflection, and time-based SQL tools."""

import asyncio
import json
import re
import sqlite3
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-sql-server")

# In-memory SQLite database setup
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)")
cursor.execute("INSERT INTO users (name, email, role) VALUES ('alice', 'alice@example.com', 'admin')")
cursor.execute("INSERT INTO users (name, email, role) VALUES ('bob', 'bob@example.com', 'user')")
cursor.execute("INSERT INTO users (name, email, role) VALUES ('test', 'test@example.com', 'tester')")
conn.commit()

TOOLS = [
    types.Tool(
        name="query_users",
        description="Query users table by name via SQL query (vulnerable to SQL injection)",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "User name to query"},
            },
            "required": ["name"],
        },
    ),
    types.Tool(
        name="safe_search",
        description="Safely search users table using parameterized query",
        inputSchema={
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Query term to search"},
            },
            "required": ["q"],
        },
    ),
    types.Tool(
        name="reflect_query",
        description="Echoes the query without executing against a database",
        inputSchema={
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Query to echo"},
            },
            "required": ["q"],
        },
    ),
    types.Tool(
        name="slow_query",
        description="Query database with simulated time-based SQL injection vulnerability",
        inputSchema={
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "SQL query expression"},
            },
            "required": ["q"],
        },
    ),
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    arguments = arguments or {}

    if name == "query_users":
        user_name = arguments.get("name", "")
        try:
            cur = conn.cursor()
            cur.execute(f"SELECT id, name, email, role FROM users WHERE name = '{user_name}'")
            rows = cur.fetchall()
            results = [{"id": r[0], "name": r[1], "email": r[2], "role": r[3]} for r in rows]
            return [types.TextContent(type="text", text=json.dumps(results))]
        except Exception:
            return [types.TextContent(type="text", text="[]")]

    elif name == "safe_search":
        q = arguments.get("q", "")
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, name, email, role FROM users WHERE name = ?", (q,))
            rows = cur.fetchall()
            results = [{"id": r[0], "name": r[1], "email": r[2], "role": r[3]} for r in rows]
            return [types.TextContent(type="text", text=json.dumps(results))]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    elif name == "reflect_query":
        q = arguments.get("q", "")
        return [types.TextContent(type="text", text=f"Echo query: {q}")]

    elif name == "slow_query":
        q = arguments.get("q", "")
        # Simulates time-based vulnerability: sleeps if payload contains sleep function
        m = re.search(
            r"(?:pg_sleep|sleep|dbms_lock\.sleep)\s*\(\s*['\"]?(\d+)|waitfor\s+delay\s+['\"]?0:0:(\d+)",
            q,
            re.I,
        )
        if m:
            dur = int(m.group(1) or m.group(2) or 5)
            await asyncio.sleep(dur)
            return [types.TextContent(type="text", text=f"Query completed in {dur}s")]

        return [types.TextContent(type="text", text="Query completed")]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
