import asyncio
import sqlite3
from mcp.server import Server
import mcp.types as types

try:
    from compat import register_handlers, run_server
except ImportError:
    from tests.servers.compat import register_handlers, run_server

server = Server("vulnerable-db-server")

TOOLS = [
    types.Tool(
        name="query_db",
        description="Execute a SQL query on the database",
        inputSchema={
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "The SQL query to execute"},
            },
            "required": ["sql"],
        },
    )
]


async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    if name == "query_db":
        sql = (arguments or {}).get("sql", "")
        try:
            # VULNERABLE: Direct string concatenation
            conn = sqlite3.connect(":memory:")
            cursor = conn.cursor()
            # We don't actually need real data for some tests,
            # but let's make it look like a real DB
            cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")
            cursor.execute("INSERT INTO users VALUES (1, 'Admin')")

            # This is where the injection happens
            cursor.execute(f"SELECT * FROM users WHERE name = '{sql}'")
            results = cursor.fetchall()
            return [types.TextContent(type="text", text=str(results))]
        except Exception as e:
            # The characteristic SQL error response
            return [types.TextContent(type="text", text=f"SQLITE_ERROR: {str(e)}")]

    raise ValueError(f"Unknown tool: {name}")


register_handlers(server, TOOLS, handle_call_tool)


async def main():
    await run_server(server)


if __name__ == "__main__":
    asyncio.run(main())
