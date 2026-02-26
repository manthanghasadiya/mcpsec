import sys
import sqlite3
import json
import asyncio
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server.stdio import stdio_server

server = Server("vulnerable-db-server")

@server.list_tools()
async def handle_list_tools():
    return [
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

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    if name == "query_db":
        sql = arguments.get("sql", "")
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

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="vulnerable-db-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
