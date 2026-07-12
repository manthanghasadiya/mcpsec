#!/usr/bin/env python3
"""
mcpsec BLIND TEST SERVER - Realistic Production-Like MCP Server

This server simulates a REAL production MCP server:
- No hints in descriptions (no "TRUE POSITIVE" labels)
- Realistic tool names and descriptions
- Mix of vulnerable and secure code
- Different vulnerability patterns than stress_test_server.py
- Some subtle bugs, some obvious ones

Run: python blind_test_server.py
Scan: mcpsec scan --stdio "python blind_test_server.py"

DO NOT look at the code before scanning - test mcpsec blind!
"""

import asyncio
import os
import re
import json
import hashlib
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server.stdio import stdio_server

server = Server("acme-workspace-server")

# Initialize database
db = sqlite3.connect(":memory:")
cur = db.cursor()
cur.execute("""
    CREATE TABLE documents (
        id INTEGER PRIMARY KEY,
        owner_id INTEGER,
        title TEXT,
        content TEXT,
        classification TEXT
    )
""")
cur.execute("""
    CREATE TABLE employees (
        id INTEGER PRIMARY KEY,
        name TEXT,
        email TEXT,
        salary INTEGER,
        ssn TEXT
    )
""")
# Seed data
cur.execute("INSERT INTO documents VALUES (1, 100, 'Q4 Report', 'Revenue: $5M', 'confidential')")
cur.execute("INSERT INTO documents VALUES (2, 100, 'Public Brief', 'Company overview', 'public')")
cur.execute("INSERT INTO documents VALUES (3, 200, 'HR Policy', 'Internal policies', 'internal')")
cur.execute("INSERT INTO documents VALUES (4, 200, 'Salary Matrix', 'Executive compensation', 'restricted')")
cur.execute("INSERT INTO employees VALUES (1, 'John Doe', 'john@acme.com', 150000, '123-45-6789')")
cur.execute("INSERT INTO employees VALUES (2, 'Jane Smith', 'jane@acme.com', 180000, '987-65-4321')")
db.commit()

# Config store
config_store = {}
note_store = {}


@server.list_tools()
async def handle_list_tools():
    return [
        # ============================================
        # TOOL SET 1: Document Management
        # ============================================
        types.Tool(
            name="search_documents",
            description="Search company documents by keyword. Returns matching document titles and snippets.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keyword": {"type": "string", "description": "Search keyword"},
                    "include_content": {"type": "boolean", "default": False}
                },
                "required": ["keyword"],
            },
        ),
        types.Tool(
            name="get_document",
            description="Retrieve a document by its ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "doc_id": {"type": "integer", "description": "Document ID"}
                },
                "required": ["doc_id"],
            },
        ),
        types.Tool(
            name="export_document",
            description="Export a document to a specified format and location.",
            inputSchema={
                "type": "object",
                "properties": {
                    "doc_id": {"type": "integer"},
                    "format": {"type": "string", "enum": ["pdf", "docx", "txt"]},
                    "output_path": {"type": "string"}
                },
                "required": ["doc_id", "format", "output_path"],
            },
        ),
        
        # ============================================
        # TOOL SET 2: Employee Directory
        # ============================================
        types.Tool(
            name="lookup_employee",
            description="Look up employee information by name or email.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Name or email to search"}
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="get_org_chart",
            description="Get organizational chart data as JSON.",
            inputSchema={
                "type": "object",
                "properties": {
                    "department": {"type": "string", "description": "Department name"}
                },
                "required": ["department"],
            },
        ),
        
        # ============================================
        # TOOL SET 3: System Utilities
        # ============================================
        types.Tool(
            name="check_service_status",
            description="Check if a service is running on a given host.",
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {"type": "string"},
                    "host": {"type": "string", "default": "localhost"}
                },
                "required": ["service_name"],
            },
        ),
        types.Tool(
            name="run_diagnostics",
            description="Run system diagnostics and return results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_type": {"type": "string", "enum": ["network", "disk", "memory"]},
                    "verbose": {"type": "boolean", "default": False}
                },
                "required": ["test_type"],
            },
        ),
        types.Tool(
            name="fetch_remote_config",
            description="Fetch configuration from a remote endpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "config_url": {"type": "string", "description": "URL to fetch config from"}
                },
                "required": ["config_url"],
            },
        ),
        
        # ============================================
        # TOOL SET 4: Notes & Memory
        # ============================================
        types.Tool(
            name="save_note",
            description="Save a note for later reference.",
            inputSchema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string"}
                },
                "required": ["title", "content"],
            },
        ),
        types.Tool(
            name="get_notes",
            description="Retrieve all saved notes.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        
        # ============================================
        # TOOL SET 5: Data Processing
        # ============================================
        types.Tool(
            name="parse_config",
            description="Parse a configuration string in various formats.",
            inputSchema={
                "type": "object",
                "properties": {
                    "config_data": {"type": "string"},
                    "format": {"type": "string", "enum": ["json", "xml", "ini"]}
                },
                "required": ["config_data", "format"],
            },
        ),
        types.Tool(
            name="transform_data",
            description="Apply a transformation expression to data.",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "object"},
                    "expression": {"type": "string", "description": "Transformation expression"}
                },
                "required": ["data", "expression"],
            },
        ),
        types.Tool(
            name="calculate_metrics",
            description="Calculate business metrics from input parameters.",
            inputSchema={
                "type": "object",
                "properties": {
                    "formula": {"type": "string", "description": "Metric formula"},
                    "values": {"type": "object"}
                },
                "required": ["formula", "values"],
            },
        ),
        
        # ============================================
        # TOOL SET 6: File Operations
        # ============================================
        types.Tool(
            name="read_workspace_file",
            description="Read a file from the workspace directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string"}
                },
                "required": ["filename"],
            },
        ),
        types.Tool(
            name="list_workspace",
            description="List files in the workspace directory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "."}
                },
            },
        ),
        types.Tool(
            name="download_attachment",
            description="Download an attachment from a URL to workspace.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "filename": {"type": "string"}
                },
                "required": ["url", "filename"],
            },
        ),
        
        # ============================================
        # TOOL SET 7: Authentication & Security
        # ============================================
        types.Tool(
            name="verify_token",
            description="Verify an authentication token.",
            inputSchema={
                "type": "object",
                "properties": {
                    "token": {"type": "string"}
                },
                "required": ["token"],
            },
        ),
        types.Tool(
            name="generate_report",
            description="Generate a formatted report from template.",
            inputSchema={
                "type": "object",
                "properties": {
                    "template_name": {"type": "string"},
                    "params": {"type": "object"}
                },
                "required": ["template_name"],
            },
        ),
        types.Tool(
            name="get_system_info",
            description="Get current system information.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    
    # ============================================
    # DOCUMENT MANAGEMENT
    # ============================================
    
    if name == "search_documents":
        keyword = args.get("keyword", "")
        include_content = args.get("include_content", False)
        
        # VULNERABLE: SQL injection via string formatting
        if include_content:
            query = f"SELECT id, title, content FROM documents WHERE title LIKE '%{keyword}%' OR content LIKE '%{keyword}%'"
        else:
            query = f"SELECT id, title FROM documents WHERE title LIKE '%{keyword}%'"
        
        try:
            cur.execute(query)
            results = cur.fetchall()
            return [types.TextContent(type="text", text=f"Found {len(results)} documents: {results}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Search error: {e}")]
    
    if name == "get_document":
        doc_id = args.get("doc_id", 0)
        # VULNERABLE: IDOR - no authorization check, returns all fields including classification
        cur.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
        doc = cur.fetchone()
        if doc:
            return [types.TextContent(type="text", text=f"Document: id={doc[0]}, owner={doc[1]}, title={doc[2]}, content={doc[3]}, classification={doc[4]}")]
        return [types.TextContent(type="text", text="Document not found")]
    
    if name == "export_document":
        doc_id = args.get("doc_id", 0)
        fmt = args.get("format", "txt")
        output_path = args.get("output_path", "")
        
        # VULNERABLE: Path traversal in output_path - no validation
        cur.execute("SELECT title, content FROM documents WHERE id = ?", (doc_id,))
        doc = cur.fetchone()
        if doc:
            try:
                # Dangerous: writes to arbitrary path
                with open(output_path, "w") as f:
                    f.write(f"Title: {doc[0]}\n\nContent: {doc[1]}")
                return [types.TextContent(type="text", text=f"Exported to {output_path}")]
            except Exception as e:
                return [types.TextContent(type="text", text=f"Export failed: {e}")]
        return [types.TextContent(type="text", text="Document not found")]
    
    # ============================================
    # EMPLOYEE DIRECTORY
    # ============================================
    
    if name == "lookup_employee":
        query = args.get("query", "")
        
        # VULNERABLE: SQL injection AND info disclosure (returns SSN!)
        sql = f"SELECT id, name, email, salary, ssn FROM employees WHERE name LIKE '%{query}%' OR email LIKE '%{query}%'"
        try:
            cur.execute(sql)
            results = cur.fetchall()
            # Returns sensitive data including SSN and salary
            return [types.TextContent(type="text", text=f"Employees found: {results}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Database error: {e}")]
    
    if name == "get_org_chart":
        department = args.get("department", "")
        # SAFE: Hardcoded response, no injection possible
        org_data = {
            "engineering": {"head": "CTO", "teams": ["backend", "frontend", "devops"]},
            "sales": {"head": "VP Sales", "teams": ["enterprise", "smb"]},
        }
        return [types.TextContent(type="text", text=json.dumps(org_data.get(department.lower(), {})))]
    
    # ============================================
    # SYSTEM UTILITIES
    # ============================================
    
    if name == "check_service_status":
        service = args.get("service_name", "")
        host = args.get("host", "localhost")
        
        # VULNERABLE: Command injection via host parameter
        try:
            import sys
            if sys.platform == "win32":
                cmd = f"ping -n 1 {host}"
            else:
                cmd = f"ping -c 1 {host}"
            
            result = subprocess.run(
                cmd,
                shell=True,  # VULNERABLE!
                capture_output=True,
                text=True,
                timeout=5,
                stdin=subprocess.DEVNULL
            )
            return [types.TextContent(type="text", text=f"Service check for {service} on {host}:\n{result.stdout}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Check failed: {e}")]
    
    if name == "run_diagnostics":
        test_type = args.get("test_type", "")
        verbose = args.get("verbose", False)
        
        # SAFE: Uses allowlist, no user input in command
        allowed_tests = {
            "network": ["ipconfig" if os.name == "nt" else "ifconfig"],
            "disk": ["wmic" if os.name == "nt" else "df", "-h"] if os.name != "nt" else ["wmic", "diskdrive", "get", "size"],
            "memory": ["wmic" if os.name == "nt" else "free", "-m"] if os.name != "nt" else ["wmic", "OS", "get", "FreePhysicalMemory"],
        }
        
        if test_type not in allowed_tests:
            return [types.TextContent(type="text", text=f"Invalid test type. Allowed: {list(allowed_tests.keys())}")]
        
        try:
            result = subprocess.run(
                allowed_tests[test_type],
                capture_output=True,
                text=True,
                timeout=10,
                stdin=subprocess.DEVNULL
            )
            return [types.TextContent(type="text", text=f"Diagnostics ({test_type}):\n{result.stdout}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Diagnostics failed: {e}")]
    
    if name == "fetch_remote_config":
        config_url = args.get("config_url", "")
        
        # VULNERABLE: SSRF - no URL validation
        try:
            with urllib.request.urlopen(config_url, timeout=5) as response:
                content = response.read().decode('utf-8')[:2000]
            return [types.TextContent(type="text", text=f"Config fetched:\n{content}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Fetch failed: {e}")]
    
    # ============================================
    # NOTES & MEMORY
    # ============================================
    
    if name == "save_note":
        title = args.get("title", "")
        content = args.get("content", "")
        # Stores note - potential RAG poisoning vector
        note_store[title] = {"content": content, "timestamp": datetime.now().isoformat()}
        return [types.TextContent(type="text", text=f"Note '{title}' saved.")]
    
    if name == "get_notes":
        # Returns all notes - completes RAG poisoning chain
        if not note_store:
            return [types.TextContent(type="text", text="No notes saved.")]
        notes_text = "\n".join([f"- {k}: {v['content']}" for k, v in note_store.items()])
        return [types.TextContent(type="text", text=f"Your notes:\n{notes_text}")]
    
    # ============================================
    # DATA PROCESSING
    # ============================================
    
    if name == "parse_config":
        config_data = args.get("config_data", "")
        fmt = args.get("format", "json")
        
        try:
            if fmt == "json":
                # SAFE: json.loads is safe
                parsed = json.loads(config_data)
                return [types.TextContent(type="text", text=f"Parsed JSON: {parsed}")]
            
            elif fmt == "xml":
                # VULNERABLE: XXE possible with default parser
                root = ET.fromstring(config_data)
                return [types.TextContent(type="text", text=f"Parsed XML: {ET.tostring(root, encoding='unicode')}")]
            
            elif fmt == "ini":
                # SAFE: Simple regex parsing
                config = {}
                for line in config_data.split('\n'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        config[k.strip()] = v.strip()
                return [types.TextContent(type="text", text=f"Parsed INI: {config}")]
        
        except Exception as e:
            return [types.TextContent(type="text", text=f"Parse error: {e}")]
    
    if name == "transform_data":
        data = args.get("data", {})
        expression = args.get("expression", "")
        
        # VULNERABLE: eval() on user expression
        try:
            result = eval(expression, {"data": data, "__builtins__": {}})
            return [types.TextContent(type="text", text=f"Result: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Transform error: {e}")]
    
    if name == "calculate_metrics":
        formula = args.get("formula", "")
        values = args.get("values", {})
        
        # VULNERABLE: eval() on formula
        try:
            result = eval(formula, {"__builtins__": {"sum": sum, "len": len, "max": max, "min": min}}, values)
            return [types.TextContent(type="text", text=f"Metric result: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Calculation error: {e}")]
    
    # ============================================
    # FILE OPERATIONS
    # ============================================
    
    if name == "read_workspace_file":
        filename = args.get("filename", "")
        
        # VULNERABLE: Path traversal - insufficient validation
        # Tries to block ../ but can be bypassed
        if ".." in filename:
            return [types.TextContent(type="text", text="Invalid path: directory traversal not allowed")]
        
        try:
            # Still vulnerable: absolute paths, ...\, URL encoding, etc.
            with open(filename, "r") as f:
                content = f.read()
            return [types.TextContent(type="text", text=f"File content:\n{content}")]
        except FileNotFoundError:
            return [types.TextContent(type="text", text=f"File not found: {filename}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Read error: {e}")]
    
    if name == "list_workspace":
        path = args.get("path", ".")
        
        # SAFE: Uses os.listdir with error handling
        try:
            # Only allows listing, not reading
            files = os.listdir(path)
            return [types.TextContent(type="text", text=f"Files in {path}: {files}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"List error: {e}")]
    
    if name == "download_attachment":
        url = args.get("url", "")
        filename = args.get("filename", "")
        
        # VULNERABLE: SSRF + arbitrary file write
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                content = response.read()
            
            # No path validation on filename
            with open(filename, "wb") as f:
                f.write(content)
            
            return [types.TextContent(type="text", text=f"Downloaded {len(content)} bytes to {filename}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Download failed: {e}")]
    
    # ============================================
    # AUTHENTICATION & SECURITY
    # ============================================
    
    if name == "verify_token":
        token = args.get("token", "")
        
        # VULNERABLE: Hardcoded secret + timing attack possible
        MASTER_TOKEN = "acme_master_token_2024_xyz"  # Hardcoded credential!
        
        if token == MASTER_TOKEN:
            return [types.TextContent(type="text", text="Token valid. Access granted.")]
        
        # Simple token validation
        if len(token) > 20 and token.startswith("acme_"):
            return [types.TextContent(type="text", text="Token format valid, but not authorized.")]
        
        return [types.TextContent(type="text", text="Invalid token.")]
    
    if name == "generate_report":
        template_name = args.get("template_name", "")
        params = args.get("params", {})
        
        # VULNERABLE: Template injection via format string
        templates = {
            "summary": "Report Summary\n==============\nGenerated: {date}\nData: {data}",
            "detailed": "Detailed Report\n===============\nParams: {params}\nAnalysis: {analysis}",
        }
        
        if template_name not in templates:
            return [types.TextContent(type="text", text=f"Unknown template. Available: {list(templates.keys())}")]
        
        try:
            # User params go directly into format()
            report = templates[template_name].format(**params)
            return [types.TextContent(type="text", text=report)]
        except KeyError as e:
            return [types.TextContent(type="text", text=f"Missing parameter: {e}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Report generation failed: {e}")]
    
    if name == "get_system_info":
        # VULNERABLE: Information disclosure
        info = {
            "hostname": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "unknown")),
            "user": os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
            "home": os.environ.get("USERPROFILE", os.environ.get("HOME", "unknown")),
            "path": os.environ.get("PATH", "")[:200],
            "temp": os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp")),
            "cwd": os.getcwd(),
            "python": os.sys.executable,
        }
        return [types.TextContent(type="text", text=f"System Info:\n{json.dumps(info, indent=2)}")]
    
    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="acme-workspace-server",
                server_version="2.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())