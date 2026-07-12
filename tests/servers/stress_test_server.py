#!/usr/bin/env python3
"""
mcpsec Stress Test Server - Comprehensive Vulnerability Test Suite

This server contains:
- TRUE POSITIVES: Real vulnerabilities that MUST be detected
- FALSE POSITIVE TRAPS: Safe code that looks dangerous but isn't
- EDGE CASES: Tricky scenarios to test scanner limits

Run with: python mcpsec_stress_test_server.py
Scan with: mcpsec scan --stdio "python mcpsec_stress_test_server.py"

Expected results after fixes:
- TRUE POSITIVES: All flagged as CRITICAL/HIGH CONFIRMED
- FALSE POSITIVE TRAPS: NOT flagged or flagged as SAFE
- EDGE CASES: Varies - tests scanner's limits
"""

import asyncio
import os
import sqlite3
import subprocess
import json
import pickle
import base64
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server.stdio import stdio_server

server = Server("mcpsec-stress-test")

# In-memory SQLite for SQL injection tests
db_conn = sqlite3.connect(":memory:")
db_cursor = db_conn.cursor()
db_cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
db_cursor.execute("INSERT INTO users VALUES (1, 'admin', 'supersecret123', 'admin')")
db_cursor.execute("INSERT INTO users VALUES (2, 'user', 'password', 'user')")
db_cursor.execute("CREATE TABLE secrets (id INTEGER, secret TEXT)")
db_cursor.execute("INSERT INTO secrets VALUES (1, 'FLAG{sql_injection_works}')")
db_conn.commit()

# Allowed directory for path traversal tests (cross-platform)
import tempfile
ALLOWED_DIR = os.path.join(tempfile.gettempdir(), "mcpsec_test")
os.makedirs(ALLOWED_DIR, exist_ok=True)

# Create a test file
with open(os.path.join(ALLOWED_DIR, "allowed_file.txt"), "w") as f:
    f.write("This file is allowed to be read.")

# Simple memory store for RAG poisoning test
memory_store = {}

@server.list_tools()
async def handle_list_tools():
    return [
        # ============================================
        # TRUE POSITIVES - Real Vulnerabilities
        # ============================================
        
        # TP-1: SQL Injection (Classic)
        types.Tool(
            name="tp_sql_login",
            description="Authenticate user against database. TRUE POSITIVE: Classic SQL injection via string concatenation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                },
                "required": ["username", "password"],
            },
        ),
        
        # TP-2: SQL Injection (UNION-based)
        types.Tool(
            name="tp_sql_search",
            description="Search users by name. TRUE POSITIVE: UNION-based SQL injection possible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term"},
                },
                "required": ["query"],
            },
        ),
        
        # TP-3: Command Injection (Direct)
        types.Tool(
            name="tp_cmd_ping",
            description="Ping a host to check connectivity. TRUE POSITIVE: Direct command injection via shell=True.",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                },
                "required": ["host"],
            },
        ),
        
        # TP-4: Command Injection (Indirect via eval)
        types.Tool(
            name="tp_eval_calculator",
            description="Evaluate a mathematical expression. TRUE POSITIVE: eval() on user input.",
            inputSchema={
                "type": "object",
                "properties": {
                    "expression": {"type": "string"},
                },
                "required": ["expression"],
            },
        ),
        
        # TP-5: Path Traversal (No validation)
        types.Tool(
            name="tp_path_read_file",
            description="Read a file from the server. TRUE POSITIVE: No path validation, direct traversal possible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                },
                "required": ["filename"],
            },
        ),
        
        # TP-6: SSRF (Server-Side Request Forgery)
        types.Tool(
            name="tp_ssrf_fetch",
            description="Fetch content from a URL. TRUE POSITIVE: No URL validation, SSRF to internal services possible.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
            },
        ),
        
        # TP-7: Insecure Deserialization (Pickle)
        types.Tool(
            name="tp_deserialize_data",
            description="Load serialized data. TRUE POSITIVE: Pickle deserialization of untrusted input.",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Base64-encoded serialized data"},
                },
                "required": ["data"],
            },
        ),
        
        # TP-8: IDOR (Insecure Direct Object Reference)
        types.Tool(
            name="tp_idor_get_user",
            description="Get user details by ID. TRUE POSITIVE: No authorization check, any user can access any profile.",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "integer"},
                },
                "required": ["user_id"],
            },
        ),
        
        # TP-9: Hardcoded Credentials
        types.Tool(
            name="tp_admin_login",
            description="Admin authentication endpoint. TRUE POSITIVE: Hardcoded credentials in source.",
            inputSchema={
                "type": "object",
                "properties": {
                    "password": {"type": "string"},
                },
                "required": ["password"],
            },
        ),
        
        # TP-10: Information Disclosure
        types.Tool(
            name="tp_debug_info",
            description="Get debug information. TRUE POSITIVE: Exposes sensitive environment variables and paths.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        
        # ============================================
        # FALSE POSITIVE TRAPS - Safe Code
        # ============================================
        
        # FP-1: SQL with Parameterized Queries (SAFE)
        types.Tool(
            name="fp_sql_safe_login",
            description="Secure authentication with parameterized queries. FALSE POSITIVE TRAP: Should NOT be flagged.",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                },
                "required": ["username", "password"],
            },
        ),
        
        # FP-2: Command with Allowlist (SAFE)
        types.Tool(
            name="fp_cmd_safe_status",
            description="Get system status using allowlisted commands only. FALSE POSITIVE TRAP: Should NOT be flagged as command injection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "metric": {"type": "string", "enum": ["cpu", "memory", "disk"]},
                },
                "required": ["metric"],
            },
        ),
        
        # FP-3: Path with Proper Validation (SAFE)
        types.Tool(
            name="fp_path_safe_read",
            description="Read file with proper path validation. FALSE POSITIVE TRAP: Uses realpath() and commonpath() checks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                },
                "required": ["filename"],
            },
        ),
        
        # FP-4: Input Sanitization Present (SAFE)
        types.Tool(
            name="fp_sanitized_echo",
            description="Echo input after sanitization. FALSE POSITIVE TRAP: Input is properly escaped.",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                },
                "required": ["message"],
            },
        ),
        
        # FP-5: Schema Validation Rejects Bad Input (SAFE)
        types.Tool(
            name="fp_strict_schema",
            description="Tool with strict schema validation. FALSE POSITIVE TRAP: Invalid input rejected at schema level.",
            inputSchema={
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "minimum": 1, "maximum": 100},
                    "name": {"type": "string", "pattern": "^[a-zA-Z0-9_]+$"},
                },
                "required": ["count", "name"],
            },
        ),
        
        # ============================================
        # EDGE CASES - Test Scanner Limits
        # ============================================
        
        # EC-1: Second-Order SQL Injection
        types.Tool(
            name="ec_second_order_sql",
            description="Store data now, vulnerable query later. EDGE CASE: Second-order SQL injection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string"},
                },
                "required": ["data"],
            },
        ),
        
        # EC-2: Blind Command Injection (Time-based)
        types.Tool(
            name="ec_blind_cmd",
            description="Process data with potential blind command injection. EDGE CASE: No output, time-based detection only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string"},
                },
                "required": ["data"],
            },
        ),
        
        # EC-3: Indirect Prompt Injection Vector
        types.Tool(
            name="ec_write_memory",
            description="Write data to agent memory. EDGE CASE: RAG poisoning vector when combined with read_memory.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["key", "value"],
            },
        ),
        
        # EC-4: Read from potentially poisoned memory
        types.Tool(
            name="ec_read_memory",
            description="Read data from agent memory. EDGE CASE: Combined with write_memory creates RAG poisoning chain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                },
                "required": ["key"],
            },
        ),
        
        # EC-5: Race Condition (TOCTOU)
        types.Tool(
            name="ec_toctou_file",
            description="Check file then read it. EDGE CASE: Time-of-check to time-of-use race condition.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filename": {"type": "string"},
                },
                "required": ["filename"],
            },
        ),
        
        # EC-6: Prototype Pollution (if using JS backend)
        types.Tool(
            name="ec_merge_config",
            description="Deep merge configuration objects. EDGE CASE: Prototype pollution in JS environments.",
            inputSchema={
                "type": "object",
                "properties": {
                    "config": {"type": "object"},
                },
                "required": ["config"],
            },
        ),
        
        # EC-7: XML External Entity (XXE)
        types.Tool(
            name="ec_parse_xml",
            description="Parse XML document. EDGE CASE: XXE injection if using vulnerable parser.",
            inputSchema={
                "type": "object",
                "properties": {
                    "xml": {"type": "string"},
                },
                "required": ["xml"],
            },
        ),
        
        # EC-8: YAML Deserialization
        types.Tool(
            name="ec_parse_yaml",
            description="Parse YAML configuration. EDGE CASE: YAML deserialization attack if using unsafe loader.",
            inputSchema={
                "type": "object",
                "properties": {
                    "yaml_content": {"type": "string"},
                },
                "required": ["yaml_content"],
            },
        ),
        
        # EC-9: Log Injection
        types.Tool(
            name="ec_log_event",
            description="Log an event message. EDGE CASE: Log injection/forging attacks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                },
                "required": ["message"],
            },
        ),
        
        # EC-10: Template Injection (SSTI)
        types.Tool(
            name="ec_render_template",
            description="Render a template with user data. EDGE CASE: Server-side template injection.",
            inputSchema={
                "type": "object",
                "properties": {
                    "template": {"type": "string"},
                    "data": {"type": "object"},
                },
                "required": ["template"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    args = arguments or {}
    
    # ============================================
    # TRUE POSITIVE IMPLEMENTATIONS
    # ============================================
    
    if name == "tp_sql_login":
        # VULNERABLE: String concatenation in SQL
        username = args.get("username", "")
        password = args.get("password", "")
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            db_cursor.execute(query)
            result = db_cursor.fetchall()
            if result:
                return [types.TextContent(type="text", text=f"Login successful! User: {result}")]
            return [types.TextContent(type="text", text="Invalid credentials")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"SQLITE_ERROR: {e}")]
    
    if name == "tp_sql_search":
        # VULNERABLE: UNION-based SQL injection
        query_term = args.get("query", "")
        sql = f"SELECT username, role FROM users WHERE username LIKE '%{query_term}%'"
        try:
            db_cursor.execute(sql)
            result = db_cursor.fetchall()
            return [types.TextContent(type="text", text=f"Results: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"SQLITE_ERROR: {e}")]
    
    if name == "tp_cmd_ping":
        # VULNERABLE: Command injection via shell=True
        # Note: Using ping -n on Windows, -c on Linux
        host = args.get("host", "")
        try:
            import sys
            ping_flag = "-n" if sys.platform == "win32" else "-c"
            result = subprocess.run(
                f"ping {ping_flag} 1 {host}",
                shell=True,
                capture_output=True,  # Captures stdout/stderr, doesn't pollute stdio
                text=True,
                timeout=5,
                stdin=subprocess.DEVNULL  # Don't inherit stdin
            )
            return [types.TextContent(type="text", text=f"Output: {result.stdout}\nErrors: {result.stderr}")]
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text="Command timed out")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]
    
    if name == "tp_eval_calculator":
        # VULNERABLE: eval() on user input
        expression = args.get("expression", "")
        try:
            result = eval(expression)
            return [types.TextContent(type="text", text=f"Result: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]
    
    if name == "tp_path_read_file":
        # VULNERABLE: No path validation
        filename = args.get("filename", "")
        try:
            with open(filename, "r") as f:
                content = f.read()
            return [types.TextContent(type="text", text=f"Content:\n{content}")]
        except FileNotFoundError:
            return [types.TextContent(type="text", text=f"File not found: {filename}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]
    
    if name == "tp_ssrf_fetch":
        # VULNERABLE: No URL validation, SSRF possible
        import urllib.request
        url = args.get("url", "")
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                content = response.read().decode('utf-8')[:1000]
            return [types.TextContent(type="text", text=f"Fetched content:\n{content}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Fetch error: {e}")]
    
    if name == "tp_deserialize_data":
        # VULNERABLE: Pickle deserialization
        data = args.get("data", "")
        try:
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)  # DANGEROUS!
            return [types.TextContent(type="text", text=f"Deserialized: {obj}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Deserialization error: {e}")]
    
    if name == "tp_idor_get_user":
        # VULNERABLE: No authorization check
        user_id = args.get("user_id", 0)
        db_cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        result = db_cursor.fetchone()
        if result:
            return [types.TextContent(type="text", text=f"User data: id={result[0]}, username={result[1]}, password={result[2]}, role={result[3]}")]
        return [types.TextContent(type="text", text="User not found")]
    
    if name == "tp_admin_login":
        # VULNERABLE: Hardcoded credentials
        ADMIN_PASSWORD = "admin123!@#"  # Hardcoded secret
        password = args.get("password", "")
        if password == ADMIN_PASSWORD:
            return [types.TextContent(type="text", text="Admin access granted! Here's the secret: FLAG{hardcoded_creds}")]
        return [types.TextContent(type="text", text="Access denied")]
    
    if name == "tp_debug_info":
        # VULNERABLE: Information disclosure
        debug_data = {
            "env": dict(os.environ),
            "cwd": os.getcwd(),
            "user": os.getenv("USER", "unknown"),
            "path": os.getenv("PATH", ""),
            "db_connection": str(db_conn),
            "python_path": os.getenv("PYTHONPATH", ""),
        }
        return [types.TextContent(type="text", text=f"Debug info:\n{json.dumps(debug_data, indent=2)}")]
    
    # ============================================
    # FALSE POSITIVE TRAP IMPLEMENTATIONS (SAFE)
    # ============================================
    
    if name == "fp_sql_safe_login":
        # SAFE: Parameterized query
        username = args.get("username", "")
        password = args.get("password", "")
        db_cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        result = db_cursor.fetchall()
        if result:
            return [types.TextContent(type="text", text="Login successful")]
        return [types.TextContent(type="text", text="Invalid credentials")]
    
    if name == "fp_cmd_safe_status":
        # SAFE: Allowlist of commands - no user input in command
        metric = args.get("metric", "")
        import sys
        
        if sys.platform == "win32":
            allowed_commands = {
                "cpu": ["wmic", "cpu", "get", "loadpercentage"],
                "memory": ["wmic", "OS", "get", "FreePhysicalMemory"],
                "disk": ["wmic", "logicaldisk", "get", "size,freespace"],
            }
        else:
            allowed_commands = {
                "cpu": ["cat", "/proc/loadavg"],
                "memory": ["free", "-h"],
                "disk": ["df", "-h"],
            }
        
        if metric not in allowed_commands:
            return [types.TextContent(type="text", text="Invalid metric. Allowed: cpu, memory, disk")]
        
        cmd = allowed_commands[metric]
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=5,
                stdin=subprocess.DEVNULL
            )
            return [types.TextContent(type="text", text=f"Status: {result.stdout}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]
    
    if name == "fp_path_safe_read":
        # SAFE: Proper path validation
        filename = args.get("filename", "")
        
        # Construct full path and normalize
        full_path = os.path.realpath(os.path.join(ALLOWED_DIR, filename))
        
        # Check if path is within allowed directory
        if not full_path.startswith(os.path.realpath(ALLOWED_DIR)):
            return [types.TextContent(type="text", text="Access denied - path outside allowed directories")]
        
        try:
            with open(full_path, "r") as f:
                content = f.read()
            return [types.TextContent(type="text", text=f"Content:\n{content}")]
        except FileNotFoundError:
            return [types.TextContent(type="text", text=f"File not found")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]
    
    if name == "fp_sanitized_echo":
        # SAFE: Input sanitization
        import shlex
        message = args.get("message", "")
        sanitized = shlex.quote(message)  # Properly escape shell characters
        return [types.TextContent(type="text", text=f"Echo: {sanitized}")]
    
    if name == "fp_strict_schema":
        # SAFE: Schema validation handles bad input
        count = args.get("count", 1)
        name_val = args.get("name", "")
        
        # Schema already validates, but double-check
        if not isinstance(count, int) or count < 1 or count > 100:
            return [types.TextContent(type="text", text="Invalid count")]
        if not name_val.replace("_", "").isalnum():
            return [types.TextContent(type="text", text="Invalid name format")]
        
        return [types.TextContent(type="text", text=f"Processed: {name_val} x {count}")]
    
    # ============================================
    # EDGE CASE IMPLEMENTATIONS
    # ============================================
    
    if name == "ec_second_order_sql":
        # Stores data that will be used in a vulnerable query later
        data = args.get("data", "")
        # Store in a "safe" way, but it's used unsafely later
        db_cursor.execute("INSERT INTO users (username, password, role) VALUES (?, 'temp', 'user')", (data,))
        db_conn.commit()
        return [types.TextContent(type="text", text=f"Data stored: {data}")]
    
    if name == "ec_blind_cmd":
        # Blind command injection - no output returned but command executes
        data = args.get("data", "")
        try:
            # VULNERABLE: shell=True with user input
            # Output goes to /dev/null so it's "blind" - but still executes!
            import sys
            null_device = "NUL" if sys.platform == "win32" else "/dev/null"
            subprocess.run(
                f"echo {data} > {null_device}",
                shell=True,
                timeout=10,
                capture_output=True,  # Capture to prevent stdout pollution
                stdin=subprocess.DEVNULL
            )
            return [types.TextContent(type="text", text="Processing complete")]
        except subprocess.TimeoutExpired:
            return [types.TextContent(type="text", text="Processing timed out")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {e}")]
    
    if name == "ec_write_memory":
        key = args.get("key", "")
        value = args.get("value", "")
        memory_store[key] = value
        return [types.TextContent(type="text", text=f"Stored '{key}'")]
    
    if name == "ec_read_memory":
        key = args.get("key", "")
        value = memory_store.get(key, "Not found")
        # This value goes directly to LLM context - RAG poisoning vector!
        return [types.TextContent(type="text", text=f"Memory[{key}]: {value}")]
    
    if name == "ec_toctou_file":
        # TOCTOU race condition
        filename = args.get("filename", "")
        full_path = os.path.join(ALLOWED_DIR, filename)
        
        # Check (time-of-check)
        if os.path.exists(full_path) and os.path.isfile(full_path):
            # Gap here where file could be changed!
            # Use (time-of-use)
            with open(full_path, "r") as f:
                content = f.read()
            return [types.TextContent(type="text", text=f"Content: {content}")]
        return [types.TextContent(type="text", text="File not found or not a file")]
    
    if name == "ec_merge_config":
        # Prototype pollution (conceptual - Python doesn't have prototypes)
        config = args.get("config", {})
        base_config = {"debug": False, "admin": False}
        # Deep merge without validation
        base_config.update(config)
        return [types.TextContent(type="text", text=f"Config: {base_config}")]
    
    if name == "ec_parse_xml":
        # XXE vulnerability
        import xml.etree.ElementTree as ET
        xml_content = args.get("xml", "")
        try:
            # Vulnerable: doesn't disable external entities
            root = ET.fromstring(xml_content)
            return [types.TextContent(type="text", text=f"Parsed XML: {ET.tostring(root, encoding='unicode')}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"XML parse error: {e}")]
    
    if name == "ec_parse_yaml":
        # YAML deserialization
        import yaml
        yaml_content = args.get("yaml_content", "")
        try:
            # VULNERABLE: yaml.load without SafeLoader
            data = yaml.load(yaml_content, Loader=yaml.Loader)  # Unsafe!
            return [types.TextContent(type="text", text=f"Parsed YAML: {data}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"YAML parse error: {e}")]
    
    if name == "ec_log_event":
        # Log injection
        import logging
        message = args.get("message", "")
        logging.info(f"Event: {message}")  # User input directly in log
        return [types.TextContent(type="text", text="Event logged")]
    
    if name == "ec_render_template":
        # Template injection (simplified)
        template = args.get("template", "")
        data = args.get("data", {})
        try:
            # VULNERABLE: Direct format string
            result = template.format(**data)
            return [types.TextContent(type="text", text=f"Rendered: {result}")]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Template error: {e}")]
    
    return [types.TextContent(type="text", text=f"Unknown tool: {name}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="mcpsec-stress-test",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())