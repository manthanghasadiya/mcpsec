import time
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from mcpsec.sql_scanner.payloads import PAYLOADS

@dataclass
class SQLIFinding:
    tool: str
    parameter: str
    payload: str
    technique: str
    evidence: str
    db_type: Optional[str] = None

@dataclass
class TestResult:
    is_vulnerable: bool
    technique: Optional[str] = None
    evidence: Optional[str] = None

# SQL error signatures for different database types
SQL_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
    ],
    "postgres": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PSQLException",
    ],
    "mssql": [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlClient\.",
        r"Unclosed quotation mark",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite",
        r"SQLITE_ERROR",
    ],
    "generic": [
        r"SQL syntax",
        r"syntax error",
        r"unexpected end of SQL",
        r"quoted string not properly terminated",
        r"unterminated.*string",
    ],
}

class SQLInjectionDetector:
    def __init__(self, mcp_client):
        self.client = mcp_client
        self.vulnerable_tools = []
    
    async def scan_tool(self, tool_name: str, tool_schema: dict, level: int = 1) -> List[SQLIFinding]:
        """Scan a single tool for SQL injection"""
        findings = []
        
        # Find string parameters that might be SQL-injectable
        injectable_params = self._find_injectable_params(tool_schema)
        
        for param in injectable_params:
            # Categories to test based on level
            categories = ["error_based", "time_based"]
            if level >= 2:
                categories.extend(["boolean_based", "stacked_queries"])
            
            for category in categories:
                payloads = PAYLOADS["detection"].get(category, [])
                for payload in payloads:
                    result = await self._test_payload(tool_name, param, payload)
                    if result.is_vulnerable:
                        findings.append(SQLIFinding(
                            tool=tool_name,
                            parameter=param,
                            payload=payload,
                            technique=category,
                            evidence=result.evidence or "",
                        ))
                        break  # Found vuln in this category, move to next param/category
        
        return findings
    
    def _find_injectable_params(self, schema: dict) -> List[str]:
        """Find parameters likely to be SQL-injectable"""
        injectable = []
        
        # Determine if we have a full schema or the simplified mcpsec format
        props = schema.get("properties")
        if props:
            # Full JSON schema format
            for param_name, param_schema in props.items():
                if isinstance(param_schema, dict):
                    param_type = param_schema.get("type", "")
                    param_desc = param_schema.get("description", "").lower()
                    
                    if param_type == "string" or not param_type:
                        if self._is_likely_sql_param(param_name, param_desc):
                            injectable.append(param_name)
        else:
            # Simplified format: {"param_name": "param_type"}
            for param_name, param_type in schema.items():
                if isinstance(param_type, str):
                    if param_type == "string" or param_type == "any":
                        if self._is_likely_sql_param(param_name, ""):
                            injectable.append(param_name)
        
        # Fallback: if no params identified but it's small, include all string/any
        if not injectable and len(schema) < 5:
             for param_name, param_info in (props.items() if props else schema.items()):
                 injectable.append(param_name)

        return injectable

    def _is_likely_sql_param(self, name: str, description: str) -> bool:
        sql_keywords = ["query", "sql", "where", "filter", "search", 
                       "id", "name", "table", "column", "order", "limit",
                       "database", "db", "select", "from"]
        name_lower = name.lower()
        desc_lower = description.lower()
        return any(kw in name_lower for kw in sql_keywords) or any(kw in desc_lower for kw in sql_keywords)
    
    async def _test_payload(self, tool: str, param: str, payload: str) -> TestResult:
        """Send payload and analyze response"""
        try:
            # Build arguments with payload
            args = {param: payload}
            
            # Call the tool
            start_time = time.time()
            response = await self.client.call_tool(tool, args)
            elapsed = time.time() - start_time
            
            # Analyze response for SQL injection indicators
            result = self._analyze_response(response, elapsed, payload)
            return result
            
        except Exception as e:
            return self._analyze_error(e, payload)
    
    def _analyze_response(self, response, elapsed, payload) -> TestResult:
        """Check if response indicates SQL injection"""
        response_text = ""
        
        # Determine response text based on MCP response structure
        if hasattr(response, 'content') and response.content:
             for block in response.content:
                 if hasattr(block, 'text'):
                     response_text += str(block.text)
                 elif hasattr(block, 'data'): # Binary content
                     pass
        elif isinstance(response, list):
             for block in response:
                 if hasattr(block, 'text'):
                     response_text += str(block.text)
        else:
             response_text = str(response)
        
        response_text_lower = response_text.lower()
        
        # Error-based detection
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return TestResult(is_vulnerable=True, 
                                     technique="error_based",
                                     evidence=f"SQL error signature ({db_type}): {pattern}")
        
        # Time-based detection
        if "sleep" in payload.lower() or "waitfor" in payload.lower():
            if elapsed > 4.5:  # Expected 5 second delay
                return TestResult(is_vulnerable=True,
                                 technique="time_based", 
                                 evidence=f"Response delayed {elapsed:.1f}s")
        
        return TestResult(is_vulnerable=False)

    def _analyze_error(self, error, payload) -> TestResult:
        """Analyze tool call errors for SQL injection indicators"""
        error_text = str(error).lower()
        
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_text, re.IGNORECASE):
                    return TestResult(is_vulnerable=True, 
                                     technique="error_based",
                                     evidence=f"SQL error signature in exception ({db_type}): {pattern}")
        
        return TestResult(is_vulnerable=False)
