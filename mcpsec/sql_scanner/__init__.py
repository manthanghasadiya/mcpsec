from mcpsec.sql_scanner.detector import SQLInjectionDetector, SQLIFinding
from mcpsec.sql_scanner.fingerprint import SQLFingerprinter
from mcpsec.sql_scanner.confirmer import SQLConfirmer
from mcpsec.ui import console

class SQLScanner:
    def __init__(self, mcp_client):
        self.client = mcp_client
        self.detector = SQLInjectionDetector(mcp_client)
        self.fingerprinter = SQLFingerprinter(mcp_client)
        self.confirmer = SQLConfirmer(mcp_client)

    async def scan_server(self, profile, level: int = 1, fingerprint: bool = False) -> list[SQLIFinding]:
        """Core scanning orchestration"""
        all_findings = []
        
        for tool in profile.tools:
            # console.print(f"  [dim]Checking tool {tool.name}...[/dim]")
            if not self._is_likely_db_tool(tool):
                continue
            
            # console.print(f"  [dim]Scanning tool {tool.name}...[/dim]")
            
            # Handle different parameter schema structures
            params_schema = tool.parameters
            if not params_schema.get("properties") and params_schema.get("inputSchema"):
                params_schema = params_schema.get("inputSchema")

            tool_findings = await self.detector.scan_tool(tool.name, params_schema, level)
            
            for finding in tool_findings:
                # Confirm finding
                if await self.confirmer.confirm(finding):
                    # Fingerprint if requested
                    if fingerprint:
                        db_type = await self.fingerprinter.fingerprint(finding.tool, finding.parameter, finding.payload)
                        finding.db_type = db_type
                    
                    all_findings.append(finding)
        
        return all_findings

    def _is_likely_db_tool(self, tool) -> bool:
        """Heuristic to identify tools that likely interact with SQL databases"""
        db_keywords = ["query", "sql", "db", "database", "select", "insert", "update", "delete"]
        name_match = any(kw in tool.name.lower() for kw in db_keywords)
        desc_match = any(kw in tool.description.lower() for kw in db_keywords)
        
        # Also check parameters
        param_match = False
        props = tool.parameters.get("properties")
        params_to_check = props.keys() if props else tool.parameters.keys()
        
        for p in params_to_check:
            if any(kw in p.lower() for kw in db_keywords):
                param_match = True
                break
                
        return name_match or desc_match or param_match
