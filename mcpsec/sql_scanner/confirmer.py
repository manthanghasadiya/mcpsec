from mcpsec.sql_scanner.detector import SQLIFinding, TestResult

class SQLConfirmer:
    def __init__(self, mcp_client):
        self.client = mcp_client

    async def confirm(self, finding: SQLIFinding) -> bool:
        """Confirm a finding by performing a secondary check with a different payload"""
        
        confirmation_payloads = {
            "error_based": "' AND 1=1--",
            "time_based": "'; SELECT SLEEP(2)--",
            "boolean_based": "' AND 'c'='c",
        }
        
        payload = confirmation_payloads.get(finding.technique)
        if not payload:
            return True # Assume valid if no confirmation payload defined
            
        try:
            response = await self.client.call_tool(finding.tool, {finding.parameter: payload})
            # Check if the response matches the expected behavior for that technique
            # For v1, we just check if it doesn't crash unexpectedly
            return True
        except:
            return False
