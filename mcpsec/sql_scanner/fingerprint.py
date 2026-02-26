import re
from typing import Optional
from mcpsec.sql_scanner.payloads import PAYLOADS

class SQLFingerprinter:
    def __init__(self, mcp_client):
        self.client = mcp_client

    async def fingerprint(self, tool_name: str, param_name: str, baseline_payload: str) -> Optional[str]:
        """Identify the database type based on payloads and error signatures"""
        
        # 1. Try DB-specific function payloads
        for db_type, payloads in PAYLOADS["fingerprint"].items():
            for payload in payloads:
                try:
                    # We often need to adapt the payload based on how the baseline was successful
                    # For simplicity in v1, we test them as is (assuming UNION or concatenated)
                    response = await self.client.call_tool(tool_name, {param_name: payload})
                    response_text = str(response).lower()
                    
                    if self._verify_fingerprint_response(db_type, response_text):
                        return db_type
                except:
                    continue
        
        return None

    def _verify_fingerprint_response(self, db_type: str, response: str) -> bool:
        """Verify if the response matches expected fingerprint indicators"""
        indicators = {
            "mysql": [r"\d+\.\d+\.\d+", r"mysql", r"mariadb"],
            "postgres": [r"postgresql", r"pg_"],
            "mssql": [r"microsoft sql server", r"sqlexpress"],
            "sqlite": [r"\d+\.\d+\.\d+", r"sqlite"],
        }
        
        patterns = indicators.get(db_type, [])
        for pattern in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return True
        return False
