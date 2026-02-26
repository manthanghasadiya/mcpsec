from dataclasses import dataclass, field
from typing import List, Dict, Set, Any, Optional
from mcpsec.models import ServerProfile, ToolInfo

TOOL_CAPABILITIES = {
    "read_fs": {
        "keywords": ["read_file", "get_file", "cat", "load", "open", "read_content"],
        "description_hints": ["read", "file content", "load file"],
        "risk": "data_access"
    },
    "write_fs": {
        "keywords": ["write_file", "save", "create_file", "put_file", "write_content"],
        "description_hints": ["write", "save", "create file"],
        "risk": "persistence"
    },
    "execute": {
        "keywords": ["execute", "exec", "run", "shell", "command", "eval", "spawn"],
        "description_hints": ["execute", "run command", "shell"],
        "risk": "code_execution"
    },
    "network_out": {
        "keywords": ["http", "fetch", "request", "send", "post", "webhook", "api_call"],
        "description_hints": ["send", "http", "request", "api"],
        "risk": "exfiltration"
    },
    "network_in": {
        "keywords": ["listen", "serve", "bind", "accept"],
        "description_hints": ["listen", "server", "incoming"],
        "risk": "backdoor"
    },
    "db_read": {
        "keywords": ["query", "select", "find", "search", "sql", "read_db"],
        "description_hints": ["query", "database", "select"],
        "risk": "data_access"
    },
    "db_write": {
        "keywords": ["insert", "update", "delete", "drop", "execute_sql", "write_db"],
        "description_hints": ["insert", "update", "modify database"],
        "risk": "data_modification"
    },
    "credentials": {
        "keywords": ["password", "secret", "key", "token", "credential", "auth"],
        "description_hints": ["password", "secret", "credential", "api key"],
        "risk": "credential_access"
    },
    "email": {
        "keywords": ["email", "send_mail", "smtp", "mail"],
        "description_hints": ["send email", "mail"],
        "risk": "exfiltration"
    },
    "cloud": {
        "keywords": ["s3", "gcs", "azure_blob", "upload", "cloud_storage"],
        "description_hints": ["cloud", "s3", "storage", "bucket"],
        "risk": "exfiltration"
    }
}

ATTACK_CHAINS = [
    {
        "id": "CHAIN-001",
        "name": "file_read_to_rce",
        "description": "File read capability combined with code execution enables reading sensitive files and executing malicious code",
        "chain": ["read_fs", "execute"],
        "severity": "CRITICAL",
        "cvss_base": 9.8,
        "mitre_attack": ["T1005", "T1059"],
        "example_attack": "Read SSH keys or config files, then execute commands using stolen credentials",
    },
    {
        "id": "CHAIN-002", 
        "name": "sql_to_exfil",
        "description": "Database access with network egress allows data theft",
        "chain": ["db_read", "network_out"],
        "severity": "HIGH",
        "cvss_base": 8.1,
        "mitre_attack": ["T1213", "T1041"],
        "example_attack": "Query sensitive data from database, exfiltrate via HTTP request",
    },
    {
        "id": "CHAIN-003",
        "name": "ssrf_to_internal",
        "description": "Network requests can pivot to internal services",
        "chain": ["network_out"],
        "severity": "HIGH",
        "cvss_base": 7.5,
        "mitre_attack": ["T1090"],
        "example_attack": "Request internal metadata endpoints (169.254.169.254) or internal services",
    },
    {
        "id": "CHAIN-004",
        "name": "credential_theft_exfil",
        "description": "Access to credentials with exfiltration path",
        "chain": ["credentials", "network_out"],
        "severity": "CRITICAL",
        "cvss_base": 9.1,
        "mitre_attack": ["T1552", "T1041"],
        "example_attack": "Read API keys or passwords, send to attacker-controlled server",
    },
    {
        "id": "CHAIN-005",
        "name": "file_write_persistence",
        "description": "File write enables persistence mechanisms",
        "chain": ["write_fs"],
        "severity": "HIGH",
        "cvss_base": 7.8,
        "mitre_attack": ["T1546"],
        "example_attack": "Write to crontab, bashrc, or startup scripts",
    },
    {
        "id": "CHAIN-006",
        "name": "full_compromise",
        "description": "Complete system access: read, write, execute, and exfiltrate",
        "chain": ["read_fs", "write_fs", "execute", "network_out"],
        "severity": "CRITICAL",
        "cvss_base": 10.0,
        "mitre_attack": ["T1005", "T1059", "T1041"],
        "example_attack": "Full control: read sensitive data, modify files, run commands, exfiltrate",
    },
    {
        "id": "CHAIN-007",
        "name": "db_to_rce",
        "description": "Database write can lead to RCE via stored procedures or file writes",
        "chain": ["db_write", "execute"],
        "severity": "CRITICAL",
        "cvss_base": 9.8,
        "mitre_attack": ["T1059"],
        "example_attack": "Write malicious stored procedure, execute via SQL",
    },
    {
        "id": "CHAIN-008",
        "name": "email_phishing",
        "description": "Email capability can be abused for phishing or spam",
        "chain": ["email"],
        "severity": "MEDIUM",
        "cvss_base": 5.4,
        "mitre_attack": ["T1566"],
        "example_attack": "Send phishing emails to arbitrary recipients",
    },
    {
        "id": "CHAIN-009",
        "name": "cloud_data_exfil",
        "description": "Cloud storage access enables large-scale data exfiltration",
        "chain": ["db_read", "cloud"],
        "severity": "HIGH",
        "cvss_base": 8.5,
        "mitre_attack": ["T1537"],
        "example_attack": "Query database, upload results to attacker's S3 bucket",
    },
    {
        "id": "CHAIN-010",
        "name": "lateral_movement",
        "description": "Network + credential access enables lateral movement",
        "chain": ["credentials", "network_out", "execute"],
        "severity": "CRITICAL",
        "cvss_base": 9.3,
        "mitre_attack": ["T1021"],
        "example_attack": "Steal credentials, connect to other systems, execute commands",
    },
]

@dataclass
class ChainFinding:
    chain_id: str
    name: str
    severity: str
    description: str
    matching_tools: Dict[str, List[str]]
    mitre_attack: List[str] = field(default_factory=list)
    example_attack: Optional[str] = None
    cvss_base: Optional[float] = None

@dataclass
class ToolChainReport:
    total_tools: int
    capabilities_found: Set[str]
    chain_findings: List[ChainFinding]
    risk_score: float

class ToolChainAnalyzer:
    def __init__(self):
        self.capabilities = TOOL_CAPABILITIES
        self.chains = ATTACK_CHAINS
    
    def analyze_server(self, profile: ServerProfile) -> ToolChainReport:
        """Analyze all tools from an MCP server for dangerous combinations"""
        tools = profile.tools
        
        # Step 1: Classify each tool's capabilities
        tool_capabilities = {}
        for tool in tools:
            caps = self._classify_tool(tool)
            if caps:
                tool_capabilities[tool.name] = caps
        
        # Step 2: Build capability graph
        server_capabilities = self._aggregate_capabilities(tool_capabilities)
        
        # Step 3: Check for dangerous chains
        findings = []
        for chain in self.chains:
            if self._chain_matches(chain, server_capabilities):
                finding = ChainFinding(
                    chain_id=chain["id"],
                    name=chain["name"],
                    severity=chain["severity"],
                    description=chain["description"],
                    matching_tools=self._get_matching_tools(chain, tool_capabilities),
                    mitre_attack=chain.get("mitre_attack", []),
                    example_attack=chain.get("example_attack"),
                    cvss_base=chain.get("cvss_base"),
                )
                findings.append(finding)
        
        # Step 4: Calculate overall risk score
        risk_score = self._calculate_risk_score(findings)
        
        return ToolChainReport(
            total_tools=len(tools),
            capabilities_found=server_capabilities,
            chain_findings=findings,
            risk_score=risk_score,
        )
    
    def _classify_tool(self, tool: ToolInfo) -> Set[str]:
        """Classify a tool's capabilities based on name and description"""
        capabilities = set()
        
        tool_name = tool.name.lower()
        tool_desc = tool.description.lower() if tool.description else ""
        
        for cap_name, cap_def in self.capabilities.items():
            # Check keywords in tool name
            if any(kw in tool_name for kw in cap_def["keywords"]):
                capabilities.add(cap_name)
                continue
            
            # Check hints in description
            if any(hint in tool_desc for hint in cap_def["description_hints"]):
                capabilities.add(cap_name)
        
        return capabilities

    def _aggregate_capabilities(self, tool_capabilities: Dict[str, Set[str]]) -> Set[str]:
        """Flatten all capabilities across tools"""
        all_caps = set()
        for caps in tool_capabilities.values():
            all_caps.update(caps)
        return all_caps

    def _chain_matches(self, chain_def: Dict, server_caps: Set[str]) -> bool:
        """Check if all capabilities in a chain are present on the server"""
        return all(cap in server_caps for cap in chain_def["chain"])

    def _get_matching_tools(self, chain_def: Dict, tool_capabilities: Dict[str, Set[str]]) -> Dict[str, List[str]]:
        """Identify which tools provide which capabilities for a chain"""
        matches = {}
        for cap in chain_def["chain"]:
            matching_for_cap = []
            for tool_name, caps in tool_capabilities.items():
                if cap in caps:
                    matching_for_cap.append(tool_name)
            matches[cap] = matching_for_cap
        return matches

    def _calculate_risk_score(self, findings: List[ChainFinding]) -> float:
        """Calculate overall risk score (0-10)"""
        if not findings:
            return 0.0
        
        max_severity = 0.0
        severity_map = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0}
        
        for f in findings:
            score = severity_map.get(f.severity, 0.0)
            if score > max_severity:
                max_severity = score
        
        return max_severity
