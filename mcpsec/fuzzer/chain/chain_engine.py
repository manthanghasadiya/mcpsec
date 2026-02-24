"""
ChainEngine - Orchestrates multi-step stateful attack chains.

This is the main entry point for chained fuzzing. It:
1. Discovers all tools via tools/list
2. Uses AI to analyze tool dependencies
3. Builds attack chains
4. Executes chains with payload injection
5. Reports findings
"""

import asyncio
import time
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from .chain_analyzer import ChainAnalyzer
from .chain_builder import ChainBuilder, AttackChain
from .state_manager import StateManager
from .state_extractor import StateExtractor
from .injection_points import InjectionPointIdentifier
from .chain_reporter import ChainReporter

console = Console()


class ChainExecutionStatus(Enum):
    """Status of chain execution."""
    SUCCESS = "success"           # Chain completed, payload delivered
    SETUP_FAILED = "setup_failed" # Setup step failed
    INJECTION_FAILED = "injection_failed"  # Payload injection failed
    CRASH_DETECTED = "crash_detected"      # Server crashed during chain
    TIMEOUT = "timeout"           # Chain execution timed out
    STATE_EXTRACTION_FAILED = "state_extraction_failed"  # Couldn't extract required state


@dataclass
class ChainExecutionResult:
    """Result of executing a single attack chain."""
    chain: AttackChain
    status: ChainExecutionStatus
    payload_used: str
    injection_point: str
    setup_responses: list[dict] = field(default_factory=list)
    target_response: dict | None = None
    extracted_state: dict = field(default_factory=dict)
    execution_time_ms: float = 0.0
    error_message: str | None = None
    
    # Vulnerability indicators
    crash_detected: bool = False
    stack_trace: str | None = None
    exploitation_evidence: str | None = None  # e.g., file contents, command output
    
    @property
    def is_finding(self) -> bool:
        """Check if this result indicates a potential vulnerability."""
        return (
            self.crash_detected or 
            self.exploitation_evidence is not None or
            self.status == ChainExecutionStatus.CRASH_DETECTED
        )


@dataclass 
class ChainFuzzingConfig:
    """Configuration for chained fuzzing."""
    # AI settings
    use_ai: bool = True
    ai_model: str | None = None
    
    # Chain settings
    max_chain_depth: int = 5          # Max steps in a chain
    max_chains_per_tool: int = 10     # Max chains to generate per target tool
    
    # Execution settings
    timeout_per_step: float = 10.0    # Seconds per tool call
    timeout_per_chain: float = 60.0   # Total chain timeout
    delay_between_steps: float = 0.1  # Delay between chain steps
    retry_failed_chains: int = 2      # Retry count for failed chains
    
    # Payload settings
    payload_categories: list[str] = field(default_factory=lambda: [
        "command_injection",
        "path_traversal", 
        "sql_injection",
        "xss",
        "ssrf",
        "template_injection",
        "prototype_pollution",
        "nosql_injection",
    ])
    max_payloads_per_injection_point: int = 50
    
    # State extraction
    extract_all_strings: bool = True   # Extract all string values as potential state
    extract_nested_depth: int = 10     # How deep to look for state in responses
    
    # Crash detection
    restart_on_crash: bool = True
    crash_indicates_finding: bool = True
    
    # Reporting
    verbose: bool = False
    save_all_responses: bool = False   # Save all responses for analysis


class ChainEngine:
    """
    Main engine for chained/stateful fuzzing.
    
    Usage:
        engine = ChainEngine(config)
        results = await engine.run(server_command, transport_type)
    """
    
    def __init__(self, config: ChainFuzzingConfig | None = None):
        self.config = config or ChainFuzzingConfig()
        self.analyzer = ChainAnalyzer(use_ai=self.config.use_ai)
        self.builder = ChainBuilder()
        self.state_manager = StateManager()
        self.extractor = StateExtractor(max_depth=self.config.extract_nested_depth)
        self.injection_identifier = InjectionPointIdentifier()
        self.reporter = ChainReporter()
        
        self._tools: list[dict] = []
        self._chains: list[AttackChain] = []
        self._results: list[ChainExecutionResult] = []
        self._transport = None
        
    async def run(
        self,
        server_command: str,
        transport_type: str = "stdio",
        http_url: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> list[ChainExecutionResult]:
        """
        Run chained fuzzing against an MCP server.
        
        Args:
            server_command: Command to start the server (for stdio)
            transport_type: "stdio" or "http"
            http_url: URL for HTTP transport
            headers: Optional headers for HTTP transport
            
        Returns:
            List of ChainExecutionResult objects
        """
        console.print("\n[bold cyan]═══ Chained Fuzzing Engine ═══[/bold cyan]\n")
        
        try:
            # Phase 1: Initialize transport and discover tools
            await self._initialize_transport(server_command, transport_type, http_url, headers)
            await self._discover_tools()
            
            if not self._tools:
                console.print("[yellow]No tools discovered. Cannot perform chained fuzzing.[/yellow]")
                return []
            
            # Phase 2: Analyze tool dependencies
            console.print("\n[bold]Phase 2: Analyzing Tool Dependencies[/bold]")
            dependency_graph = await self.analyzer.analyze_tools(self._tools)
            
            if self.config.verbose:
                self._print_dependency_graph(dependency_graph)
            
            # Phase 3: Identify injection points
            console.print("\n[bold]Phase 3: Identifying Injection Points[/bold]")
            injection_points = self.injection_identifier.identify(self._tools)
            
            console.print(f"  Found [cyan]{len(injection_points)}[/cyan] potential injection points")
            
            # Phase 4: Build attack chains
            console.print("\n[bold]Phase 4: Building Attack Chains[/bold]")
            self._chains = self.builder.build_chains(
                tools=self._tools,
                dependency_graph=dependency_graph,
                injection_points=injection_points,
                max_depth=self.config.max_chain_depth,
                max_chains_per_tool=self.config.max_chains_per_tool,
            )
            
            console.print(f"  Generated [cyan]{len(self._chains)}[/cyan] attack chains")
            
            if not self._chains:
                console.print("[yellow]No attack chains could be generated.[/yellow]")
                return []
            
            # Phase 5: Execute chains with payloads
            console.print("\n[bold]Phase 5: Executing Attack Chains[/bold]")
            await self._execute_all_chains()
            
            # Phase 6: Report findings
            console.print("\n[bold]Phase 6: Results Summary[/bold]")
            self._print_results_summary()
            
            return self._results
            
        except Exception as e:
            console.print(f"[red]Chain fuzzing error: {e}[/red]")
            if self.config.verbose:
                import traceback
                traceback.print_exc()
            return self._results
            
        finally:
            await self._cleanup()
    
    async def _initialize_transport(
        self,
        server_command: str,
        transport_type: str,
        http_url: str | None,
        headers: dict[str, str] | None,
    ) -> None:
        """Initialize the transport layer."""
        console.print("[bold]Phase 1: Initializing Transport[/bold]")
        
        if transport_type == "stdio":
            from mcpsec.fuzzer.transport.stdio_fuzzer import StdioFuzzer
            self._transport = StdioFuzzer(
                command=server_command,
                timeout=self.config.timeout_per_step,
            )
            self._transport.start()
            console.print(f"  Started server: [dim]{server_command}[/dim]")
        else:
            from mcpsec.fuzzer.transport.http_fuzzer import HttpFuzzer
            self._transport = HttpFuzzer(
                url=http_url,
                headers=headers or {},
                timeout=self.config.timeout_per_step,
            )
            # HTTP transport in mcpsec doesn't have an async start() usually, but it connects on demand.
            console.print(f"  Connected to: [dim]{http_url}[/dim]")
    
    async def _discover_tools(self) -> None:
        """Discover all tools from the server with automatic framing detection."""
        console.print("  Discovering tools...")
        
        # Try JSONL framing first (Python servers)
        if hasattr(self._transport, "framing"):
            self._transport.framing = "jsonl"
        
        init_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-chained", "version": "1.0.0"}
            }
        }
        
        init_response = await self._transport.send_request_async(init_msg)
        
        # If JSONL didn't work, try CRLF framing (Node servers)
        if not init_response or "result" not in init_response:
            if self.config.verbose:
                console.print("  [dim]JSONL framing failed, trying CRLF...[/dim]")
            
            # Restart server to reset state
            if hasattr(self._transport, "restart_async"):
                await self._transport.restart_async()
            else:
                # Fallback to thread for non-async transporters if they have restart
                restart_fn = getattr(self._transport, "restart", None)
                if restart_fn:
                    await asyncio.to_thread(restart_fn)
            
            await asyncio.sleep(1.0)
            
            if hasattr(self._transport, "framing"):
                self._transport.framing = "crlf"
            init_response = await self._transport.send_request_async(init_msg)
        
        if not init_response or "result" not in init_response:
            console.print("[yellow]  Warning: Server did not respond to initialize[/yellow]")
            return
        
        if self.config.verbose:
            framing = getattr(self._transport, "framing", "unknown")
            console.print(f"  [dim]Using framing: {framing}[/dim]")
        
        # Send initialized notification (no ID!)
        await self._transport.send_notification_async({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })
        
        await asyncio.sleep(0.5)  # Give server time to process
        
        # Get tools list
        tools_response = await self._transport.send_request_async({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        })
        
        if tools_response and "result" in tools_response:
            self._tools = tools_response["result"].get("tools", [])
            console.print(f"  Discovered [cyan]{len(self._tools)}[/cyan] tools:")
            
            for tool in self._tools:
                console.print(f"    • {tool.get('name')}")
        else:
            console.print("[yellow]  Warning: Could not retrieve tools list[/yellow]")
            if tools_response:
                console.print(f"  [dim]Response: {tools_response}[/dim]")
    
    async def _execute_all_chains(self) -> None:
        """Execute all attack chains with payloads."""
        total_executions = 0
        findings_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Executing chains...", 
                total=len(self._chains)
            )
            
            for chain in self._chains:
                # Get payloads for this chain's injection point
                payloads = self._get_payloads_for_injection_point(chain)
                
                for payload in payloads[:self.config.max_payloads_per_injection_point]:
                    result = await self._execute_single_chain(chain, payload)
                    self._results.append(result)
                    total_executions += 1
                    
                    if result.is_finding:
                        findings_count += 1
                        console.print(f"\n  [red]Target Tool: {chain.target_tool} - Payload Result: {result.status.value}")
                        if result.exploitation_evidence:
                            console.print(f"     Evidence: {result.exploitation_evidence[:100]}...")
                        if result.crash_detected:
                            console.print(f"     Crash detected!")
                    
                    # Check if server crashed and needs restart
                    if result.crash_detected and self.config.restart_on_crash:
                        await self._restart_server()
                
                progress.advance(task)
        
        console.print(f"\n  Executed [cyan]{total_executions}[/cyan] chain variants")
        console.print(f"  Found [red]{findings_count}[/red] potential findings")
    
    async def _execute_single_chain(
        self, 
        chain: AttackChain, 
        payload: str
    ) -> ChainExecutionResult:
        """Execute a single attack chain with a specific payload."""
        start_time = time.time()
        result = ChainExecutionResult(
            chain=chain,
            status=ChainExecutionStatus.SUCCESS,
            payload_used=payload,
            injection_point=chain.injection_point,
        )
        
        try:
            # Reset state for this chain
            self.state_manager.reset()
            
            # PHASE 1: Execute ALL setup steps and extract state
            for i, setup_step in enumerate(chain.setup_steps):
                if self.config.verbose:
                    console.print(f"    [dim]Setup {i+1}: {setup_step.tool_name}[/dim]")
                
                # Resolve any $state.X placeholders with current state
                step_args = self._resolve_arguments(setup_step.arguments, self.state_manager)
                
                response = await self._transport.send_request_async({
                    "jsonrpc": "2.0",
                    "id": 100 + i,
                    "method": "tools/call",
                    "params": {
                        "name": setup_step.tool_name,
                        "arguments": step_args,
                    }
                })
                
                if response is None:
                    result.status = ChainExecutionStatus.CRASH_DETECTED
                    result.crash_detected = True
                    result.error_message = f"Server crashed during setup step: {setup_step.tool_name}"
                    return result
                
                result.setup_responses.append(response)
                
                # Check for errors in setup
                if "error" in response:
                    result.status = ChainExecutionStatus.SETUP_FAILED
                    result.error_message = f"Setup failed at {setup_step.tool_name}: {response.get('error')}"
                    return result
                
                # CRITICAL: Extract state from this response
                extracted = self.extractor.extract(response)
                if self.config.verbose and extracted:
                    console.print(f"    [dim]  Extracted state: {list(extracted.keys())}[/dim]")
                self.state_manager.update(extracted, tool_name=setup_step.tool_name)
                result.extracted_state.update(extracted)
                
                await asyncio.sleep(self.config.delay_between_steps)
            
            # PHASE 2: Check if we have required state for target tool
            # If the target tool needs a ref and we don't have one, skip this chain
            if getattr(chain, "requires_state", []):
                for required_key in chain.requires_state:
                    if not self.state_manager.has(required_key):
                        result.status = ChainExecutionStatus.STATE_EXTRACTION_FAILED
                        result.error_message = f"Missing required state: {required_key}"
                        return result
            
            # PHASE 3: Execute target tool with payload injection
            target_args = self._resolve_arguments(chain.target_arguments, self.state_manager)
            target_args = self._inject_payload(target_args, chain.injection_point, payload)
            
            if self.config.verbose:
                console.print(f"    [dim]Target: {chain.target_tool}({chain.injection_point}={payload[:30]}...)[/dim]")
            
            target_response = await self._transport.send_request_async({
                "jsonrpc": "2.0",
                "id": 999,
                "method": "tools/call",
                "params": {
                    "name": chain.target_tool,
                    "arguments": target_args,
                }
            })
            
            if target_response is None:
                result.status = ChainExecutionStatus.CRASH_DETECTED
                result.crash_detected = True
                return result
            
            result.target_response = target_response
            
            # PHASE 4: Analyze response for REAL exploitation evidence
            evidence = self._check_exploitation_evidence(target_response, payload, chain)
            if evidence:
                result.exploitation_evidence = evidence
            
        except asyncio.TimeoutError:
            result.status = ChainExecutionStatus.TIMEOUT
            result.error_message = "Chain execution timed out"
            
        except Exception as e:
            result.status = ChainExecutionStatus.INJECTION_FAILED
            result.error_message = str(e)
            
        finally:
            result.execution_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    def _resolve_arguments(
        self, 
        args_template: dict[str, Any], 
        state: StateManager
    ) -> dict[str, Any]:
        """Resolve argument placeholders with actual state values."""
        resolved = {}
        for key, value in args_template.items():
            if isinstance(value, str) and value.startswith("$state."):
                state_key = value[7:]  # Remove "$state." prefix
                resolved[key] = state.get(state_key, value)
            elif isinstance(value, dict):
                resolved[key] = self._resolve_arguments(value, state)
            else:
                resolved[key] = value
        return resolved
    
    def _inject_payload(
        self, 
        args: dict[str, Any], 
        injection_point: str, 
        payload: str
    ) -> dict[str, Any]:
        """Inject payload into the specified injection point."""
        # Handle nested injection points (e.g., "options.text")
        parts = injection_point.split(".")
        current = args
        
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = payload
        return args
    
    def _get_payloads_for_injection_point(self, chain: AttackChain) -> list[str]:
        """Get relevant payloads for the injection point type."""
        from mcpsec.fuzzer.generators.injection_payloads import INJECTION_PAYLOADS
        
        all_payloads_raw = INJECTION_PAYLOADS
        selected_payloads = []
        
        # Determine payload types based on injection point characteristics
        point_type = chain.injection_point_type
        
        target_categories = []
        if point_type in ["text", "content", "value", "input", "query", "label"]:
            target_categories = ["cmdi", "sqli", "xss", "ssti", "log", "header"]
        elif point_type in ["path", "file", "url", "uri", "src", "href"]:
            target_categories = ["path", "ssrf"]
        elif point_type in ["selector", "ref", "id", "element"]:
            target_categories = ["xss", "proto", "constructor"]
        else:
            # Categorize by everything
            target_categories = ["cmdi", "sqli", "xss", "ssti", "path", "ssrf", "proto"]
            
        for name, value, desc in all_payloads_raw:
            if any(cat in name for cat in target_categories):
                selected_payloads.append(value)
                
        # Fallback if no category matched
        if not selected_payloads:
            selected_payloads = [p[1] for p in all_payloads_raw[:20]]
            
        return selected_payloads
    
    def _check_exploitation_evidence(
        self, 
        response: dict, 
        payload: str,
        chain: AttackChain,
    ) -> str | None:
        """
        Check if the response contains evidence of SUCCESSFUL exploitation.
        
        Key principle: We're looking for DATA that shouldn't be there,
        not error messages that echo our payload back.
        """
        if not response:
            return None
        
        response_str = str(response)
        response_lower = response_str.lower()
        
        # STEP 1: Filter out obvious non-exploits
        # If response is an error that just echoes our payload, it's NOT a finding
        error_patterns = [
            "not found",
            "invalid",
            "does not exist", 
            "no such",
            "cannot find",
            "unable to",
            "failed to",
            "permission denied",
            "access denied",
            "not allowed",
            "not in allowed",
            "outside of",
            "err_name_not_resolved",
            "enoent",
            "is not a valid",
        ]
        
        # Check if this looks like a rejection/error
        is_error_response = "error" in response_lower or any(p in response_lower for p in error_patterns)
        
        # If it's an error AND our payload appears in the error message, it's just being echoed
        payload_lower = payload.lower()[:50]  # First 50 chars of payload
        if is_error_response and payload_lower in response_lower:
            return None  # Payload echoed in error = NOT a finding
        
        # STEP 2: Check for REAL exploitation evidence
        
        # === Command Injection Evidence ===
        # These indicate actual command execution, not just payload echo
        command_execution_evidence = [
            # Unix command output patterns
            ("uid=", r"uid=\d+"),                    # id command output
            ("gid=", r"gid=\d+"),                    # id command output  
            ("groups=", r"groups=\d+"),              # id command output
            ("root:x:0:0", None),                    # /etc/passwd entry
            ("/bin/bash", None),                     # Shell path in passwd
            ("/bin/sh", None),                       # Shell path
            ("daemon:x:", None),                     # passwd entry
            ("nobody:x:", None),                     # passwd entry
            
            # Windows command output patterns
            ("volume serial number", None),         # dir command
            ("directory of c:\\", None),            # dir command
            ("nt authority\\system", None),         # whoami on system
            ("nt authority\\network", None),        # whoami network service
            (" domain\\", r"\w+\\[\w]+"),           # domain\user format
        ]
        
        for indicator, regex in command_execution_evidence:
            if indicator in response_lower:
                # Extra validation with regex if provided
                if regex:
                    import re
                    if re.search(regex, response_lower):
                        return self._extract_evidence_context(response_str, indicator)
                else:
                    return self._extract_evidence_context(response_str, indicator)
        
        # === Path Traversal Evidence ===
        # Actual file CONTENTS, not just path names in errors
        file_content_evidence = [
            # /etc/passwd contents (NOT the path, the CONTENTS)
            ("root:x:0:0:root:", None),             # Full passwd line
            ("daemon:x:1:1:", None),                # Another passwd line
            ("bin:x:2:2:", None),                   # Another passwd line
            
            # /etc/shadow indicators
            ("$6$", None),                          # SHA-512 hash prefix
            ("$y$", None),                          # yescrypt hash prefix
            ("$5$", None),                          # SHA-256 hash prefix
            
            # Windows file contents
            ("[extensions]", None),                 # win.ini section
            ("[mci extensions]", None),             # win.ini section
            ("[fonts]", None),                      # win.ini/system.ini
            ("for 16-bit app support", None),       # system.ini comment
            
            # SSH keys
            ("ssh-rsa aaaa", None),                 # SSH public key
            ("ssh-ed25519 aaaa", None),             # SSH public key
            ("-----begin rsa private", None),       # Private key header
            ("-----begin openssh private", None),   # Private key header
            
            # Configuration files
            ("<?xml version=", None),               # XML config
            ("jdbc:", None),                        # Database connection string
            ("password=", None),                    # Leaked credential (if NOT in our payload)
            ("api_key=", None),                     # Leaked API key
            ("secret_key=", None),                  # Leaked secret
        ]
        
        for indicator, regex in file_content_evidence:
            if indicator in response_lower:
                # Make sure it's not just our payload being echoed
                if indicator not in payload_lower:
                    return self._extract_evidence_context(response_str, indicator)
        
        # === SSRF Evidence ===
        # Actual cloud metadata responses
        ssrf_evidence = [
            # AWS metadata
            ("ami-", r"ami-[a-f0-9]{8,17}"),        # AMI ID format
            ("i-", r"i-[a-f0-9]{8,17}"),            # Instance ID format
            ("arn:aws:", None),                     # AWS ARN
            ("accesskeyid", None),                  # AWS credentials
            ("secretaccesskey", None),              # AWS credentials
            
            # GCP metadata
            ("project-id", None),                   # GCP project
            ("instance-id", None),                  # GCP instance
            ("service-accounts", None),             # GCP service accounts
            
            # Azure metadata  
            ("subscriptionid", None),               # Azure subscription
            ("vmid", None),                         # Azure VM ID
        ]
        
        for indicator, regex in ssrf_evidence:
            if indicator in response_lower:
                if regex:
                    import re
                    if re.search(regex, response_lower):
                        return self._extract_evidence_context(response_str, indicator)
                else:
                    return self._extract_evidence_context(response_str, indicator)
        
        # === SQL Injection Evidence ===
        # Actual database errors revealing structure (not generic errors)
        sqli_evidence = [
            ("you have an error in your sql syntax", None),  # MySQL specific
            ("postgresql", r"(?:syntax error|column).+(?:at or near|does not exist)"),
            ("sqlite3.operationalerror", None),     # Python SQLite error
            ("ora-", r"ora-\d{5}"),                 # Oracle error codes
            ("sql server", r"sql server.+(?:error|exception)"),
            ("unclosed quotation mark", None),      # SQL Server specific
            ("quoted string not properly terminated", None),  # Oracle
        ]
        
        for indicator, regex in sqli_evidence:
            if indicator in response_lower:
                if regex:
                    import re
                    if re.search(regex, response_lower):
                        return self._extract_evidence_context(response_str, indicator)
                else:
                    return self._extract_evidence_context(response_str, indicator)
        
        # === Stack Trace / Internal Path Disclosure ===
        # Only flag if it reveals INTERNAL paths, not our payload paths
        if "traceback" in response_lower or "stack trace" in response_lower:
            # Check for internal path disclosure
            internal_paths = [
                "/home/", "/var/", "/opt/", "/usr/",  # Unix internal
                "c:\\program files", "c:\\users\\", "c:\\windows",  # Windows internal
                "node_modules", "site-packages", ".venv",  # Dependencies
            ]
            for path in internal_paths:
                if path in response_lower and path not in payload_lower:
                    return self._extract_evidence_context(response_str, path)
        
        # === Server Crash / DoS Evidence ===
        # These are always findings
        crash_indicators = [
            "panic:", "segmentation fault", "sigsegv", "sigabrt",
            "fatal error", "unhandled exception", "core dumped",
        ]
        for indicator in crash_indicators:
            if indicator in response_lower:
                return self._extract_evidence_context(response_str, indicator)
        
        # === Generic Success/Finding Indicators ===
        # These are kept for cases where a server explicitly says "Exploited!"
        # or other high-confidence anomalies.
        generic_evidence = [
            ("exploited!", None),
            ("vulnerable!", None),
            ("hacked!", None),
            ("injected!", None),
            ("command successful", None),
        ]
        
        for indicator, regex in generic_evidence:
            if indicator in response_lower:
                if regex:
                    import re
                    if re.search(regex, response_lower):
                        return self._extract_evidence_context(response_str, indicator)
                else:
                    return self._extract_evidence_context(response_str, indicator)

        return None

    def _extract_evidence_context(self, response: str, indicator: str, context_chars: int = 150) -> str:
        """Extract context around the evidence indicator."""
        response_lower = response.lower()
        indicator_lower = indicator.lower()
        
        idx = response_lower.find(indicator_lower)
        if idx == -1:
            return indicator
        
        start = max(0, idx - 50)
        end = min(len(response), idx + len(indicator) + context_chars)
        
        context = response[start:end]
        if start > 0:
            context = "..." + context
        if end < len(response):
            context = context + "..."
        
        return context
    
    async def _restart_server(self) -> None:
        """Restart the server after a crash."""
        console.print("  [yellow]Restarting server...[/yellow]")
        await self._transport.restart()
        await asyncio.sleep(1.0)
        
        # Re-initialize
        await self._transport.send_request_async({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-chained", "version": "1.0.0"}
            }
        })
        await self._transport.send_notification_async({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        })
        await asyncio.sleep(0.5)
    
    def _print_dependency_graph(self, graph: dict) -> None:
        """Print the tool dependency graph."""
        table = Table(title="Tool Dependencies")
        table.add_column("Tool", style="cyan")
        table.add_column("Depends On", style="yellow")
        table.add_column("Provides State", style="green")
        
        for tool_name, deps in graph.items():
            table.add_row(
                tool_name,
                ", ".join(deps.requires) if isinstance(deps.requires, list) else "-",
                ", ".join(deps.provides) if isinstance(deps.provides, list) else "-",
            )
        
        console.print(table)
    
    def _print_results_summary(self) -> None:
        """Print a summary of all results."""
        findings = [r for r in self._results if r.is_finding]
        
        if not findings:
            console.print("  [green]No vulnerabilities detected[/green]")
            return
        
        table = Table(title=f"🎯 {len(findings)} Potential Vulnerabilities Found")
        table.add_column("Tool", style="cyan")
        table.add_column("Injection Point", style="yellow")
        table.add_column("Payload", style="red", max_width=30)
        table.add_column("Evidence", style="green", max_width=40)
        
        for finding in findings:
            table.add_row(
                finding.chain.target_tool,
                finding.injection_point,
                finding.payload_used[:30] + "..." if len(finding.payload_used) > 30 else finding.payload_used,
                (finding.exploitation_evidence[:40] + "...") if finding.exploitation_evidence else "Crash",
            )
        
        console.print(table)
    
    async def _cleanup(self) -> None:
        """Clean up resources."""
        if self._transport:
            try:
                await self._transport.stop()
            except Exception:
                pass
