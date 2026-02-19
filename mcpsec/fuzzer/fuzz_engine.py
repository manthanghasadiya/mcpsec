"""
MCP Protocol Fuzzer Engine.
Orchestrates test case generation, execution, and crash analysis.
"""

import time
from pathlib import Path
from typing import List

from mcpsec.fuzzer.transport.stdio_fuzzer import StdioFuzzer, FuzzResult
from mcpsec.fuzzer.generators.base import FuzzCase
from mcpsec.fuzzer.generators import (
    malformed_json,
    protocol_violation,
    type_confusion,
    boundary_testing,
    unicode_attacks,
)
from mcpsec.ui import console, print_section, get_progress

class FuzzEngine:
    """Orchestrates the fuzzing campaign."""
    
    def __init__(self, command: str, timeout: float = 5.0, debug: bool = False):
        self.command = command
        self.timeout = timeout
        self.debug = debug
        self.results: List[FuzzResult] = []
        self.interesting: List[tuple[FuzzCase, FuzzResult]] = []
    
    def run(self, generators: list[str] | None = None) -> dict:
        """Run the full fuzzing campaign."""
        
        # 1. Collect test cases from all generators
        all_cases = self._collect_cases(generators)
        
        print_section("Fuzzing", "🔥")
        console.print(f"  [accent]Test cases:[/accent] {len(all_cases)}")
        console.print(f"  [accent]Target:[/accent] {self.command}")
        console.print()
        
        # 2. Start server
        fuzzer = StdioFuzzer(self.command, self.timeout)
        
        # 3. First, do a normal initialize handshake so we can test 
        #    post-init methods too
        if self.debug:
            console.print("  [dim]Starting server...[/dim]")
        
        fuzzer.start_server()
        try:
            if self.debug:
                console.print("  [dim]Sending initialize...[/dim]")
                
            init_result = self._do_initialize(fuzzer)
            if not init_result:
                 console.print("  [danger]Server failed to respond to initialize![/danger]")
                 fuzzer.stop_server()
                 return self._summarize(fuzzer)
            
            if self.debug:
                 resp_preview = init_result.response.decode(errors='replace')[:200] if init_result.response else "None"
                 console.print(f"  [muted]Initialize response: {resp_preview}[/muted]")

            if init_result.crashed or init_result.timeout:
                console.print(f"  [danger]Server crashed/timed out during initialize! (timeout={init_result.timeout})[/danger]")
                fuzzer.stop_server()
                return self._summarize(fuzzer)

            if init_result.error_message:
                 console.print(f"  [danger]Initialize error: {init_result.error_message}[/danger]")

        except Exception as e:
            console.print(f"  [danger]Failed to initialize server: {e}[/danger]")
            if self.debug:
                import traceback
                traceback.print_exc()
            fuzzer.stop_server()
            return self._summarize(fuzzer)
 
        if self.debug:
            console.print("  [dim]Initialization successful. Starting fuzzing...[/dim]")
        # 4. Run all fuzz cases
        with get_progress() as progress:
            task = progress.add_task("Fuzzing...", total=len(all_cases))
            
            for case in all_cases:
                if not fuzzer.is_alive():
                    console.print(f"  [danger]Server crashed! Restarting...[/danger]")
                    # Record the crash
                    self.interesting.append((case, FuzzResult(
                        test_id=fuzzer.test_count,
                        generator=case.generator,
                        payload=case.payload,
                        response=None,
                        elapsed_ms=0,
                        crashed=True, timeout=False,
                        error_message="Server died from previous test"
                    )))
                    # Restart and re-initialize
                    fuzzer.restart_server()
                    try: 
                        self._do_initialize(fuzzer)
                    except Exception:
                        pass # Keep going if re-init fails, simple fuzzer logic
                
                result = fuzzer.send_raw(case.payload)
                result.generator = case.generator
                self.results.append(result)

                if self.debug:
                    resp_preview = result.response.decode(errors='replace')[:200] if result.response else "None"
                    if result.timeout:
                        console.print(f"  [dim][DEBUG] {case.name}: TIMEOUT[/dim]")
                    else:
                        console.print(f"  [dim][DEBUG] {case.name}: {len(result.response or b'')} bytes[/dim]")
                
                # Check if interesting
                if result.crashed or result.timeout or self._is_anomalous(result):
                    self.interesting.append((case, result))
                
                progress.advance(task)
        
        # 5. Stop server
        fuzzer.stop_server()
        
        return self._summarize(fuzzer)
    
    def _collect_cases(self, generators: list[str] | None) -> list[FuzzCase]:
        """Collect fuzz cases from all enabled generators."""
        gen_map = {
            "malformed_json": malformed_json.generate,
            "protocol_violation": protocol_violation.generate,
            "type_confusion": type_confusion.generate,
            "boundary": boundary_testing.generate,
            "unicode": unicode_attacks.generate,
        }
        
        cases = []
        active = generators or list(gen_map.keys())
        
        for name in active:
            if name in gen_map:
                cases.extend(gen_map[name]())
        
        return cases
    
    def _do_initialize(self, fuzzer: StdioFuzzer) -> FuzzResult | None:
        """Send proper initialize handshake."""
        import json
        init_msg = {
            "jsonrpc": "2.0", "method": "initialize", "id": 1,
            "params": {
                "protocolVersion": "2024-11-05",  # Updated for latest spec
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-fuzzer", "version": "0.2.0"}
            }
        }
        result = fuzzer.send_mcp_message(init_msg)
        
        # Send initialized notification
        if not result.crashed:
            notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            fuzzer.send_mcp_message(notif)
        
        return result
    
    def _is_anomalous(self, result: FuzzResult) -> bool:
        """Detect anomalous responses that might indicate bugs."""
        if not result.response:
            return False
        
        try:
            text = result.response.decode("utf-8", errors="replace")
        except Exception:
            return True  # Can't decode = weird
        
        # Stack traces in response = server leaking internals
        if any(x in text.lower() for x in ["traceback", "stack trace", "at object.", "error:", "panic:"]):
            # Loose heuristic, but useful
            return True
        
        # Very slow response (>2 seconds for a simple request)
        if result.elapsed_ms > 2000:
            return True
        
        # Very large response for a simple request
        if len(result.response) > 100_000:
            return True
        
        return False
    
    def _summarize(self, fuzzer: StdioFuzzer) -> dict:
        """Generate summary of fuzzing campaign."""
        return {
            "total_tests": fuzzer.test_count,
            "crashes": fuzzer.crash_count,
            "timeouts": fuzzer.timeout_count,
            "interesting": len(self.interesting),
            "interesting_cases": [
                {
                    "case_name": case.name,
                    "generator": case.generator,
                    "description": case.description,
                    "crashed": result.crashed,
                    "timeout": result.timeout,
                    "elapsed_ms": result.elapsed_ms,
                    "error": result.error_message,
                }
                for case, result in self.interesting
            ]
        }
