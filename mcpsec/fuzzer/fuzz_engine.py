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
    
    def __init__(self, command: str, timeout: float = 2.0, startup_timeout: float = 15.0, framing: str = "auto", debug: bool = False):
        self.command = command
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self.framing = framing
        self.debug = debug
        self.results: List[FuzzResult] = []
        self.interesting: List[tuple[FuzzCase, FuzzResult]] = []
    
    def run(self, generators: list[str] | None = None) -> dict:
        """Run the full fuzzing campaign."""
        
        print_section("Fuzzing", "🔥")
        console.print(f"  [accent]Target:[/accent] {self.command}")
        console.print()
        
        # 1. Start server and initialize (detect framing)
        fuzzer = StdioFuzzer(self.command, self.timeout, debug=self.debug)
        
        if self.debug:
            console.print("  [dim]Starting server...[/dim]")
        
        detected_framing = "clrf" # Default fallback
        
        try:
            init_result = self._do_initialize(fuzzer)
            if not init_result:
                 console.print("  [danger]Server failed to respond to initialize![/danger]")
                 fuzzer.stop_server()
                 return self._summarize(fuzzer)
            
            # Capture the framing that worked
            detected_framing = fuzzer.framing
            
            if self.debug:
                 resp_preview = init_result.response.decode(errors='replace')[:200] if init_result.response else "None"
                 console.print(f"  [muted]Initialize response: {resp_preview}[/muted]")

            if init_result.crashed or init_result.timeout:
                error = init_result.error_message or ("Timeout" if init_result.timeout else "Unknown")
                console.print(f"  [danger]Server crashed/timed out during initialize! ({error})[/danger]")
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
            console.print(f"  [dim]Initialization successful (framing={detected_framing}). Starting fuzzing...[/dim]")
            
        # 2. Collect test cases using the detected framing
        all_cases = self._collect_cases(generators, detected_framing)
        console.print(f"  [accent]Test cases:[/accent] {len(all_cases)}")
        
        # 3. Run all fuzz cases
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
                    # Restore framing setting on new fuzzer instance/process
                    fuzzer.framing = detected_framing
                    try: 
                        # initialization might need to happen again?
                        # _do_initialize handles restart_server internally if needed but here we just called it.
                        # Wait, _do_initialize sends the init message. We should resend it.
                        
                        # Simplified re-init:
                        import json
                        init_msg = {
                            "jsonrpc": "2.0", "method": "initialize", "id": 1,
                            "params": {
                                "protocolVersion": "2024-11-05", 
                                "capabilities": {}, 
                                "clientInfo": {"name": "mcpsec-fuzzer", "version": "0.2.0"}
                            }
                        }
                        # Just send it, relying on detected framing
                        fuzzer.send_mcp_message_with_timeout(init_msg, self.startup_timeout)
                        
                    except Exception:
                        pass # Keep going if re-init fails
                
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
        
        # 4. Stop server
        fuzzer.stop_server()
        
        return self._summarize(fuzzer)
    
    def _collect_cases(self, generators: list[str] | None, framing: str) -> list[FuzzCase]:
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
                try:
                    # Try passing framing argument
                    cases.extend(gen_map[name](framing=framing))
                except TypeError:
                    # Fallback for generators not yet updated (though I will update them all)
                    cases.extend(gen_map[name]())
        
        return cases
    
    def _do_initialize(self, fuzzer: StdioFuzzer) -> FuzzResult | None:
        """Send proper initialize handshake with startup timeout and framing detection."""
        # 2. Start server
        if not fuzzer.process:
             fuzzer.start_server()
        
        # We rely on startup_timeout to handle slow servers.
        # OS pipes buffer stdin, so writing early is fine.
             
        import json
        init_msg = {
            "jsonrpc": "2.0", "method": "initialize", "id": 1,
            "params": {
                "protocolVersion": "2024-11-05",  # Updated for latest spec
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-fuzzer", "version": "0.3.0"}
            }
        }

        # Auto-detect framing if needed
        strategies = []
        if self.framing == "auto":
            # Try jsonl (Python) first, then clrf (Node)
            strategies = ["jsonl", "clrf"]
        else:
            strategies = [self.framing]

        for strategy in strategies:
            if self.debug:
                 console.print(f"  [dim][DEBUG] Attempting initialization with {strategy} framing...[/dim]")
            
            fuzzer.framing = strategy
            
            # Use specialized timeout for initialization
            # If auto-detecting, use a shorter timeout for the first attempt to fail fast
            # but still long enough for some startup? 
            # Actually, startup_timeout is for *startup*.
            # If we're retrying, we might need to restart the server?
            # Yes, if we sent garbage framing, the server might be in a bad state.
            
            if strategy != strategies[0]:
                # Restart for subsequent attempts
                fuzzer.restart_server()
            
            result = fuzzer.send_mcp_message_with_timeout(init_msg, self.startup_timeout)
            
            if result and result.response and not result.timeout and not result.crashed:
                # Success!
                if self.framing == "auto" and self.debug:
                    console.print(f"  [success]✔ Auto-detected framing: {strategy}[/success]")
                # Lock in the successful framing
                # self.framing = strategy # Don't overwrite self.framing so we know it was auto
                # But we do need to tell the fuzzer to keep using it.
                # fuzzer.framing is already set.
                
                # Send initialized notification
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                fuzzer.send_mcp_message(notif)
                return result
            
            if self.debug:
                console.print(f"  [dim][DEBUG] {strategy} framing failed (timeout={result.timeout}, crashed={result.crashed}). Retrying...[/dim]")

        # If we get here, all strategies failed. Return the last result.
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
