"""
MCP Protocol Fuzzer Engine.
Orchestrates test case generation, execution, and crash analysis.
"""

import json
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
    session_attacks,
    injection_payloads,
    resource_exhaustion,
    encoding_attacks,
    method_mutations,
    param_mutations,
    timing_attacks,
    header_mutations,
    json_edge_cases,
    protocol_state,
)
from mcpsec.ui import console, print_section, get_progress

class FuzzEngine:
    """Orchestrates the fuzzing campaign."""
    
    def __init__(self, command: str, timeout: float = 2.0, startup_timeout: float = 15.0, framing: str = "auto", debug: bool = False, intensity: str = "medium", ai: bool = False):
        self.command = command
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self.framing = framing
        self.debug = debug
        self.intensity = intensity
        self.ai = ai
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
        
        # 2b. AI-generated fuzz cases (per-tool)
        if self.ai:
            ai_cases = self._generate_ai_cases(fuzzer, detected_framing)
            all_cases.extend(ai_cases)
        
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
        # Low: core protocol tests (~65 cases)
        low_gens = {
            "malformed_json": malformed_json.generate,
            "protocol_violation": protocol_violation.generate,
            "type_confusion": type_confusion.generate,
            "boundary": boundary_testing.generate,
            "unicode": unicode_attacks.generate,
        }
        # Medium: + session + encoding (~150 cases)
        medium_gens = {
            "session_attacks": session_attacks.generate,
            "encoding_attacks": encoding_attacks.generate,
        }
        # High: + method/param/timing/header/json/protocol (~500 cases)
        high_gens = {
            "injection_payloads": injection_payloads.generate,
            "method_mutations": method_mutations.generate,
            "param_mutations": param_mutations.generate,
            "timing_attacks": timing_attacks.generate,
            "header_mutations": header_mutations.generate,
            "json_edge_cases": json_edge_cases.generate,
            "protocol_state": protocol_state.generate,
        }
        # Insane: all of the above + resource exhaustion (~550+ cases)
        insane_gens = {
            "resource_exhaustion": resource_exhaustion.generate,
        }
        
        gen_map = dict(low_gens)
        if self.intensity in ("medium", "high", "insane"):
            gen_map.update(medium_gens)
        if self.intensity in ("high", "insane"):
            gen_map.update(high_gens)
        if self.intensity == "insane":
            gen_map.update(insane_gens)
        
        cases = []
        active = generators or list(gen_map.keys())
        
        for name in active:
            if name in gen_map:
                try:
                    cases.extend(gen_map[name](framing=framing))
                except TypeError:
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
    
    def _generate_ai_cases(self, fuzzer: StdioFuzzer, framing: str) -> list[FuzzCase]:
        """Use AI to generate custom adversarial payloads per tool."""
        cases: list[FuzzCase] = []
        
        def _frame(body: bytes) -> bytes:
            if framing == "jsonl":
                return body + b"\n"
            return f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        
        # 1. Discover tools by sending tools/list
        console.print("  [accent]🧠 AI Fuzz:[/accent] Discovering server tools...")
        tools_msg = {"jsonrpc": "2.0", "method": "tools/list", "id": 9999}
        result = fuzzer.send_mcp_message_with_timeout(tools_msg, self.startup_timeout)
        
        if not result or not result.response or result.timeout or result.crashed:
            console.print("  [warning]⚠ Could not discover tools. Skipping AI fuzz.[/warning]")
            return cases
        
        # Parse tools from response
        try:
            resp_text = result.response.decode("utf-8", errors="replace")
            # Handle CLRF framing: extract JSON from headers
            if "\r\n\r\n" in resp_text:
                resp_text = resp_text.split("\r\n\r\n", 1)[-1]
            resp_data = json.loads(resp_text)
            tools = resp_data.get("result", {}).get("tools", [])
        except Exception:
            console.print("  [warning]⚠ Could not parse tools/list response. Skipping AI fuzz.[/warning]")
            return cases
        
        if not tools:
            console.print("  [muted]No tools found. Skipping AI fuzz.[/muted]")
            return cases
        
        console.print(f"  [accent]🧠 AI Fuzz:[/accent] Found {len(tools)} tools. Generating payloads...")
        
        # 2. Get LLM client
        try:
            from mcpsec.config import get_api_key
            from mcpsec.ai.llm_client import LLMClient
            
            api_key, provider = get_api_key()
            if not api_key:
                console.print("  [warning]⚠ No AI API key configured. Skipping AI fuzz.[/warning]")
                return cases
            
            llm = LLMClient(api_key=api_key, provider=provider)
        except Exception as e:
            console.print(f"  [warning]⚠ Could not initialize AI: {e}. Skipping AI fuzz.[/warning]")
            return cases
        
        # 3. For each tool, generate adversarial payloads
        for tool in tools:
            tool_name = tool.get("name", "unknown")
            tool_desc = tool.get("description", "No description")
            tool_schema = tool.get("inputSchema", {})
            
            prompt = f"""You are a security fuzzer. Given this MCP tool:
Name: {tool_name}
Parameters: {json.dumps(tool_schema, indent=2)}
Description: {tool_desc}

Generate 15 malformed/adversarial tool call payloads designed to crash, 
hang, or exploit the server. Each payload should have crafted arguments.

Focus on:
- Type confusion (wrong types for each parameter)
- Boundary values (empty, null, huge, negative)
- Injection payloads specific to the parameter name/type
  (e.g., SQL for 'query' params, paths for 'file' params, commands for 'command' params)
- Unicode edge cases in parameter values
- Prototype pollution in arguments object

Return ONLY a JSON array of objects (no markdown, no explanation):
[{{"name": "test_name", "arguments": {{}}, "description": "what this tests"}}]"""
            
            try:
                response = llm.chat(prompt)
                
                # Parse JSON from response
                text = response.strip()
                # Strip markdown if present
                if "```" in text:
                    text = text.split("```")[1]
                    if text.startswith("json"):
                        text = text[4:]
                    text = text.strip()
                
                payloads = json.loads(text)
                
                if not isinstance(payloads, list):
                    continue
                
                for p in payloads:
                    if not isinstance(p, dict):
                        continue
                    test_name = p.get("name", "ai_test")
                    arguments = p.get("arguments", {})
                    description = p.get("description", "AI-generated payload")
                    
                    msg = {
                        "jsonrpc": "2.0", "method": "tools/call", "id": 1,
                        "params": {"name": tool_name, "arguments": arguments}
                    }
                    
                    cases.append(FuzzCase(
                        name=f"ai_{tool_name}_{test_name}",
                        generator="ai_fuzz",
                        payload=_frame(json.dumps(msg).encode()),
                        description=f"🧠 {tool_name}: {description}",
                        expected_behavior="Server handles gracefully"
                    ))
                
                console.print(f"  [success]  ✔ {tool_name}:[/success] {sum(1 for c in cases if c.generator == 'ai_fuzz' and tool_name in c.name)} payloads")
                
            except Exception as e:
                if self.debug:
                    console.print(f"  [warning]  ⚠ {tool_name}: AI generation failed ({e})[/warning]")
                continue
        
        console.print(f"  [accent]🧠 AI Fuzz:[/accent] Generated {len(cases)} custom payloads")
        return cases
    
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
