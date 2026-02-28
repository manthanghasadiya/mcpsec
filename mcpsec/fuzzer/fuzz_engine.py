"""
MCP Protocol Fuzzer Engine.
Orchestrates test case generation, execution, and crash analysis.
"""

import json
import time
from pathlib import Path
from typing import List

from mcpsec.fuzzer.transport.stdio_fuzzer import StdioFuzzer, FuzzResult
from mcpsec.fuzzer.transport.http_fuzzer import HttpFuzzer
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
    protocol_state_machine,
    id_confusion,
    # Nuclear expansion generators
    integer_boundaries,
    concurrency_attacks,
    memory_exhaustion_v2,
    regex_dos,
    deserialization,
)
from mcpsec.ui import console, print_section, get_progress

class FuzzEngine:
    """Orchestrates the fuzzing campaign."""
    
    def __init__(self, command: str, timeout: float = 2.0, startup_timeout: float = 15.0, framing: str = "auto", debug: bool = False, intensity: str = "medium", ai: bool = False, headers: dict | None = None):
        self.command = command
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self.framing = framing
        self.debug = debug
        self.intensity = intensity
        self.ai = ai
        self.headers = headers
        self.results: List[FuzzResult] = []
        self.interesting: List[tuple[FuzzCase, FuzzResult]] = []
        self._discovered_tools: list[dict] = []
    
    def run(self, generators: list[str] | None = None) -> dict:
        """Run the full fuzzing campaign."""
        
        print_section("Fuzzing", "🔥")
        console.print(f"  [accent]Target:[/accent] {self.command}")
        console.print()
        
        # 1. Start server and initialize (detect framing)
        if self.command.startswith(("http://", "https://")):
            fuzzer = HttpFuzzer(self.command, self.timeout, debug=self.debug, headers=self.headers)
        else:
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
                self._run_generator(fuzzer, case, detected_framing)
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
        # Medium: + session + encoding + integer boundaries (~200 cases)
        medium_gens = {
            "session_attacks": session_attacks.generate,
            "encoding_attacks": encoding_attacks.generate,
            "integer_boundaries": integer_boundaries.generate,
        }
        # High: + method/param/timing/header/json/protocol/concurrency/regex/deser (~800 cases)
        high_gens = {
            "injection_payloads": injection_payloads.generate,
            "method_mutations": method_mutations.generate,
            "param_mutations": param_mutations.generate,
            "timing_attacks": timing_attacks.generate,
            "header_mutations": header_mutations.generate,
            "json_edge_cases": json_edge_cases.generate,
            "protocol_state": protocol_state.generate,
            "protocol_state_machine": protocol_state_machine.generate,
            "id_confusion": id_confusion.generate,
            "concurrency_attacks": concurrency_attacks.generate,
            "regex_dos": regex_dos.generate,
            "deserialization": deserialization.generate,
        }
        # Insane: all of the above + resource exhaustion + memory exhaustion (~1500+ cases)
        insane_gens = {
            "resource_exhaustion": resource_exhaustion.generate,
            "memory_exhaustion_v2": memory_exhaustion_v2.generate,
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
                    # Try passing combined framing and intensity first
                    generated = gen_map[name](framing=framing, intensity=self.intensity)
                except TypeError:
                    try:
                        # Try just framing
                        generated = gen_map[name](framing=framing)
                    except TypeError:
                        try:
                            # Try just intensity (the new ones)
                            generated = gen_map[name](intensity=self.intensity)
                        except TypeError:
                            # Try no args
                            generated = gen_map[name]()
                
                for item in generated:
                    if isinstance(item, dict):
                        # Convert dict to FuzzCase and handle framing
                        raw_payload = item.get("payload")
                        if isinstance(raw_payload, dict):
                            body = json.dumps(raw_payload).encode("utf-8")
                            if framing == "jsonl":
                                payload = body + b"\n"
                            else:
                                payload = f"Content-Length: {len(body)}\r\n\r\n".encode() + body
                        else:
                            payload = raw_payload
                        
                        cases.append(FuzzCase(
                            name=item.get("name", "unknown"),
                            generator=name,
                            payload=payload,
                            description=item.get("description", ""),
                            expected_behavior="Error expected" if item.get("expects_error") else "Success",
                            skip_init=item.get("skip_init", False),
                            send_after_init=item.get("send_after_init", False),
                            send_shutdown_first=item.get("send_shutdown_first", False),
                            repeat=item.get("repeat", 1),
                            delay_between=item.get("delay_between", 0.0),
                            expects_error=item.get("expects_error", False),
                            crash_indicates_bug=item.get("crash_indicates_bug", True)
                        ))
                    else:
                        cases.append(item)
        
        # Enrichment logic (OMITTED for brevity in constructed file if not needed, but here it's original)
        if self._discovered_tools:
            enriched: list[FuzzCase] = []
            for case in cases:
                if case.generator == "injection_payloads":
                    for tool in self._discovered_tools:
                        tool_name = tool.get("name", "test_tool")
                        schema = tool.get("inputSchema", {})
                        real_params = list(schema.get("properties", {}).keys())
                        try:
                            raw = case.payload
                            if b"\r\n\r\n" in raw:
                                body = raw.split(b"\r\n\r\n", 1)[1]
                            elif raw.endswith(b"\n"):
                                body = raw.rstrip(b"\n")
                            else:
                                body = raw
                            msg = json.loads(body)
                            if msg.get("method") == "tools/call":
                                msg["params"]["name"] = tool_name
                                if real_params:
                                    old_args = msg["params"].get("arguments", {})
                                    payload_val = next(iter(old_args.values()), "")
                                    msg["params"]["arguments"] = {p: payload_val for p in real_params}
                                new_body = json.dumps(msg).encode()
                                if framing == "jsonl":
                                    framed = new_body + b"\n"
                                else:
                                    framed = f"Content-Length: {len(new_body)}\r\n\r\n".encode() + new_body
                                enriched.append(FuzzCase(
                                    name=f"{case.name}_{tool_name}",
                                    generator=case.generator,
                                    payload=framed,
                                    description=f"{case.description} (tool: {tool_name})",
                                    expected_behavior=case.expected_behavior,
                                ))
                        except Exception:
                            pass
                    enriched.append(case)
                else:
                    enriched.append(case)
            return enriched
        
        return cases

    def _run_generator(self, fuzzer, case: FuzzCase, framing: str):
        """Execute a single fuzz case, handling special protocol flags."""
        
        # 1. Handle state-breaking flags
        if case.skip_init or case.send_shutdown_first:
            fuzzer.restart_server()
            fuzzer.framing = framing
            
            if case.send_shutdown_first:
                # To test post-shutdown, we must first be initialized
                self._do_initialize(fuzzer)
                # Send shutdown request
                shutdown_msg = {"jsonrpc": "2.0", "id": 999, "method": "shutdown", "params": {}}
                fuzzer.send_mcp_message(shutdown_msg)
                # Technically should wait for response, but for fuzzing we can just send exit next
                exit_msg = {"jsonrpc": "2.0", "method": "notifications/exit"}
                exit_body = json.dumps(exit_msg).encode("utf-8")
                if framing == "jsonl":
                    exit_payload = exit_body + b"\n"
                else:
                    exit_payload = f"Content-Length: {len(exit_body)}\r\n\r\n".encode() + exit_body
                fuzzer.send_notification(exit_payload)
                time.sleep(0.1)

        # 2. Ensure initialized if needed (and not already)
        if not case.skip_init and not fuzzer.is_alive():
            is_crash, crash_reason = fuzzer._check_real_crash()
            if is_crash and self.debug:
                console.print(f"  [danger]Server crashed! ({crash_reason}) Restarting...[/danger]")
            
            fuzzer.restart_server()
            fuzzer.framing = framing
            self._do_initialize(fuzzer)
        
        # 3. Handle double-initialize or other "after init" requirements
        if case.send_after_init:
            # We ensure we are initialized (already handled above if not alive)
            if not fuzzer.is_alive():
                fuzzer.restart_server()
                fuzzer.framing = framing
                self._do_initialize(fuzzer)

        # 4. Execution loop (for repeat)
        for i in range(max(1, case.repeat)):
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
            
            if case.repeat > 1 and i < case.repeat - 1 and case.delay_between > 0:
                time.sleep(case.delay_between)
    
    def _do_initialize(self, fuzzer: StdioFuzzer) -> FuzzResult | None:
        """Send proper initialize handshake with startup timeout and framing detection."""
        if not fuzzer.process:
             fuzzer.start_server()
             
        import json
        init_msg = {
            "jsonrpc": "2.0", "method": "initialize", "id": 1,
            "params": {
                "protocolVersion": "2024-11-05", 
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-fuzzer", "version": "0.3.0"}
            }
        }

        strategies = []
        if self.framing == "auto":
            strategies = ["jsonl", "clrf"]
        else:
            strategies = [self.framing]

        for strategy in strategies:
            if self.debug:
                 console.print(f"  [dim][DEBUG] Attempting initialization with {strategy} framing...[/dim]")
            
            fuzzer.framing = strategy
            
            if strategy != strategies[0]:
                fuzzer.restart_server()
            
            result = fuzzer.send_mcp_message_with_timeout(init_msg, self.startup_timeout)
            
            if result and result.response and not result.timeout and not result.crashed:
                # Success!
                if self.framing == "auto" and self.debug:
                    console.print(f"  [success]✔ Auto-detected framing: {strategy}[/success]")
                
                # Send initialized notification
                notif_json = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
                if getattr(fuzzer, "framing", None) == "jsonl":
                    notif_payload = (notif_json + "\n").encode("utf-8")
                else:
                    body = notif_json.encode("utf-8")
                    notif_payload = f"Content-Length: {len(body)}\r\n\r\n".encode() + body
                
                if fuzzer.process and fuzzer.process.stdin:
                    fuzzer.process.stdin.write(notif_payload)
                    fuzzer.process.stdin.flush()
                else:
                    fuzzer.send_raw(notif_payload)
                return result
            
            if self.debug:
                console.print(f"  [dim][DEBUG] {strategy} framing failed. Retrying...[/dim]")

        return result
    
    def _generate_ai_cases(self, fuzzer: StdioFuzzer, framing: str) -> list[FuzzCase]:
        """Use AI to generate custom adversarial payloads per tool."""
        cases: list[FuzzCase] = []
        
        def _frame(body: bytes) -> bytes:
            if framing == "jsonl":
                return body + b"\n"
            return f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        
        console.print("  [accent]🧠 AI Fuzz:[/accent] Discovering server tools...")
        time.sleep(1.0)
        
        tools_msg = {"jsonrpc": "2.0", "method": "tools/list", "id": 9999}
        result = None
        for attempt in range(3):
            if not fuzzer.is_alive():
                fuzzer.restart_server()
                fuzzer.framing = framing
                # Re-initialize
                init_msg = {
                    "jsonrpc": "2.0", "method": "initialize", "id": 1,
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "mcpsec-fuzzer", "version": "1.0.0"}
                    }
                }
                init_result = fuzzer.send_mcp_message_with_timeout(init_msg, self.startup_timeout)
                if not init_result or init_result.crashed:
                    continue
                # Send initialized notification
                notif_json = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
                if framing == "jsonl":
                    notif_payload = (notif_json + "\n").encode("utf-8")
                else:
                    body = notif_json.encode("utf-8")
                    notif_payload = f"Content-Length: {len(body)}\r\n\r\n".encode() + body
                
                if fuzzer.process and fuzzer.process.stdin:
                    fuzzer.process.stdin.write(notif_payload)
                    fuzzer.process.stdin.flush()
                else:
                    fuzzer.send_raw(notif_payload)
                time.sleep(0.5)
            
            result = fuzzer.send_mcp_message_with_timeout(tools_msg, self.startup_timeout)
            time.sleep(1.0)
            if result and result.response and not result.crashed and not result.timeout:
                break
            time.sleep(0.5)
        
        if not result or not result.response:
            return cases
        
        try:
            resp_text = result.response.decode("utf-8", errors="replace")
            if "\r\n\r\n" in resp_text:
                resp_text = resp_text.split("\r\n\r\n", 1)[1]
            resp_data = json.loads(resp_text)
            tools = resp_data.get("result", {}).get("tools", [])
        except Exception:
            return cases
        
        if not tools:
            return cases
        
        self._discovered_tools = tools
        console.print(f"  [accent]🧠 AI Fuzz:[/accent] Found {len(tools)} tools. Generating payloads...")
        
        try:
            from mcpsec.config import get_api_key
            from mcpsec.ai.llm_client import LLMClient
            provider, api_key, base_url, model = get_api_key()
            if not provider:
                return cases
            llm = LLMClient()
        except Exception:
            return cases
        
        for tool in tools:
            tool_name = tool.get("name", "unknown")
            tool_schema = tool.get("inputSchema", {})
            
            system_prompt = "You are a security fuzzer. Output STRICT STATIC JSON ONLY."
            user_prompt = f"Generate 15 adversarial payloads for MCP tool: {tool_name}. Schema: {json.dumps(tool_schema)}"
            
            try:
                import asyncio
                import re
                response = asyncio.run(llm.chat(system_prompt, user_prompt))
                if not response: continue
                
                text = response.strip()
                if "```" in text:
                    text = text.split("```")[1]
                    if text.startswith("json"): text = text[4:]
                    text = text.strip()
                
                # Basic sanitization
                text = re.sub(r'\\x([0-9a-fA-F]{2})', r'\\u00\1', text)
                text = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)
                text = re.sub(r',\s*([}\]])', r'\1', text)
                
                try:
                    payloads = json.loads(text)
                except json.JSONDecodeError:
                    match = re.search(r'\[.*\]', text, re.DOTALL)
                    if match: payloads = json.loads(match.group())
                    else: continue
                
                if not isinstance(payloads, list): continue
                
                for p in payloads:
                    if not isinstance(p, dict): continue
                    msg = {
                        "jsonrpc": "2.0", "method": "tools/call", "id": 1,
                        "params": {"name": tool_name, "arguments": p.get("arguments", {})}
                    }
                    cases.append(FuzzCase(
                        name=f"ai_{tool_name}_{p.get('name', 'test')}",
                        generator="ai_fuzz",
                        payload=_frame(json.dumps(msg).encode()),
                        description=f"🧠 {tool_name}: {p.get('description', '')}",
                        expected_behavior="Server handles gracefully"
                    ))
            except Exception:
                continue
        
        return cases
    
    def _is_anomalous(self, result: FuzzResult) -> bool:
        """Detect anomalous responses that might indicate bugs."""
        if not result.response: return False
        try:
            text = result.response.decode("utf-8", errors="replace")
        except Exception:
            return True
        if any(x in text.lower() for x in ["traceback", "stack trace", "error:", "panic:"]):
            return True
        if result.elapsed_ms > 2000: return True
        if len(result.response) > 100_000: return True
        return False
    
    def _summarize(self, fuzzer: StdioFuzzer) -> dict:
        """Generate summary of fuzzing campaign."""
        return {
            "total_tests": fuzzer.test_count,
            "crashes": fuzzer.crash_count,
            "timeouts": fuzzer.timeout_count,
            "interesting": len(self.interesting),
            "error_log": fuzzer.error_log_path,
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
