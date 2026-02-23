import time
import httpx
from typing import Optional
from mcpsec.fuzzer.transport.stdio_fuzzer import FuzzResult

class HttpFuzzer:
    """
    Manages an HTTP connection to an MCP server for fuzzing.
    Supports custom headers for authentication.
    """
    
    def __init__(self, url: str, timeout: float = 5.0, debug: bool = False, headers: Optional[dict] = None):
        self.url = url
        self.timeout = timeout
        self.debug = debug
        self.headers = headers or {}
        # Ensure Content-Type if not provided
        if "Content-Type" not in self.headers and "content-type" not in {k.lower() for k in self.headers}:
            self.headers["Content-Type"] = "application/json"
            
        self.process = None # Complement for StdioFuzzer
        self.test_count = 0
        self.crash_count = 0
        self.timeout_count = 0
        self.framing = "jsonl" # Default to no framing for HTTP bodies
        self.error_log_path = "mcpsec_fuzz_http.log"

    def start_server(self):
        """No-op for HTTP."""
        pass

    def stop_server(self):
        """No-op for HTTP."""
        pass

    def restart_server(self):
        """No-op for HTTP."""
        pass

    def is_alive(self, strict: bool = False) -> bool:
        """HTTP targets are assumed alive."""
        return True

    def _check_real_crash(self) -> tuple[bool, str]:
        """HTTP fuzzer cannot detect remote server crashes easily."""
        return False, ""

    def send_raw(self, payload: bytes) -> FuzzResult:
        """Send raw bytes via POST and capture response."""
        self.test_count += 1
        
        # Strip potential stdio framing (Content-Length: ...\r\n\r\n)
        # if the payload comes from a generator that assumed stdio framing.
        body = payload
        if b"\r\n\r\n" in payload:
            try:
                # Basic attempt to strip headers if they look like stdio framing
                parts = payload.split(b"\r\n\r\n", 1)
                if b"Content-Length:" in parts[0]:
                    body = parts[1]
            except Exception:
                pass

        start = time.perf_counter()
        
        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    self.url,
                    content=body,
                    headers=self.headers
                )
                
            elapsed = (time.perf_counter() - start) * 1000
            
            # For HTTP, 5xx might be considered a "crash" of sorts or at least interesting
            crashed = response.status_code >= 500
            if crashed:
                 self.crash_count += 1

            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=response.content,
                elapsed_ms=elapsed,
                crashed=crashed,
                timeout=False,
                error_message=f"HTTP Status {response.status_code}" if crashed else ""
            )
            
        except httpx.TimeoutException:
            self.timeout_count += 1
            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=None,
                elapsed_ms=0,
                crashed=False,
                timeout=True,
                error_message="HTTP Timeout"
            )
        except Exception as e:
            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=None,
                elapsed_ms=0,
                crashed=False,
                timeout=False,
                error_message=str(e)
            )

    def send_mcp_message_with_timeout(self, msg: dict, timeout: float) -> FuzzResult:
        """Helper to send a JSON-RPC message."""
        import json
        payload = json.dumps(msg).encode()
        return self.send_raw(payload)
