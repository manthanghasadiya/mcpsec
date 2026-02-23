import time
import json
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

    def stop(self):
        """No-op for HTTP."""
        pass

    def restart(self):
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
                 self._log_event("CRASH", body, response.content, response.status_code)

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
            self._log_event("TIMEOUT", body)
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
            self._log_event("ERROR", body, error=str(e))
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

    def _log_event(self, event_type: str, request_body: bytes, response_body: bytes | None = None, status_code: int | None = None, error: str | None = None):
        """Log a fuzzer event to the log file."""
        from datetime import datetime
        timestamp = datetime.now().isoformat()
        
        with open(self.error_log_path, "a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"TIMESTAMP: {timestamp}\n")
            f.write(f"EVENT:     {event_type}\n")
            f.write(f"URL:       {self.url}\n")
            if status_code:
                f.write(f"STATUS:    {status_code}\n")
            if error:
                f.write(f"ERROR:     {error}\n")
            
            f.write("-" * 40 + " [REQUEST] " + "-" * 40 + "\n")
            try:
                # Attempt to pretty print JSON
                req_json = json.loads(request_body)
                f.write(json.dumps(req_json, indent=2))
            except:
                f.write(request_body.decode(errors="replace"))
            f.write("\n")
            
            if response_body:
                f.write("-" * 40 + " [RESPONSE] " + "-" * 40 + "\n")
                try:
                    resp_json = json.loads(response_body)
                    f.write(json.dumps(resp_json, indent=2))
                except:
                    f.write(response_body.decode(errors="replace"))
                f.write("\n")
            f.write(f"{'='*80}\n")

    def send_mcp_message_with_timeout(self, msg: dict, timeout: float) -> FuzzResult:
        """Helper to send a JSON-RPC message."""
        import json
        payload = json.dumps(msg).encode()
        return self.send_raw(payload)

    async def send_request_async(self, message: dict) -> Optional[dict]:
        """
        Async-friendly wrapper to send an MCP request and return the response.
        """
        import asyncio
        # Run the sync send_mcp_message_with_timeout in a thread
        result = await asyncio.to_thread(self.send_mcp_message_with_timeout, message, self.timeout)
        
        if result.response:
            try:
                return json.loads(result.response)
            except json.JSONDecodeError:
                return None
        return None

    async def send_notification_async(self, message: dict) -> None:
        """
        Async-friendly wrapper to send an MCP notification.
        """
        import asyncio
        await asyncio.to_thread(self.send_mcp_message_with_timeout, message, self.timeout)
