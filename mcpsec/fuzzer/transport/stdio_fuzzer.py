"""
Raw stdio transport for fuzzing — bypasses MCP SDK validation.
Spawns MCP server as subprocess and communicates via raw stdin/stdout.
"""

import asyncio
import json
import subprocess
import shutil
import sys
import threading
import time
from dataclasses import dataclass

@dataclass
class FuzzResult:
    """Result of sending a single fuzz case."""
    test_id: int
    generator: str          # Which generator created this
    payload: bytes          # Raw bytes sent
    response: bytes | None  # Raw bytes received (None if timeout/crash)
    elapsed_ms: float       # Time to response
    crashed: bool           # Server process died
    timeout: bool           # No response within timeout
    error_message: str = ""

class StdioFuzzer:
    """Manages a raw stdio connection to an MCP server for fuzzing."""
    
    def __init__(self, command: str, timeout: float = 5.0, debug: bool = False):
        self.command = command
        self.timeout = timeout
        self.debug = debug
        self.process: subprocess.Popen | None = None
        self.test_count = 0
        self.crash_count = 0
        self.timeout_count = 0
        self.interesting_count = 0
        self.interesting_count = 0
        self.stderr_lines: list[str] = []
        self.framing = "clrf" # Default to content-length framing

    def start_server(self):
        """Spawn the MCP server subprocess."""
        import shlex
        
        # Split command
        parts = shlex.split(self.command, posix=(sys.platform != "win32"))
        cmd = parts[0]
        args = parts[1:]
        
        # Resolve command path (vital for Windows batch files like npx.cmd)
        resolved = shutil.which(cmd)
        if not resolved and sys.platform == "win32":
            # Try appending .cmd or .bat if not found
            resolved = shutil.which(cmd + ".cmd") or shutil.which(cmd + ".bat")
            
        if resolved:
            cmd = resolved
        
        try:
            self.process = subprocess.Popen(
                [cmd] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False # Better for IO redirection than shell=True
            )
        except FileNotFoundError:
            # Fallback if resolution failed unexpectedly
            self.process = subprocess.Popen(
                parts, # Pass whole command list if path wasn't resolved
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False
            )
        
        # Start stderr consumer thread to prevent blocking
        self._stderr_thread = threading.Thread(target=self._consume_stderr, daemon=True)
        self._stderr_thread.start()

    def _consume_stderr(self):
        """Consume stderr to prevent buffer blocking and log if debug."""
        try:
            proc = self.process
            if not proc or not proc.stderr:
                return
            while proc.poll() is None:
                line = proc.stderr.readline()
                if line:
                    decoded = line.decode(errors='replace').strip()
                    self.stderr_lines.append(decoded)
                    if self.debug and decoded:
                        print(f"[stderr] {decoded}")
                else:
                    time.sleep(0.01)
        except:
            pass
    
    def stop_server(self):
        """Kill the server process."""
        proc = self.process
        if proc:
            proc.kill()
            proc.wait()
            self.process = None
    
    def restart_server(self):
        """Restart after crash."""
        self.stop_server()
        self.start_server()
    
    def is_alive(self) -> bool:
        """Check if server process is still running."""
        proc = self.process
        if not proc:
            return False
        return proc.poll() is None
    
    def send_raw(self, payload: bytes) -> FuzzResult:
        """
        Send raw bytes to the server and capture response.
        This is the core fuzzing primitive.
        """
        self.test_count += 1
        
        proc = self.process
        if not proc or not proc.stdin or not self.is_alive():
            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=None,
                elapsed_ms=0,
                crashed=True,
                timeout=False,
                error_message="Server not running"
            )
        
        start = time.perf_counter()
        
        try:
            # Write raw bytes to stdin
            if proc.stdin is None:
                return FuzzResult(
                    test_id=self.test_count,
                    generator="",
                    payload=payload,
                    response=None,
                    elapsed_ms=0,
                    crashed=True,
                    timeout=False,
                    error_message="Stdin not available"
                )
            
            # Explicit assertion for type checker
            assert proc.stdin is not None
            proc.stdin.write(payload)
            proc.stdin.flush()
            
            # Read response with timeout
            # MCP stdio protocol: Content-Length: N\r\n\r\n{json}
            response = self._read_response()
            elapsed = (time.perf_counter() - start) * 1000
            
            crashed = not self.is_alive()
            if crashed:
                self.crash_count += 1
            
            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=response,
                elapsed_ms=elapsed,
                crashed=crashed,
                timeout=False,
            )
            
        except TimeoutError:
            self.timeout_count += 1
            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=None,
                elapsed_ms=self.timeout * 1000,
                crashed=False,
                timeout=True,
            )
        except (BrokenPipeError, OSError) as e:
            self.crash_count += 1
            return FuzzResult(
                test_id=self.test_count,
                generator="",
                payload=payload,
                response=None,
                elapsed_ms=(time.perf_counter() - start) * 1000,
                crashed=True,
                timeout=False,
                error_message=str(e),
            )
    
    def _read_response(self) -> bytes | None:
        """Read a complete MCP response with timeout."""
        if self.framing == "jsonl":
            return self._read_jsonl_response()
        else:
            return self._read_clrf_response()
            
    def _read_jsonl_response(self) -> bytes | None:
        """Read a single JSON line."""
        # Use thread with timeout
        import threading
        result = [None]
        
        def _reader():
            try:
                if self.process and self.process.stdout:
                    line = self.process.stdout.readline()
                    if line:
                        result[0] = line.strip()
            except: pass
        
        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=self.timeout)
        
        if t.is_alive():
            raise TimeoutError()
            
        return result[0]

    def _read_clrf_response(self) -> bytes | None:
        """Read Content-Length framed response."""
        # Use a thread to read because select/poll doesn't work on Windows pipes
        import threading
        
        result: bytes | None = None
        error: Exception | None = None
        
        def _reader():
            nonlocal result, error
            try:
                proc = self.process
                if not proc or not proc.stdout:
                    return

                data = b""
                # Read header line by line until \r\n\r\n
                # Robustness fix: Handle potential stdout noise before headers
                # we read until we find the double CRLF, then look backwards for Content-Length
                while b"\r\n\r\n" not in data:
                    # Check if process died
                    if proc.poll() is not None:
                         return

                    byte = proc.stdout.read(1)
                    if not byte:
                        return  # EOF
                    data += byte
                
                # Split at the first \r\n\r\n
                parts = data.split(b"\r\n\r\n", 1)
                header_part = parts[0]
                
                # Parse Content-Length from the header part
                header_str = header_part.decode("utf-8", errors="replace")
                
                length = 0
                lines = header_str.splitlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line.lower().startswith("content-length:"):
                        try:
                            length = int(line.split(":", 1)[1].strip())
                            break
                        except ValueError:
                            pass
                
                # Read body (N bytes)
                body = b""
                while len(body) < length:
                    remaining = length - len(body)
                    chunk = proc.stdout.read(remaining)
                    if not chunk:
                        break
                    body += chunk
                
                result = body
                
            except Exception as e:
                error = e
        
        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=self.timeout)
        
        if t.is_alive():
            # Timeout — thread is stuck on read
            raise TimeoutError()
        
        if error is not None:
            raise error
            
        return result
    
    def send_mcp_message(self, message: dict) -> FuzzResult:
        """
        Convenience: send a properly framed MCP message.
        Encodes as JSON, adds Content-Length header.
        """
        return self.send_mcp_message_with_timeout(message, self.timeout)

    def send_mcp_message_with_timeout(self, message: dict, timeout: float) -> FuzzResult:
        """Send a properly framed MCP message with a specific timeout."""
        json_bytes = json.dumps(message).encode("utf-8")
        
        if self.framing == "jsonl":
            # Python SDK: just newline-delimited JSON
            payload = json_bytes + b"\n"
        else:
            # Node SDK: Content-Length framing (default)
            payload = f"Content-Length: {len(json_bytes)}\r\n\r\n".encode() + json_bytes
        
        # We can implement this by temporarily swapping self.timeout or by passing timeout to send_raw
        # Use a temporary swap for now since send_raw relies on self._read_response which uses self.timeout
        old_timeout = self.timeout
        self.timeout = timeout
        try:
            return self.send_raw(payload)
        finally:
            self.timeout = old_timeout
    
    def send_malformed(self, raw_bytes: bytes, generator_name: str = "") -> FuzzResult:
        """Send raw malformed bytes (no framing)."""
        result = self.send_raw(raw_bytes)
        result.generator = generator_name
        return result
