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
        self.stderr_lines: list[str] = []
        self.framing = "clrf" # Default to content-length framing

    def start_server(self):
        """Spawn the MCP server subprocess."""
        import shlex
        
        # Split command
        is_windows = sys.platform == "win32"
        parts = shlex.split(self.command, posix=not is_windows)
        cmd = parts[0]
        args = parts[1:]
        
        # Resolve command path (vital for Windows batch files like npx.cmd)
        resolved = shutil.which(cmd)
        if not resolved and is_windows:
            resolved = shutil.which(cmd + ".cmd") or shutil.which(cmd + ".bat")
            
        if resolved:
            cmd = resolved
        
        try:
            self.process = subprocess.Popen(
                [cmd] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, # CRITICAL: prevent OS buffer saturation deadlock
                shell=False
            )
        except Exception:
            # Fallback
            self.process = subprocess.Popen(
                parts,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False
            )

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
            proc.stdin.write(payload)
            proc.stdin.flush()
            
            # Read response with timeout
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
                # 1. Read header until \r\n\r\n
                while b"\r\n\r\n" not in data:
                    if proc.poll() is not None:
                         return
                    byte = proc.stdout.read(1)
                    if not byte:
                        return
                    data += byte
                    if len(data) > 1024 * 1024: break # Safety
                
                # 2. Extract length
                header_part = data.split(b"\r\n\r\n", 1)[0]
                header_str = header_part.decode("utf-8", errors="replace")
                
                length = 0
                for line in reversed(header_str.splitlines()):
                    l_line = line.strip().lower()
                    if l_line.startswith("content-length:"):
                        try:
                            length = int(l_line.split(":", 1)[1].strip())
                            break
                        except ValueError: pass
                
                # 3. Read body
                body = b""
                while len(body) < length:
                    chunk = proc.stdout.read(min(length - len(body), 8192))
                    if not chunk: break
                    body += chunk
                
                result = body
                
            except Exception as e:
                error = e
        
        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=self.timeout)
        
        if t.is_alive():
            raise TimeoutError()
        if error:
            raise error
            
        return result

    def send_mcp_message_with_timeout(self, message: dict, timeout: float) -> FuzzResult:
        """Send formatted message with custom timeout."""
        json_bytes = json.dumps(message).encode("utf-8")
        if self.framing == "jsonl":
            payload = json_bytes + b"\n"
        else:
            payload = f"Content-Length: {len(json_bytes)}\r\n\r\n".encode() + json_bytes
        
        old_timeout = self.timeout
        self.timeout = timeout
        try:
            return self.send_raw(payload)
        finally:
            self.timeout = old_timeout

    def send_mcp_message(self, message: dict) -> FuzzResult:
        return self.send_mcp_message_with_timeout(message, self.timeout)

    def send_malformed(self, raw_bytes: bytes, generator_name: str = "") -> FuzzResult:
        result = self.send_raw(raw_bytes)
        result.generator = generator_name
        return result
