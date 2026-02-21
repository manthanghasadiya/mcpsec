import asyncio
import json
import logging
import subprocess
import shutil
import sys
import time
from typing import Optional
from dataclasses import dataclass

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

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
    
    def __init__(self, command: str, timeout: float = 5.0, debug: bool = False, error_log_path: str = "mcpsec_fuzz_stderr.log"):
        self.command = command
        self.timeout = timeout
        self.debug = debug
        self.error_log_path = error_log_path
        self.process: subprocess.Popen | None = None
        self.error_file = None
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
        
        # Open error log file to safely redirect massive standard error dumps
        # This prevents 65KB pipe buffer deadlock while preserving the logs
        self.error_file = open(self.error_log_path, "ab")
        
        try:
            self.process = subprocess.Popen(
                [cmd] + args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.error_file,
                shell=False
            )
        except Exception:
            # Fallback
            self.process = subprocess.Popen(
                parts,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.error_file,
                shell=False
            )

    def stop_server(self):
        """Kill the server process and close logs."""
        proc = self.process
        if proc:
            proc.kill()
            proc.wait()
            self.process = None
            
        if self.error_file and not self.error_file.closed:
            self.error_file.flush()
            self.error_file.close()
            self.error_file = None

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
            import threading
            from typing import List
            result_obj: List[bytes | None] = [None]
            error_obj: List[Exception | None] = [None]
            
            def _execute():
                try:
                    if not proc or not proc.stdin: return
                    proc.stdin.write(payload)
                    proc.stdin.flush()
                    result_obj[0] = self._read_response()
                except Exception as e:
                    error_obj[0] = e
                    
            t = threading.Thread(target=_execute, daemon=True)
            t.start()
            t.join(timeout=self.timeout)
            
            if t.is_alive():
                # We are permanently hung on write() or read().
                self._force_kill()
                raise TimeoutError()
                
            if error_obj[0]:
                raise error_obj[0]
                
            response = result_obj[0]
            elapsed = (time.perf_counter() - start) * 1000
            
            # ─────────────────────────────────────────────────────────────
            # FIX: Fuzzer State Desync / Payload Bleed
            # Wait 50ms for the OS to purge buffers and the process to die
            # if the payload caused a fatal exception.
            time.sleep(0.05)
            # ─────────────────────────────────────────────────────────────
            
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
            
            # ─────────────────────────────────────────────────────────────
            # FIX: Fuzzer State Desync / Payload Bleed
            # If we timed out, wait 50ms to see if the process actually 
            # died but the OS hadn't updated poll() yet.
            time.sleep(0.05)
            # ─────────────────────────────────────────────────────────────
            
            crashed = not self.is_alive()
            if crashed:
                self.crash_count += 1
                return FuzzResult(
                    test_id=self.test_count,
                    generator="",
                    payload=payload,
                    response=None,
                    elapsed_ms=self.timeout * 1000,
                    crashed=True,
                    timeout=False,
                    error_message="Server crashed after timeout"
                )
                
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
        """Read a complete MCP response synchronously."""
        if self.framing == "jsonl":
            return self._read_jsonl_response()
        else:
            return self._read_clrf_response()
            
    def _read_jsonl_response(self) -> bytes | None:
        """Read a single JSON line synchronously."""
        if not self.process or not self.process.stdout:
            return None
        try:
            line = self.process.stdout.readline()
            return line.strip() if line else None
        except:
            return None

    def _read_clrf_response(self) -> bytes | None:
        """Read Content-Length framed response synchronously."""
        proc = self.process
        if not proc or not proc.stdout:
            return None
        
        try:
            data = b""
            # 1. Read header until \r\n\r\n
            while b"\r\n\r\n" not in data:
                if proc.poll() is not None:
                     return None
                byte = proc.stdout.read(1)
                if not byte:
                    return None
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
            
            return body
        except:
            return None

    def _force_kill(self):
        """Violently sever the subprocess tree to clear IO locks on Windows."""
        if self.process:
            try:
                import psutil
                parent = psutil.Process(self.process.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except:
                try:
                    self.process.kill()
                    self.process.terminate()
                except: pass

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
