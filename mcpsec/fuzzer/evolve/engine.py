"""Main evolutionary fuzzing engine."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

from .corpus import Corpus, CorpusEntry
from .feedback import FeedbackCollector, ResponseFingerprint, ResponseType
from .mutators import MutationEngine
from .mcp_mutators import MCPStructureMutator, MCPToolCallMutator
from .scheduler import Scheduler


console = Console()


@dataclass
class EvolveFuzzConfig:
    """Configuration for evolutionary fuzzing."""

    # Execution
    timeout: float = 5.0
    max_iterations: int = 100000
    max_time: int = 3600  # 1 hour default

    # Corpus
    corpus_dir: Path | None = None
    seed_dir: Path | None = None
    crash_dir: Path | None = None

    # Mutation
    max_mutations_per_input: int = 8
    mcp_mutation_weight: float = 0.8  # 80% MCP-aware, 20% raw bytes

    # Display
    stats_interval: float = 1.0

    # Debug
    debug: bool = False


@dataclass
class EvolveFuzzStats:
    """Runtime statistics."""

    start_time: float = field(default_factory=time.time)
    iterations: int = 0
    crashes: int = 0
    timeouts: int = 0
    unique_crashes: int = 0
    unique_behaviors: int = 0
    corpus_size: int = 0
    execs_per_sec: float = 0.0
    last_new_behavior: float = field(default_factory=time.time)
    cycle_count: int = 0


class EvolveFuzzEngine:
    """Coverage-guided evolutionary fuzzer for MCP servers."""

    def __init__(
        self,
        target_command: str,
        config: EvolveFuzzConfig | None = None,
        transport: str = "stdio",
    ):
        self.target_command = target_command
        self.config = config or EvolveFuzzConfig()
        self.transport = transport

        # Initialize components
        self.corpus = Corpus(self.config.corpus_dir)
        self.feedback = FeedbackCollector()
        self.mutation_engine = MutationEngine()
        self.scheduler = Scheduler(self.corpus)

        # Set mutation weights
        self.mutation_engine.set_mcp_weight(self.config.mcp_mutation_weight)

        # MCP-aware mutators (added after tool discovery)
        self.mcp_structure_mutator = MCPStructureMutator()
        self.mcp_tool_mutator = MCPToolCallMutator()

        self.stats = EvolveFuzzStats()
        self.known_tools: list[str] = []

        # Process management
        self.process: subprocess.Popen | None = None
        self.should_stop = False

        # Crash directory
        if self.config.crash_dir:
            self.config.crash_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> dict[str, Any]:
        """Run the fuzzing campaign."""
        console.print(Panel.fit(
            "[bold cyan]mcpsec evolve - Evolutionary MCP Fuzzer[/bold cyan]\n"
            f"Target: {self.target_command}\n"
            f"Max iterations: {self.config.max_iterations}\n"
            f"Max time: {self.config.max_time}s\n"
            f"MCP mutation weight: {self.config.mcp_mutation_weight:.0%}",
            border_style="cyan"
        ))

        # Load existing corpus or create seeds
        self._load_or_create_seeds()

        # Discover tools
        await self._discover_tools()

        # Update mutators with tool knowledge
        self.mcp_tool_mutator.set_tools(self.known_tools)
        self.mutation_engine.add_mcp_mutators([
            self.mcp_structure_mutator,
            self.mcp_tool_mutator,
        ])

        # Main fuzzing loop
        self.stats.start_time = time.time()

        try:
            with Live(self._create_stats_table(), refresh_per_second=2) as live:
                while not self._should_stop():
                    await self._fuzz_one()
                    self.stats.iterations += 1

                    if self.stats.iterations % 10 == 0:
                        self._update_stats()
                        live.update(self._create_stats_table())
        except KeyboardInterrupt:
            console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")

        return self._generate_report()

    def _should_stop(self) -> bool:
        """Check if fuzzing should stop."""
        if self.should_stop:
            return True
        if self.stats.iterations >= self.config.max_iterations:
            return True
        if time.time() - self.stats.start_time > self.config.max_time:
            return True
        return False

    def _load_or_create_seeds(self):
        """Load existing corpus or create initial seeds."""
        self.corpus.load()

        if self.config.seed_dir and self.config.seed_dir.exists():
            for seed_file in self.config.seed_dir.glob("*.json"):
                try:
                    data = seed_file.read_bytes()
                    entry = CorpusEntry(
                        data=data,
                        fingerprint=ResponseFingerprint(ResponseType.SUCCESS),
                        source="seed",
                    )
                    self.corpus.add(entry)
                except Exception:
                    continue

        if not self.corpus.entries:
            self._create_default_seeds()

    def _create_default_seeds(self):
        """Create initial seed inputs."""
        seeds = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-evolve", "version": "1.0"}
            }},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
            {"jsonrpc": "2.0", "id": 4, "method": "prompts/list"},
            {"jsonrpc": "2.0", "id": 5, "method": "ping"},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
                "name": "test", "arguments": {}
            }},
        ]

        for seed in seeds:
            data = json.dumps(seed).encode("utf-8")
            entry = CorpusEntry(
                data=data,
                fingerprint=ResponseFingerprint(ResponseType.SUCCESS),
                source="seed",
            )
            self.corpus.add(entry)

    async def _discover_tools(self):
        """Discover available tools from target server."""
        console.print("[dim]Discovering tools...[/dim]")

        try:
            self.process = await self._start_server()

            # Send initialize
            init_req = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcpsec-evolve", "version": "1.0"}
                }
            }).encode() + b"\n"

            self.process.stdin.write(init_req)
            self.process.stdin.flush()

            await asyncio.sleep(0.5)

            # Send initialized notification
            notif = json.dumps({
                "jsonrpc": "2.0", "method": "notifications/initialized"
            }).encode() + b"\n"
            self.process.stdin.write(notif)
            self.process.stdin.flush()

            await asyncio.sleep(0.5)

            # Request tools list
            tools_req = json.dumps({
                "jsonrpc": "2.0", "id": 2, "method": "tools/list"
            }).encode() + b"\n"
            self.process.stdin.write(tools_req)
            self.process.stdin.flush()

            # Read response
            response = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, self.process.stdout.readline
                ),
                timeout=5.0
            )

            if response:
                for line in response.decode().strip().split("\n"):
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and "result" in obj and isinstance(obj.get("result"), dict):
                            tools = obj["result"].get("tools")
                            if isinstance(tools, list):
                                self.known_tools = [t.get("name", "") for t in tools if isinstance(t, dict) and t.get("name")]
                                console.print(f"[green]Discovered {len(self.known_tools)} tools[/green]")
                                break
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            if self.config.debug:
                console.print(f"[yellow]Tool discovery failed: {e}[/yellow]")

        finally:
            await self._stop_server()

    async def _start_server(self) -> subprocess.Popen:
        """Start the target server."""
        if os.name == "nt":
            cmd = self.target_command
            shell = True
        else:
            import shlex
            cmd = shlex.split(self.target_command)
            shell = False

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            bufsize=0,
        )

        await asyncio.sleep(0.3)
        return process

    async def _stop_server(self):
        """Stop the target server."""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None

    async def _fuzz_one(self):
        """Execute one fuzzing iteration."""
        entry = self.scheduler.next()
        if not entry:
            return

        mutated_data = self._mutate(entry.data)
        result = await self._execute(mutated_data)

        fingerprint, is_new = self.feedback.analyze_response(
            response=result.get("response"),
            response_time=result.get("time", 0),
            crashed=result.get("crashed", False),
            timeout=result.get("timeout", False),
            stderr=result.get("stderr"),
        )

        if is_new:
            new_entry = CorpusEntry(
                data=mutated_data,
                fingerprint=fingerprint,
                source="mutation",
                parent_hash=entry.data_hash,
            )
            self.corpus.add(new_entry)
            self.scheduler.notify_new_coverage(new_entry)
            self.stats.unique_behaviors += 1
            self.stats.last_new_behavior = time.time()

            if fingerprint.response_type == ResponseType.CRASH:
                self.stats.unique_crashes += 1
                self._save_crash(new_entry, result)

        self.corpus.update_energy(entry.data_hash, is_new)

        if result.get("crashed"):
            self.stats.crashes += 1
        if result.get("timeout"):
            self.stats.timeouts += 1

        self.stats.corpus_size = len(self.corpus.entries)

    def _mutate(self, data: bytes) -> bytes:
        """Mutate input data."""
        num_mutations = 1 + (self.stats.iterations % self.config.max_mutations_per_input)
        return self.mutation_engine.mutate(data, num_mutations)

    async def _execute(self, data: bytes) -> dict[str, Any]:
        """Execute payload against target and collect feedback."""
        result: dict[str, Any] = {
            "response": None,
            "time": 0,
            "crashed": False,
            "timeout": False,
            "stderr": None,
        }

        try:
            self.process = await self._start_server()
            start_time = time.time()

            if not data.endswith(b"\n"):
                data = data + b"\n"

            self.process.stdin.write(data)
            self.process.stdin.flush()

            try:
                response_line = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self.process.stdout.readline
                    ),
                    timeout=self.config.timeout
                )

                result["time"] = time.time() - start_time

                if response_line:
                    try:
                        result["response"] = json.loads(response_line.decode())
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        result["response"] = {"raw": response_line.decode(errors="replace")}

            except asyncio.TimeoutError:
                result["timeout"] = True
                result["time"] = self.config.timeout

            ret = self.process.poll()
            if ret is not None and ret != 0:
                result["crashed"] = True
                try:
                    stderr = self.process.stderr.read(4096).decode(errors="replace")
                    result["stderr"] = stderr
                except Exception:
                    pass

        except Exception as e:
            result["crashed"] = True
            result["stderr"] = str(e)

        finally:
            await self._stop_server()

        return result

    def _save_crash(self, entry: CorpusEntry, result: dict[str, Any]):
        """Save crash information."""
        if not self.config.crash_dir:
            return

        crash_file = self.config.crash_dir / f"crash_{entry.data_hash}.json"
        crash_data = {
            "payload": entry.data.hex(),
            "payload_str": entry.data.decode(errors="replace"),
            "stderr": result.get("stderr"),
            "timestamp": time.time(),
            "iteration": self.stats.iterations,
        }

        with open(crash_file, "w") as f:
            json.dump(crash_data, f, indent=2)

        payload_file = self.config.crash_dir / f"crash_{entry.data_hash}.bin"
        with open(payload_file, "wb") as f:
            f.write(entry.data)

    def _update_stats(self):
        """Update statistics."""
        elapsed = time.time() - self.stats.start_time
        self.stats.execs_per_sec = self.stats.iterations / max(elapsed, 0.001)

    def _create_stats_table(self) -> Table:
        """Create stats display table."""
        elapsed = time.time() - self.stats.start_time
        time_since_new = time.time() - self.stats.last_new_behavior
        feedback_stats = self.feedback.get_stats()

        table = Table(title="mcpsec evolve - Evolutionary Fuzzer", border_style="cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Iterations", f"{self.stats.iterations:,}")
        table.add_row("Exec/sec", f"{self.stats.execs_per_sec:.1f}")
        table.add_row("Corpus size", f"{self.stats.corpus_size}")
        table.add_row("Unique behaviors", f"{self.stats.unique_behaviors}")
        table.add_row("Crashes", f"{self.stats.crashes} ({self.stats.unique_crashes} unique)")
        table.add_row("Timeouts", f"{self.stats.timeouts}")
        table.add_row("Parse errors", f"{feedback_stats['parse_error_count']} ({feedback_stats['parse_error_ratio']:.1%})")
        table.add_row("Elapsed", f"{elapsed:.0f}s")
        table.add_row("Last new", f"{time_since_new:.0f}s ago")
        table.add_row("Known tools", f"{len(self.known_tools)}")

        return table

    def _generate_report(self) -> dict[str, Any]:
        """Generate final report."""
        crashes = self.corpus.get_crashes()

        report = {
            "stats": {
                "iterations": self.stats.iterations,
                "duration": time.time() - self.stats.start_time,
                "execs_per_sec": self.stats.execs_per_sec,
                "crashes": self.stats.crashes,
                "unique_crashes": self.stats.unique_crashes,
                "unique_behaviors": self.stats.unique_behaviors,
                "corpus_size": self.stats.corpus_size,
            },
            "crashes": [
                {
                    "hash": c.data_hash,
                    "payload": c.data.decode(errors="replace"),
                    "fingerprint": c.fingerprint.response_type.name,
                }
                for c in crashes
            ],
            "corpus_stats": self.corpus.stats(),
            "feedback_stats": self.feedback.get_stats(),
        }

        console.print("\n")
        console.print(Panel.fit(
            f"[bold]Fuzzing Complete[/bold]\n\n"
            f"Iterations: {self.stats.iterations:,}\n"
            f"Unique behaviors: {self.stats.unique_behaviors}\n"
            f"Unique crashes: {self.stats.unique_crashes}\n"
            f"Corpus size: {self.stats.corpus_size}\n"
            f"Duration: {time.time() - self.stats.start_time:.0f}s",
            border_style="green" if self.stats.unique_crashes == 0 else "red"
        ))

        if crashes:
            console.print("\n[bold red]Crashes Found:[/bold red]")
            for crash in crashes[:10]:
                console.print(f"  - {crash.data_hash}: {crash.data[:100]!r}")

        return report
