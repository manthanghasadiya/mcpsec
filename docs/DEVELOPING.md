# Developer Guide

This guide walks you through setting up your environment, adding new detectors, writing tests, and following project conventions.

## Development Setup

mcpsec requires Python 3.11 or newer. We recommend developing inside a virtual environment.

```bash
git clone https://github.com/manthanghasadiya/mcpsec.git
cd mcpsec

python3 -m venv .venv
source .venv/bin/activate

# Install mcpsec in editable mode with development dependencies
pip install -e ".[dev]"
```

### Running Tests

Run the full test suite with pytest:

```bash
pytest tests/ -q
```

To run a specific test file or test case:

```bash
pytest tests/test_evidence_model.py -v
pytest tests/test_command_injection_oracle.py -k "test_arithmetic_canary"
```

### Code Formatting and Linting

We use Ruff for linting and code formatting:

```bash
# Check code for lint errors
ruff check .

# Apply safe automatic fixes
ruff check . --fix

# Verify code formatting
ruff format --check .

# Reformat files
ruff format .
```

Continuous integration runs these exact checks on every pull request across Ubuntu, Windows, and macOS. PRs must pass linting and tests before merging.

## Repository Layout

```
mcpsec/
├── ai/                      AI client integration and finding classifiers
├── client/                  Live MCP client connecting via stdio or HTTP/SSE
├── fuzzer/                  Protocol fuzzing engine
│   ├── generators/          Fuzz case generators organized by vulnerability class
│   ├── transport/           Subprocess stdio and HTTP transport managers
│   └── baseline.py          Differential response analyzer
├── scanners/                Active vulnerability scanners
│   ├── oracles/             Verification oracles (canary, sentinel, OOB HTTP)
│   ├── base.py              BaseScanner abstract base class
│   ├── param_selection.py   Unified candidate parameter selector
│   └── response_classifier.py Defensive response and sandbox pattern matcher
├── static/                  Static analysis engine (Audit v3)
│   ├── analysis/            Regex sink patterns and reachability analyzers
│   ├── framework/           Language and MCP framework detection
│   └── semgrep/             AST-level Semgrep rulesets
├── cli.py                   CLI entry points and commands
├── config.py                Configuration files and credentials storage
└── models.py                ServerProfile, Finding, Severity, and evidence validation

tests/
├── corpus/                  Data-driven recall corpus test harness
├── servers/                 Mock vulnerable and defensive MCP server fixtures
└── test_*.py                Unit, scanner, fuzzer, and oracle test suites
```

## Adding a Runtime Scanner

All runtime scanners live in `mcpsec/scanners/` and inherit from `BaseScanner` (`mcpsec/scanners/base.py`).

### Step-by-Step Implementation

1. Create a new module in `mcpsec/scanners/` (for example, `mcpsec/scanners/my_scanner.py`).
2. Subclass `BaseScanner` and declare a unique `name` and `description`.
3. Use `candidate_injectable_params(tool)` from `mcpsec/scanners/param_selection.py` to identify string parameters to probe.
4. Call `self._get_dummy_args(tool, target_param, payload)` to ensure required sibling arguments are populated with valid dummy values.
5. Apply the `response_classifier` SAFE guard: if a response matches known error codes or sandbox block patterns, do not report it.
6. Emit findings exclusively through `self.create_finding(...)` to ensure compliance with the evidence model.

### Scanner Skeleton

```python
from __future__ import annotations

from typing import Any
from mcpsec.client.mcp_client import MCPSecClient
from mcpsec.models import Finding, ServerProfile, Severity
from mcpsec.scanners.base import BaseScanner
from mcpsec.scanners.param_selection import candidate_injectable_params
from mcpsec.scanners.response_classifier import classify_response, Verdict


class MyScanner(BaseScanner):
    name = "my-scanner"
    description = "Checks tools for my vulnerability class"

    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]:
        if not client:
            return []

        findings: list[Finding] = []

        for tool in profile.tools:
            params = candidate_injectable_params(tool, max_params=self.max_params_per_tool)
            for param in params:
                payload = "..."
                args = self._get_dummy_args(tool, param, payload)

                try:
                    res = await client.call_tool(tool.name, args, timeout=10.0)
                    response_text = str(res)
                except Exception:
                    continue

                # Run the SAFE check first
                verdict = classify_response(response_text)
                if verdict == Verdict.SAFE:
                    continue

                # Heuristic or pattern match: emit as suspected
                if "some_error_indicator" in response_text:
                    findings.append(
                        self.create_finding(
                            severity=Severity.HIGH,
                            tool_name=tool.name,
                            parameter=param,
                            title=f"Potential issue in '{param}'",
                            evidence=f"Matched indicator in response: {response_text[:120]}",
                            confidence="suspected",
                            remediation="Sanitize user input before processing.",
                        )
                    )

        return findings
```

Register your new scanner in `mcpsec/scanners/__init__.py` and add it to `SCANNERS` in `mcpsec/engine.py`.

## Adding a Detection Oracle

Oracles live in `mcpsec/scanners/oracles/`. They verify whether an attack succeeded by checking for an observable effect rather than input reflection.

### The Confirm-by-Effect Contract

Only two conditions allow emitting a finding with `confidence="confirmed"`:
1. **Observable side effect**: An out-of-band network request was captured by the OOB collector, a planted sentinel file was read or written on the filesystem, or a computed mathematical canary was evaluated by an execution engine.
2. **Structural proof**: A parsed dictionary confirming access to cloud metadata (containing required co-occurring identity keys) or an equivalent unambiguous structure.

Raw string reflection, database syntax errors, and HTTP 500 status codes are not proof of execution. They must be emitted as `confidence="suspected"`.

### Oracle Pattern Example

```python
import secrets


async def confirm_vulnerability(
    call_fn: Any,
    tool_name: str,
    param_name: str,
    dummy_args: dict[str, Any],
) -> tuple[bool, str]:
    """Test for vulnerability by effect. Returns (confirmed, evidence)."""
    nonce = secrets.token_hex(8)
    # Build payload containing nonce that only executes under real injection
    payload = f"echo {nonce}"
    args = dict(dummy_args)
    args[param_name] = payload

    response_text, _ = await call_fn(tool_name, args)

    if nonce in response_text and payload not in response_text:
        return True, f"Canary {nonce} observed in output without payload reflection"

    return False, ""
```

## Adding a Fuzz Generator

Fuzz generators live in `mcpsec/fuzzer/generators/` and subclass `BaseGenerator` (`mcpsec/fuzzer/generators/base.py`).

1. Create a module such as `mcpsec/fuzzer/generators/my_generator.py`.
2. Implement `generate(self, tools: list[dict]) -> list[FuzzCase]`.
3. Each `FuzzCase` includes a descriptive name, generator name, payload data, and target parameter path.
4. Place the generator into an intensity tier in `mcpsec/fuzzer/fuzz_engine.py`:
   - `low`: Core protocol and framing checks
   - `medium`: Encoding and boundary cases
   - `high`: Injection payloads, complex mutations, and timing checks
   - `insane`: Exhaustion and heavy recursion cases

## Adding an Audit Sink Pattern

Static sink patterns are defined in `mcpsec/static/pattern_db.py`.

To add a pattern:
1. Locate the appropriate vulnerability category in `PATTERN_DATABASE` (for example, `command_injection`, `path_traversal`, or `ssrf`).
2. Add a `SinkPattern` defining:
   - `pattern`: compiled regular expression matching the dangerous call
   - `languages`: list of languages where this sink applies
   - `confidence`: default confidence rating (`HIGH`, `MEDIUM`)
   - `description`: clear explanation of the sink risk
   - `cwe`: relevant CWE identifier

Ensure that new regex patterns do not match common sanitization wrappers or safe standard library helpers.

## The Evidence Model Contributor Rule

Every contributor must observe the evidence model invariant:

> **No finding with confidence other than "confirmed" may carry CRITICAL severity.**

If your scanner identifies an unconfirmed indicator, pattern match, or error trace, emit it as `confidence="suspected"`. The `Finding` model validator automatically caps suspected findings at `HIGH` severity.

To verify your code adheres to this rule, run:

```bash
pytest tests/test_evidence_model.py -v
```

## Test Layout and Discipline

### Test Directories

- `tests/`: Unit tests for scanners, oracles, models, and CLI routines.
- `tests/servers/`: Lightweight mock MCP servers implemented in Python. These provide controlled environments that test specific vulnerabilities (such as command injection, SQL injection, and path traversal) without external services.
- `tests/corpus/`: Data-driven recall corpus test harness (`tests/corpus/harness.py`). It loads local target manifests from `tests/corpus/targets_local/`.

### Import Discipline (`pytest.importorskip`)

Test modules that depend on optional or dev-only packages (such as `yaml`) must guard imports using `pytest.importorskip`:

```python
yaml = pytest.importorskip("yaml", reason="PyYAML is required for YAML test fixtures")
```

This prevents missing optional dependencies from causing test collection failures in minimal environments.

### Keeping CI Green

Continuous integration runs on Linux, macOS, and Windows runners across Python 3.11 and 3.12. CI enforces clean runs:
- Tests must pass without unexpected errors or timeouts.
- Target servers must terminate cleanly without orphaned child processes.
- Do not leave temporary files in the repository tree. Always use `tempfile.gettempdir()` and clean up in `finally` blocks.
