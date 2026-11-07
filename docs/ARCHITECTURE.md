# Architecture

This document describes how mcpsec is structured internally, how its components interact, and the principles behind its detection design.

## The Three Engines

mcpsec analyzes Model Context Protocol (MCP) implementations through three distinct analysis engines that operate over a shared data model:

```
                      Target Server or Source Code
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │ (live JSON-RPC)         │ (source files)          │ (raw transport)
         ▼                         ▼                         ▼
   Runtime Scanner           Static Audit             Protocol Fuzzer
   (mcpsec/scanners/)        (mcpsec/static/)         (mcpsec/fuzzer/)
         │                         │                         │
         │                         ▼                         │
         │                  Semgrep + AST + AI               │
         │                         │                         │
         ▼                         │                         ▼
   Detection Oracles               │                 Baseline Differential
 (mcpsec/scanners/oracles)         │                 (mcpsec/fuzzer/baseline.py)
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   │
                                   ▼
                         Unified Finding Model
                         (mcpsec/models.py)
                                   │
                         CLI / JSON / SARIF
```

1. **Runtime Scanner (`mcpsec/scanners/`, `mcpsec/engine.py`)**: Connects to live MCP servers over stdio or HTTP/SSE, enumerates tools, resources, and prompts, and drives targeted security probes through the MCP protocol session. It tests parameters using detection oracles that verify vulnerabilities by observable effect.
2. **Static Audit (`mcpsec/static/`, `mcpsec/static/audit_engine.py`)**: Inspects server source code without execution. It runs regex sink patterns across 12 languages, applies 149 Semgrep rules, performs Python/JavaScript AST analysis, and optionally traces data flow using LLM reachability analysis.
3. **Protocol Fuzzer (`mcpsec/fuzzer/`, `mcpsec/fuzzer/fuzz_engine.py`)**: Communicates with servers through raw transport channels to test parser resilience, framing compliance, state transitions, and boundary handling. It benchmarks each tool with a baseline run and isolates genuine crashes from harness disconnections.

All three engines emit findings into the central data structures defined in `mcpsec/models.py`.

## Shared Data and Evidence Model

The core data structures live in `mcpsec/models.py`.

### ServerProfile

`ServerProfile` captures the attack surface of a connected MCP server:

- `tools`: list of `ToolInfo` records containing tool names, descriptions, input schemas, parameter types, and annotations.
- `resources`: list of `ResourceInfo` records containing URIs, MIME types, and descriptions.
- `prompts`: list of `PromptInfo` records with template argument definitions.
- `capabilities`: dictionary of server-declared capabilities (tools, resources, prompts, logging).
- `transport`: connection protocol (`stdio` or `http`).

### Finding and the Evidence Model

A `Finding` represents a detected vulnerability. In earlier scanner versions, tools that echoed input or returned general error messages could be misclassified as critical vulnerabilities. To prevent false positives without dropping recall, mcpsec enforces an evidence model inside `Finding` and `create_finding`:

- **Confirmed (`confidence="confirmed"`)**: The scanner holds deterministic proof of execution. Proof requires an effect oracle hit (such as a planted sentinel file returned on disk, a unique out-of-band HTTP request, or an arithmetic canary expression evaluated by a shell) or an unambiguous structural signature (such as a parsed JSON cloud metadata object). Confirmed findings may carry `CRITICAL` severity and display `[CONFIRMED]` in reports.
- **Suspected (`confidence="suspected"`)**: The scanner observed heuristic indicators, regex pattern matches, database syntax errors, or reflections. Suspected findings are never dropped, ensuring human auditors can review them. However, they are capped at `HIGH` severity (never `CRITICAL`), display `[SUSPECTED]` in reports, and carry an explanatory note indicating that manual verification is required.

This rule is enforced by a validator on the `Finding` model:

```python
@modelvalidator(mode="after")
def validateevidence_model(self) -> Finding:
    conf_str = str(self.confidence or "").lower()
    if conf_str == "confirmed":
        self.confidence = "confirmed"
    else:
        self.confidence = "suspected"
        if self.severity == Severity.CRITICAL:
            self.severity = Severity.HIGH
    return self
```

An automated test suite in `tests/test_evidence_model.py` runs across all scanners to verify that no finding is emitted as `CRITICAL` without verified proof.

## Scanner Contract

Every runtime scanner inherits from `BaseScanner` in `mcpsec/scanners/base.py`:

```python
class BaseScanner(ABC):
    name: str = "base"
    description: str = "Base scanner"
    max_params_per_tool: int = 25

    def create_finding(self, **kwargs) -> Finding: ...

    @abstractmethod
    async def scan(
        self, profile: ServerProfile, client: MCPSecClient | None = None
    ) -> list[Finding]: ...
```

### Parameter Selection

Scanners select target parameters using `candidate_injectable_params` from `mcpsec/scanners/param_selection.py`. This helper inspects schema properties and orders candidate parameters:

1. Parameters whose names or descriptions match injection hints (`uri`, `url`, `path`, `file`, `cmd`, `command`, `query`, `sql`, `data`, `yaml`, `template`) are placed first.
2. All other string-typed parameters and untyped parameters follow.
3. Non-string primitives (integers, booleans, nulls) are excluded because standard injection payloads cannot conform to their types.
4. Total evaluated parameters per tool are capped by `max_params` (default 25) to avoid excessive probe latency.

### Dummy Arguments

When a tool requires multiple arguments to satisfy its input schema, scanners call `_get_dummy_args(tool, target_param, payload)`. This populates the target parameter with the security payload while filling sibling required parameters with type-valid dummy values (`"mcpsec_test"` for strings, `1` for numbers, `False` for booleans, `{}` for objects, `[]` for arrays).

## Detection Oracles and Response Classification

Runtime scanners avoid naive string searching by delegating confirmation to effect oracles located in `mcpsec/scanners/oracles/`.

- **Command Injection (`oracles/command_injection.py`)**: Uses an arithmetic canary (such as `$(( 36008 + 97783 ))` or backticked expressions). The oracle confirms only when the arithmetic sum appears in the output while the payload expression itself is absent, defeating sanitizers that echo cleaned strings. It also supports scaled sleep probes where delay scales across two distinct durations.
- **Path Traversal (`oracles/path_traversal.py`)**: Writes a unique sentinel file with random contents into temporary storage. It attempts to traverse back to the sentinel file and confirms only when the exact file contents return in the tool response.
- **SQL Injection (`oracles/sql_injection.py`)**: Employs directional boolean-differential verification. It confirms only when a TRUE condition preserves the tool baseline result set and a FALSE condition collapses or empties it. It also runs dual-duration scaled timing tests.
- **SSRF (`oracles/ssrf.py`, `oracles/oob_collector.py`)**: Operates a built-in HTTP listener. It mints unique random tokens, injects callback URLs, and confirms SSRF only when the listener receives an inbound network connection carrying that token.
- **Deserialization (`oracles/deserialization.py`)**: Injects payloads that induce scaled delays on unsafe object construction, avoiding false alerts from reflected type markers.

### SAFE-First Short Circuit

Before matching signatures, dynamic scanners pass responses to `response_classifier.py`. If a response contains standard JSON-RPC protocol error codes (such as `-32602` for invalid params) or matches defensive sandbox rejection phrases (`permission denied`, `path outside allowed directory`, `operation not permitted`), the classifier returns `Verdict.SAFE`. This stops benign rejections from being marked as vulnerabilities.

## Static Audit Pipeline

The static audit engine in `mcpsec/static/audit_engine.py` runs seven sequential analysis phases:

1. **Source Retrieval**: Clones a remote GitHub repository or reads a local directory path into a temporary workspace.
2. **Framework Detection**: Detects programming languages, MCP SDK variants (Python, TypeScript, Go, Rust, C#), and web frameworks.
3. **Pattern Scanning**: Evaluates code against more than 3,450 regex sink patterns across 12 languages stored in `mcpsec/static/pattern_db.py`.
4. **Semgrep Analysis**: Executes semantic AST rules defined under `mcpsec/static/semgrep/rules/`.
5. **AST Taint Tracking**: Parses Python and JavaScript ASTs to trace input flow from tool parameters to dangerous sinks.
6. **LLM Reachability Analysis**: When `--ai` is enabled, passes candidate sink locations and function bodies to an LLM to evaluate whether user inputs reach dangerous calls. If AI is not configured, a rule-based heuristic fallback ranks candidate findings.
7. **Deduplication and Ranking**: Groups duplicate reports from different analysis layers, merges evidence, and produces the final finding list.

## Protocol Fuzzer Architecture

The fuzzer in `mcpsec/fuzzer/fuzz_engine.py` tests MCP servers at the transport level.

### Generators and Intensity Tiers

Fuzz generators in `mcpsec/fuzzer/generators/` create malformed JSON-RPC messages, extreme boundary values, and encoding anomalies. They are categorized into four intensity levels:

- **Low (~65 cases)**: Core protocol checks, malformed JSON, basic type confusion, and boundary testing.
- **Medium (~200 cases)**: Adds integer boundaries, session mutation, and encoding attacks.
- **High (~800 cases)**: Adds injection payloads, schema mutations, timing checks, regex DoS inputs, and protocol state transitions.
- **Insane (~1500+ cases)**: Includes deep recursive nesting and memory exhaustion payloads.

### Baseline Differentials

Before fuzzing, `mcpsec/fuzzer/baseline.py` calls each tool with valid arguments to establish a normal response profile (status codes, output length, response keys, latency). During fuzzing, responses are compared against this baseline:

- Responses matching standard rejection codes are classified as clean rejections.
- Structural changes, unhandled exceptions, and abnormal response codes are marked as deviations.

### Real Crash vs Pipe Break

When a subprocess communication failure occurs, the harness determines whether the server genuinely crashed:

- **Real Crash**: The process exited with a non-zero exit code or terminated via an OS signal (SIGSEGV, SIGABRT). The stderr log is inspected for backtraces and panic messages.
- **Pipe Disconnect**: The transport pipe closed or timed out while the process remains alive. The harness classifies these separately to avoid false crash reports.

## Repository Map

```
mcpsec/
├── ai/                      LLM client, finding classifiers, and prompt generators
├── client/                  Live MCP client connecting over stdio or HTTP/SSE
├── fuzzer/                  Protocol fuzzing engine
│   ├── generators/          Payload generators grouped by attack class
│   ├── transport/           Low-level stdio and HTTP transport managers
│   └── baseline.py          Differential response analyzer
├── scanners/                Runtime vulnerability scanners
│   ├── oracles/             Effect-based verification oracles (OOB, sentinel, canaries)
│   ├── base.py              BaseScanner interface
│   ├── param_selection.py   Candidate parameter selector
│   └── response_classifier.py SAFE pattern matching and status classification
├── static/                  Static analysis engine (Audit v3)
│   ├── analysis/            Sink pattern scanner and reachability checks
│   ├── framework/           Language and MCP SDK detector
│   └── semgrep/             Semantic rulesets
├── cli.py                   Typer CLI commands and options
├── config.py                Provider credentials and configuration storage
└── models.py                ServerProfile, Finding, Severity, and evidence validation

tests/
├── corpus/                  Data-driven recall corpus test harness
├── servers/                 Mock MCP server test fixtures (vulnerable and defensive)
└── test_*.py                Unit and integration test suites
```

## Design Principles

1. **Confirm by effect**: An attack is only proven if an observable side effect occurred. String reflection alone is never accepted as proof of execution.
2. **Never hide suspected signals**: Heuristic and signature matches are labeled as suspected and capped at HIGH, but they are never discarded. Human reviewers retain access to all leads.
3. **Defense is not a bug**: If a server catches an invalid payload, validates a schema, or denies access through a sandbox, that rejection is recorded as safe behavior rather than an exploit.
4. **CI stays clean**: Test fixtures and recall corpus manifests skip cleanly when optional external runtimes or private targets are absent, keeping continuous integration green.
