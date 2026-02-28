# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-02-28

### Added
- **Scanner Nuclear Expansion**: Command injection (11→138 payloads), path traversal (6→104 payloads), SSRF (6→81 payloads) with categorized attack vectors and encoding bypasses.
- **Confirmation-Based Detection**: Regex pattern matching with confidence scoring (CONFIRMED vs LIKELY) across all expanded scanners.
- **5 New Fuzzer Generators**: Integer boundaries, concurrency attacks, memory exhaustion v2, regex DoS, and deserialization — adding 187+ new test cases.
- **Go Semgrep Rules**: `exec.Command`, SQL concatenation, `os.Open` path traversal, SSRF detection for Go MCP servers.
- **Rust Semgrep Rules**: `Command::new`, `format!` SQL, unsafe deserialization for Rust MCP servers.
- **Python Async Semgrep Rules**: `create_subprocess_shell`, `aiofiles.open` traversal, `pickle.loads`, `eval/exec` for async Python servers.
- **.NET Semgrep Rules**: `Process.Start`, SQL interpolation, `BinaryFormatter`, `TypeNameHandling` deserialization for C# MCP servers.

## [2.2.0] - 2026-02-28

### Added
- **SARIF 2.1.0 Output**: Production-quality SARIF reports for CI/CD integration with GitHub Code Scanning, GitLab SAST, and Azure DevOps.
- **`--format sarif` flag**: Available on `scan`, `fuzz`, and `audit` commands. Default remains `json` for backward compatibility.
- **`--output` and `--format` for `audit`**: Static analysis results can now be saved as JSON or SARIF reports.
- **CWE Mapping**: Automatic CWE classification for all scanner types (CWE-78, CWE-89, CWE-22, CWE-918, CWE-94, etc.).
- **Security-Severity Scores**: GitHub-compatible severity scoring for Code Scanning integration.
- **Fingerprint Deduplication**: SHA-256 fingerprints for stable finding deduplication across runs.
- **Code Flows**: Taint analysis findings include SARIF code flow data.
- **Fuzz SARIF**: Fuzzer crashes, timeouts, and anomalies mapped to SARIF rule categories.

### Fixed
- Exploit `run` command now resolves parameter names from tool schema instead of using hardcoded fallback.
- AI client import corrected from non-existent `mcpsec.ai.client` to `mcpsec.ai.llm_client.LLMClient`.

## [2.1.0] - 2026-02-27

### Added
- **AI-Powered Exploitation Assistant**: Interactive commands `select`, `run`, `next`, `verdict`, and `auto` for guided vulnerability validation.
- **Advanced REPL UX**: New commands `edit`, `aggressive`, and `hint` for precise control over AI payload generation.
- **Manual Payload Integration**: Manual `call` commands are now tracked in suggestion history, allowing the AI to learn from user-guided attempts.
- **Finding Integration**: Fixes and improvements to `--from-scan` parsing, supporting raw JSON arrays and ScanResult objects.

### Fixed
- Missing `parameter` field in `Finding` model which caused errors during some scanner integrations.
- `--from-scan` parsing logic to handle diverse JSON report structures.
- Exploit session stability when AI is disabled.

## [2.0.3] - 2026-02-26

### Added
- **MCP Repeater**: Interactive terminal-based exploitation session manager.
- **`mcpsec exploit` command**: Direct access to the exploitation REPL.
- **`--exploit` flag for `scan`**: Seamless transition from vulnerability discovery to exploitation.
- **Attack Playbooks**: Predefined stages for Path Traversal, SQLi, Command Injection, SSRF, and Sandbox Escape.
- **AI Payload Recommendations**: Real-time payload suggestions based on server behavior and tool schema.
- **Evidence Bundle & PoC Generator**: Export session history as JSON/Markdown or generate standalone Python PoCs.

### Changed
- Refined session state tracking with `ExploitState` and `AttemptRecord`.
- Enhanced terminal autocompletion for MCP tools and findings.

---

## [2.0.2] - 2026-02-26

### Added
- **Tool Chain Analysis**: Heuristic-based detection of dangerous tool combinations across resources.
- **Windows Priority Support**: Improved `npx` execution and executable resolution on Windows.
- **Enhanced UI**: Improved status reporting and transport diagnostic output.

---

## [2.0.1] - 2026-02-25

### Added

**Advanced SQL Injection to RCE Scanner**
- New `sql-rce` scanner for detecting and escalating SQL injection
- Multi-phase detection: Error-based, Union-based, Stacked-query, and WAF bypass
- Database-specific RCE escalation (SQLite `load_extension`, Postgres `COPY TO PROGRAM`, MSSQL `xp_cmdshell`)
- Automatic DB fingerprinting and smart false-positive filtering for restricted environments

### Changed

- **Refactored Scanner Engine**: Support for dynamic scanner registration via decorators
- **Scanner Metadata**: Improved evidence reporting and severity classification

---

## [2.0.0] - 2026-02-25

### Added

**Protocol State Machine Fuzzer**
- New generator targeting MCP initialization sequence violations
- Tests pre-initialization method calls, double initialization, post-shutdown behavior
- Validates protocol version handling with malformed inputs
- 50+ test cases covering state machine edge cases

**ID Confusion Fuzzer**
- New generator for JSON-RPC message ID edge cases
- Tests integer overflow, negative IDs, float IDs, null IDs
- Type confusion attacks (arrays, objects as IDs)
- ID collision and reuse scenarios

**New Runtime Scanners**
- `description-prompt-injection`: Detects hidden LLM manipulation in tool descriptions
- `resource-ssrf`: Tests resource URI handlers for SSRF vulnerabilities  
- `capability-escalation`: Validates servers enforce declared capabilities

**New Semgrep Rules**
- `mcp-description-injection.yml`: Unsafe tool description construction
- `mcp-resource-uri.yml`: Resource URI handling issues
- `mcp-capability-issues.yml`: Capability declaration problems
- `mcp-protocol-handler.yml`: Protocol message handling vulnerabilities
- Total: 49 rules (previously ~25)

**Fuzzer Execution Flags**
- `skip_init`: Bypass initialization for pre-init testing
- `send_after_init`: Target post-initialization state
- `send_shutdown_first`: Test post-shutdown behavior
- `repeat`: Send payload multiple times for collision testing
- `delay_between`: Control timing between repeated payloads

### Changed

- Fuzzer engine manages server lifecycle for state-breaking tests
- Improved framing auto-detection with graceful fallback
- Scanner registry updated with new scanner classes

### Fixed

- Notification messages no longer incorrectly include request IDs
- Server restart handling for tests requiring fresh state

---

## [1.0.6] - 2026-02-23

### Added

- Chained fuzzing engine for stateful multi-tool attack sequences
- Chain analyzer for automatic dependency discovery
- SARIF output format for CI/CD integration

### Fixed

- False positive reduction in chained fuzzing evidence detection

---

## [1.0.5] - 2026-02-23

### Added

- Diagnostic logging for crash payload identification
- HTTP transport request/response logging
- Stdio crash trigger capture

---

## [1.0.4] - 2026-02-23

### Added

- Custom HTTP headers via `--header` / `-H` flags
- Sensitive header masking in output
- Rogue server command for client-side testing
- Memory exhaustion, XSS, prototype pollution attack vectors

---

## [1.0.3] - 2026-02-23

### Added

- Retry loop for tool discovery in AI fuzzing
- Dynamic payload customization with discovered tool schemas
- Improved framing auto-detection

### Fixed

- Server restart on framing mismatch

---

## [1.0.1] - 2026-02-22

### Fixed

- AI payload JSON parsing with hex escape handling
- JavaScript string concatenation in AI output
- Backslash sanitization for path traversal payloads

---

## [1.0.0] - 2026-02-18

### Added

- Initial release
- Runtime scanning via stdio and HTTP transports
- Protocol fuzzer with 500+ test cases
- AI-powered payload generation
- Semgrep-based static analysis
- Support for OpenAI, Anthropic, Google, Groq, DeepSeek, Ollama