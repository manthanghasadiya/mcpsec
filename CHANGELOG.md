# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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