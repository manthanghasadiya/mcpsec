# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-23
### Added
- **Protocol State Machine Fuzzer**: New generator to test violations of the MCP ritual (pre-init calls, double init, post-shutdown).
- **ID Confusion Fuzzer**: New generator to test JSON-RPC ID edge cases (large integers, floats, nulls, collisions).
- **Advanced Execution Flags**: Added `skip_init`, `send_after_init`, `send_shutdown_first`, `repeat`, and `delay_between` support to `FuzzCase` and `FuzzEngine`.
- **Improved Engine Robustness**: `FuzzEngine` now manages server lifecycle more aggressively for state-breaking tests.

## [1.0.5] - 2026-02-23
### Added
- **Chained Fuzzing Engine**: A new stateful fuzzer that handles sequential tool calls with data dependencies (e.g., `navigate` -> `snapshot` -> `click`).
- **Chain Analyzer**: AI-powered dependency analysis to automatically discover the correct order of tool calls.
- **Stateful Injection**: Ability to maintain valid session state and refs while fuzzing deep tool sinks.
- **SARIF Reporting**: Export chained fuzzing results to SARIF format for seamless CI/CD security pipeline integration.
- **New Command**: Added `mcpsec chained` command and `--chained` flag to `mcpsec fuzz`.

## [1.0.4] - 2026-02-23
### Added
- **Diagnostic Fuzz Logging**: New logging system for identifying exactly which payloads crash an MCP server.
- **HTTP Transport Logs**: Captures full request/response context for status 500 errors and timeouts in `mcpsec_fuzz_http.log`.
- **Trigger Payload Capture**: Stdio fuzzer now logs the specific malformed message that caused a process crash in `mcpsec_fuzz_stderr.log`.

## [1.0.3] - 2026-02-23

### Added
- Added a robust retry loop for tool discovery in AI fuzzing, allowing slow-starting servers up to 3 attempts to initialize before skipping.
- Enhanced tool discovery by storing result schemas; the fuzzer now dynamically replaces generic tool names and parameter keys in injection payloads with real-world target data discovered from the server.
- Improved initialization handshake for "auto" framing mode to gracefully handle servers that close the pipe on incorrect framing by automatically restarting the process.
- **[Phase 1]** Added support for custom HTTP headers via `--header` / `-H` flags in `scan` and `fuzz` commands. Essential for OAuth/Bearer authentication.
- **[Phase 1]** Implemented sensitive header masking in UI output to protect tokens and API keys.
- **[Phase 2]** Introduced `rogue-server` command to launch a malicious MCP server for testing client-side vulnerabilities (Memory exhaustion, XSS, Proto Pollution, Terminal injection).
- **[Phase 2]** Added `aiohttp` optional dependency for the rogue server and HTTP fuzzing.

## [1.0.1] - 2026-02-22

### Added
- Added strict JSON constraints to the AI generation prompt to prevent JavaScript syntax injections (like `.repeat()`) from producing invalid JSON tests.
- Enhanced JSON parsing to dynamically replace `\xNN` hex escapes with valid `\u00NN` unicode escapes prior to decoding.
- Improved JS string concatenation parsing to sanitize split properties like `"A" + "B"` during AI output extraction.
- Enhanced unescaped backslash sanitization in AI payloads to successfully test path traversal vulnerabilities like `..\..\etc\passwd` within valid JSON arrays.

### Fixed
- Fixed an issue where the underlying LLM would prematurely close the generated AI Fuzzing responses, or inject its own code blocks to ruin the strict JSON parsing array response.
- Resolved AI parsing failures for highly nested tools, allowing fully contextualized payloads to correctly send to the target tools.

## [1.0.0] - 2026-02-18

### Added
- Initial release of `mcpsec`.
- Built-in static protocol and encoding fuzzer payloads for the MCP specification.
- Seamless AI Payload generation bridging LLMs and the fuzzer to explore deep Application Logic vulnerabilities.
- Integrated Code scanning wrappers for identifying hardcoded secrets and malicious commands using Semgrep rules. 
