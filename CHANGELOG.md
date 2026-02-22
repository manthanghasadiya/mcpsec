# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
