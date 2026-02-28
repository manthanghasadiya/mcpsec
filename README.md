<div align="center">
     
# mcpsec

</div>

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/mcpsec)](https://pypi.org/project/mcpsec/)
[![Bugs Found](https://img.shields.io/badge/bugs%20reported-10+-red)](https://github.com/manthanghasadiya/mcpsec)
[![Fuzz Cases](https://img.shields.io/badge/fuzz%20cases-700+-orange)](https://github.com/manthanghasadiya/mcpsec)
[![Semgrep Rules](https://img.shields.io/badge/semgrep%20rules-49-purple)](https://github.com/manthanghasadiya/mcpsec)

**Security scanner and protocol fuzzer for MCP servers.**

Most MCP security tools do static analysis. mcpsec connects to live servers and proves exploitation.

[Installation](#installation) • [Usage](#usage) • [Scanners](#scanners) • [Fuzzing](#fuzz-generators)

</div>

---

## Why mcpsec?

MCP is the protocol connecting AI agents (Claude, Cursor, VS Code) to external tools. Every major AI company uses it. Its security is often overlooked.

- **82%** of MCP implementations have path traversal vulnerabilities
- **67%** are vulnerable to code injection  
- **~2,000** internet-exposed MCP servers found with zero authentication
- Anthropic's own Git MCP server had 3 critical RCE vulnerabilities

mcpsec has been used to discover and report **12+ vulnerabilities** across Anthropic and GitHub MCP implementations, affecting Python, TypeScript, and Go SDK ecosystems.

---

## Installation

```bash
pip install mcpsec
```

For AI-powered features:
```bash
pip install mcpsec[ai]
```

---

## Usage

### Runtime Scanning

```bash
# Scan via stdio
mcpsec scan --stdio "npx @modelcontextprotocol/server-filesystem /tmp"

# Scan via HTTP with auth
mcpsec scan --http http://localhost:8080/mcp -H "Authorization: Bearer TOKEN"

# Enumerate attack surface
mcpsec info --stdio "python my_server.py"

# Advanced SQL Injection Discovery
mcpsec sql --stdio "npx @benborla29/mcp-server-mysql" --fingerprint

# Attack Chain Analysis (Priority 0)
mcpsec chains --stdio "npx @example/complex-server"
```

### Protocol Fuzzing

```bash
# Standard fuzzing (150+ cases)
mcpsec fuzz --stdio "python my_server.py"

# High intensity (500+ cases)
mcpsec fuzz --stdio "python my_server.py" --intensity high

# Target specific attack class
mcpsec fuzz --stdio "python my_server.py" -g protocol_state_machine
mcpsec fuzz --stdio "python my_server.py" -g id_confusion

# AI-powered payload generation
mcpsec fuzz --stdio "python my_server.py" --ai
```

### Static Analysis

```bash
# Local source
mcpsec audit --path ./my-mcp-server

# GitHub repository
mcpsec audit --github https://github.com/user/mcp-server

# With AI validation
mcpsec audit --github https://github.com/user/mcp-server --ai
```

### Rogue Server (Client Testing)

```bash
# Test MCP clients for vulnerabilities
mcpsec rogue-server --port 9999 --attack all
```

---

## Scanners

| Scanner | Description |
|---------|-------------|
| `prompt-injection` | Hidden instructions in tool descriptions |
| `command-injection` | OS command injection with proof of exploitation |
| `path-traversal` | File traversal with proof of exploitation |
| `ssrf` | Server-Side Request Forgery to internal services |
| `auth-audit` | Missing auth, dangerous tool combinations |
| `description-prompt-injection` | LLM manipulation via descriptions |
| `resource-ssrf` | SSRF via MCP resource URIs |
| `capability-escalation` | Undeclared capability abuse |
| `sql` | Modular SQL Injection (Error, Time, Boolean, Stacked) |
| `chains` | Tool Chain Analysis (Dangerous combinations detection) |
| `sql-rce` | SQL Injection to RCE/File access (Legacy) |

---

## Fuzz Generators

| Generator | Description |
|-----------|-------------|
| `malformed_json` | Invalid JSON structures |
| `protocol_violation` | JSON-RPC spec violations |
| `type_confusion` | Type mismatch attacks |
| `unicode_attacks` | Encoding edge cases |
| `injection_payloads` | SQLi, XSS, command injection |
| `protocol_state_machine` | MCP state violations |
| `id_confusion` | JSON-RPC ID edge cases |

---

## Semgrep Rules

49 MCP-specific rules:

- Command injection (`exec`, `spawn`, `child_process`)
- SQL injection (raw queries, ORM bypass)
- Path traversal (`path.join` with unsanitized input)
- Description injection (dynamic tool descriptions)
- Resource URI issues (SSRF vectors)
- Protocol handler vulnerabilities

---

## Configuration

### AI Provider Setup

```bash
mcpsec setup
```

Supports: OpenAI, Anthropic, Google, Groq, DeepSeek, Ollama

### Output Formats

```bash
# JSON
mcpsec scan --stdio "server" --output results.json

# SARIF (CI/CD)
mcpsec fuzz --stdio "server" --output results.sarif
```

---

## How It Works

```
┌─────────┐     MCP Protocol      ┌────────────┐
│ mcpsec  │ ◄──── JSON-RPC ────►  │   Target   │
│         │    (stdio / HTTP)     │   Server   │
└────┬────┘                       └────────────┘
     │
     ├── Connect & enumerate attack surface
     ├── Run static scanners
     ├── Generate dynamic payloads  
     ├── Execute fuzzing campaigns
     └── Report findings with evidence
```

---

## Disclaimer

For authorized security testing only. Only scan servers you own or have permission to test.

---

## Changelog

### v2.1.0 (2026-02-27)
- **AI Exploitation Assistant**: New REPL commands (`select`, `run`, `next`, `verdict`, `auto`) for interactive AI-led testing.
- **Expert Controls**: Added `edit`, `aggressive`, and `hint` to guide AI toward complex bypasses.
- **Feedback Loop**: AI now learns from manual `call` commands and response history.
- **Robustness**: Fixed `Finding` model schema and improved `--from-scan` report ingestion.

### v2.0.3 (2026-02-26)
- **Interactive Exploitation (MCP Repeater)**: New REPL for manual/semi-auto validation of findings.
- **AI Payload Engine**: Context-aware payload recommendations integrated into playbooks.
- **Exploit Playbooks**: Attack sequences for SQLi, RCE, SSRF, and more.
- **Evidence Capture**: Automated logging and PoC script generation.

### v2.0.2 (2026-02-26)
- **Tool Chain Analysis**: Detect dangerous tool combinations (read+exec, sql+exfil).
- **Cross-Platform Priority**: Robust Windows support for `npx`, modern path resolution.
- **Improved UI**: Refined terminal output and error reporting.

### v2.0.1 (2026-02-25)
- **Advanced SQL Scanner**: Modular architecture with error/time/boolean detection.
- **DB Fingerprinting**: Automated identification of MySQL, Postgres, MSSQL, and SQLite.
- **Enhanced Heuristics**: Better tool and parameter surface discovery.

### v2.0.0 (2026-02-24)
- **Fuzzing Engine v2**: Chained fuzzer for deep state-machine exploration.
- **AI-Powered Validation**: LLM verification of potential security findings.

---

## License

[MIT](LICENSE)

---

<div align="center">

Built by [Manthan Ghasadiya](https://www.linkedin.com/in/man-ghasadiya)

</div>
