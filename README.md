# ⚡ mcpsec

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/mcpsec)](https://pypi.org/project/mcpsec/)
[![Found Bugs](https://img.shields.io/badge/bugs_found-5-red)]()
[![Servers Tested](https://img.shields.io/badge/servers_tested-10+-blue)]()
[![Fuzz Cases](https://img.shields.io/badge/fuzz_cases-600+-orange)]()

**Security scanner for MCP (Model Context Protocol) server implementations.**

MCP is the universal protocol connecting AI agents (Claude, ChatGPT, Gemini, Cursor) to external tools and data sources. It's adopted by every major AI company — Anthropic, OpenAI, Google, Microsoft. Its security is broken. `mcpsec` finds the vulnerabilities.

```
  ███╗   ███╗ ██████╗██████╗ ███████╗███████╗ ██████╗
  ████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
  ██╔████╔██║██║     ██████╔╝███████╗█████╗  ██║     
  ██║╚██╔╝██║██║     ██╔═══╝ ╚════██║██╔══╝  ██║     
  ██║ ╚═╝ ██║╚██████╗██║     ███████║███████╗╚██████╗
  ╚═╝     ╚═╝ ╚═════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
```

## Why?

- **82%** of MCP implementations have path traversal vulnerabilities ([Endor Labs](https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec))
- **67%** are vulnerable to code injection
- **~2,000** internet-exposed MCP servers found with **zero authentication** ([Knostic](https://www.descope.com/learn/post/mcp))
- Anthropic's own Git MCP server had **3 critical RCE vulnerabilities** (CVE-2025-68143/44/45)
- Nobody built an open-source scanner for this. Until now.

## Proven Results

mcpsec has been used to discover and responsibly report multiple vulnerabilities across official MCP implementations by major technology companies. Findings include transport-layer crashes, unhandled exception panics, and protocol-level denial of service issues affecting the Python SDK, TypeScript SDK, and Go SDK ecosystems.

- **5 bugs reported** across Anthropic and GitHub MCP implementations
- **3 SDK ecosystems affected** (Python, TypeScript, Go)
- **Fixes submitted within hours** of initial reports
- **Reproduced known CVEs**: CVE-2025-53967 (Figma MCP), CVE-2025-53818 (Kanban MCP)
- **SQL injection confirmed** in community MCP servers via static analysis

> Details will be published following responsible disclosure timelines.

## Install

```bash
pip install mcpsec
```

## Quick Start

```bash
# Scan an MCP server running via stdio
mcpsec scan --stdio "npx @modelcontextprotocol/server-filesystem /tmp"

# 💥 Run Mega Fuzzer with Custom Headers
mcpsec fuzz --http http://localhost:8080/mcp -H "Authorization: Bearer <token>"

# 🎭 Launch a Rogue Server to test your client (Cursor/Claude)
mcpsec rogue-server --port 9999 --attack all

# 🧠 Run AI-Powered Fuzzing
mcpsec fuzz --stdio "python my_server.py" --ai

# Enumerate attack surface
mcpsec info --stdio "python my_server.py"

# Static Audit (Source Code Analysis)
mcpsec audit --path . --ai

# List available scanners
mcpsec list-scanners
```

## Mega Fuzzer (v1.0.3)

`mcpsec` v1.0.2 introduces the **Rogue MCP Server**, a powerful framework for testing client-side vulnerabilities, along with support for custom HTTP headers to audit authenticated servers.

- **🎭 Rogue MCP Server**: Launch a malicious server with `--attack` vectors targeting Claude Desktop, Cursor, and VS Code. (Memory bombs, XSS, Proto Pollution, etc.)
- **🔐 Custom Headers**: Pass any token or cookie via `--header` / `-H`. Essential for protected Supabase, Slack, or GitHub deployments.
- **500+ Security Test Cases**: Exhaustive coverage for malformed JSON, protocol violations, and memory exhaustion.
- **AI-Powered Payloads**: Context-aware adversarial payloads tailored to your server's specific tool schemas.
- **Improved Compatibility**: Optimized for Windows (Proactor loop fixes) and strict protocol clients (Claude Desktop handshake).
- **Refined Intensity Tiers**:
  - `low`: Core protocol smoke tests (~65 cases)
  - `medium`: Standard security baseline (~150 cases)
  - `high`: Full regression suite (500+ cases)
  - `insane`: Includes resource exhaustion and DoS patterns
  - `ai`: High intensity + AI-generated payloads

## Scanners

| Scanner | Type | What It Detects |
|---------|------|----------------|
| `prompt-injection` | Static | Hidden instructions, base64-encoded payloads, cross-tool manipulation, data exfiltration indicators in tool descriptions |
| `auth-audit` | Static | Missing authentication, over-permissioned tools, dangerous tool combinations, misleading annotations |
| `path-traversal` | Dynamic | File path traversal via `../../` payloads — **proves exploitation** with actual file contents |
| `command-injection` | Dynamic | OS command injection via shell escape characters — **proves exploitation** with command output |
| `ssrf` | Dynamic | Server-Side Request Forgery targeting cloud metadata endpoints and internal services |
| `protocol-fuzzer` | Dynamic | **(500+ Cases)** Malformed JSON-RPC, boundary testing, state-machine violations, type confusion to find crashes |
| `ai-payloads` | Dynamic | **(New)** Context-aware payloads generated by LLMs (SQLi, Logic bugs, Edge cases) |

## How It Works

```
┌─────────┐     MCP Protocol      ┌────────────┐
│ mcpsec  │ ◄──── JSON-RPC ────►  │ Target MCP │
│ client  │    (stdio or HTTP)    │   Server   │
└────┬────┘                       └────────────┘
     │
     ├── 1. Connect (stdio subprocess or HTTP)
     ├── 2. Enumerate tools, resources, prompts  
     ├── 3. Run static scanners (analyze descriptions)
     ├── 4. Generate & Run dynamic payloads (Fuzzing + AI)
     └── 5. Report findings with evidence + remediation
```

## Features

- ✅ Prompt injection scanner
- ✅ Authentication & authorization audit
- ✅ Path traversal scanner (dynamic proof-of-exploitation)
- ✅ Command injection scanner (dynamic proof-of-exploitation)
- ✅ SSRF scanner
- ✅ JSON report output
- ✅ Static source code analysis with Semgrep rules
- ✅ Protocol Fuzzer (500+ adversarial test cases)
- ✅ AI-Powered Fuzzing (LLM-generated payloads per tool schema)
- ✅ Custom timeouts for slow targets (`--timeout`)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to set up your environment and add new scanners.

## Disclaimer

This tool is intended for authorized security testing only. Only scan MCP servers you own or have explicit permission to test. The authors are not responsible for misuse.

## License

[MIT](LICENSE)

---

*Built by [Manthan](https://www.linkedin.com/in/man-ghasadiya) — because your AI agents deserve a pentest too.*
