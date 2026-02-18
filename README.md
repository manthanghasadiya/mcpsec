# ⚡ mcpsec

**Security scanner for MCP (Model Context Protocol) server implementations.**

MCP is the universal protocol connecting AI agents (Claude, ChatGPT, Gemini, Cursor) to external tools. It's adopted by every major AI company. Its security is broken. `mcpsec` finds the vulnerabilities.

```
  ███╗   ███╗ ██████╗██████╗ ███████╗███████╗ ██████╗
  ████╗ ████║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
  ██╔████╔██║██║     ██████╔╝███████╗█████╗  ██║     
  ██║╚██╔╝██║██║     ██╔═══╝ ╚════██║██╔══╝  ██║     
  ██║ ╚═╝ ██║╚██████╗██║     ███████║███████╗╚██████╗
  ╚═╝     ╚═╝ ╚═════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
```

## Why?

- **82%** of MCP implementations have path traversal vulnerabilities
- **67%** are vulnerable to code injection
- **~2,000** internet-exposed MCP servers found with **zero authentication**
- Anthropic's own Git MCP server had **3 critical RCE vulnerabilities**
- Nobody built an open-source scanner for this. Until now.

## Install

```bash
pip install mcpsec
```

## Quick Start

```bash
# Scan an MCP server running via stdio
mcpsec scan --stdio "npx @modelcontextprotocol/server-filesystem /tmp"

# Scan an MCP server running via HTTP
mcpsec scan --http http://localhost:3000/mcp

# Just enumerate (no scanning)
mcpsec info --stdio "python my_server.py"

# Save JSON report
mcpsec scan --stdio "python my_server.py" --output report.json

# List available scanners
mcpsec list-scanners
```

## Scanners

| Scanner | What It Detects |
|---------|----------------|
| `prompt-injection` | Hidden instructions in tool descriptions that manipulate AI agents |
| `auth-audit` | Missing authentication, over-permissioned tools, dangerous tool combinations |
| *More coming...* | Path traversal, command injection, SSRF, SQL injection, drift detection |

## How It Works

1. **Connect** — mcpsec acts as an MCP client, connecting to the target server via stdio or HTTP
2. **Enumerate** — Discovers all tools, resources, and prompts exposed by the server
3. **Scan** — Runs security scanners against the discovered attack surface
4. **Report** — Outputs findings with severity, evidence, and remediation guidance

## Development

```bash
git clone https://github.com/manthan/mcpsec.git
cd mcpsec
pip install -e ".[dev]"

# Run against the included vulnerable test server
mcpsec scan --stdio "python tests/vuln_test_server.py"
```

## Roadmap

- [ ] Path traversal scanner (dynamic testing with payloads)
- [ ] Command injection scanner
- [ ] SSRF scanner
- [ ] SQL injection scanner
- [ ] Tool description drift detector (rug pull detection)
- [ ] Static analysis mode (scan source code without running the server)
- [ ] AI-powered semantic prompt injection detection (DeepSeek integration)
- [ ] HTML report dashboard
- [ ] SARIF output for CI/CD integration
- [ ] GitHub Action

## License

MIT

---

*Built by [Manthan](https://www.linkedin.com/in/man-ghasadiya) — because your AI agents deserve a pentest too.*