# Command Reference

This reference covers the commands, options, and operational modes available in mcpsec.

## Global Options

```bash
mcpsec --help       # Show top-level help and exit
mcpsec --version    # Show installed version and exit (-V)
```

---

## scan

Scan an active MCP server for security vulnerabilities.

Connects to a running server over stdio or HTTP/SSE, discovers tools, prompts, and resources, and executes selected security scanners.

```bash
# Scan a server running as a subprocess
mcpsec scan --stdio "npx @modelcontextprotocol/server-filesystem /tmp"

# Scan a remote server over HTTP
mcpsec scan --http http://localhost:8080/mcp

# Scan with an authorization header
mcpsec scan --http http://localhost:8080/mcp -H "Authorization: Bearer token123"

# Auto-discover local servers from desktop configuration files
mcpsec scan --auto

# Export scan results to SARIF for CI/CD ingestion
mcpsec scan --stdio "python server.py" --output report.sarif --format sarif
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Command to launch the target server via stdio. |
| `--http` | | `<str>` | URL of the remote MCP server endpoint. |
| `--scanners` | `-S` | `<str>` | Comma-separated list of scanners to run (default: all). |
| `--output` | `-o` | `<str>` | Path to save scan results file. |
| `--format` | `-f` | `<str>` | Output format: `json` or `sarif` (default: `json`). |
| `--quiet` | `-q` | flag | Suppress banners and tool listings; display only findings. |
| `--ai` | | flag | Use configured AI provider to generate targeted payloads. |
| `--header` | `-H` | `<str>` | HTTP header in `Key: Value` format. Can be repeated. |
| `--exploit` | | flag | Automatically launch interactive exploit REPL after scan. |
| `--auto` | `-a` | flag | Auto-discover and scan all locally configured servers. |
| `--config` | `-c` | `<str>` | Path to specific MCP configuration file. |
| `--list` | `-l` | flag | Enumerate and display discovered servers without scanning. |
| `--server` | | `<str>` | Filter servers by name when using auto-discovery. |
| `--oob-host` | | `<str>` | IP or hostname advertised in SSRF callback URLs (default: `127.0.0.1`). |
| `--max-params-per-tool` | | `<int>` | Maximum parameters to probe per tool (default: `25`). |

---

## audit

Run static code analysis against an MCP server repository or directory.

Audits source files using regex sink patterns across 12 languages, AST taint tracking, and Semgrep rules.

```bash
# Audit a local project directory
mcpsec audit --path ./my-server

# Audit a public GitHub repository
mcpsec audit --github https://github.com/user/mcp-server

# Audit an npm package with LLM reachability analysis
mcpsec audit --npm @example/mcp-server --ai
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--path` | `-p` | `<str>` | Local directory path to audit. |
| `--github` | `-g` | `<str>` | GitHub repository URL to clone and audit. |
| `--npm` | `-n` | `<str>` | npm package name to download and audit. |
| `--output` | `-o` | `<str>` | Path to write the output report. |
| `--format` | `-f` | `<str>` | Output report format: `json` or `sarif` (default: `json`). |
| `--ai` | | flag | Enable LLM reachability analysis for candidate sinks. |
| `--include-tests` | | flag | Include test files and fixtures in the audit scan. |

---

## fuzz

Fuzz an MCP server by sending mutated and malformed protocol messages.

Tests server resilience against framing errors, boundary violations, type confusion, and injection payloads.

```bash
# Run medium intensity fuzzing against a stdio target
mcpsec fuzz --stdio "python server.py"

# Run high intensity fuzzing with custom framing
mcpsec fuzz --stdio "python server.py" --intensity high --framing crlf

# Fuzz an HTTP endpoint with debugging logs
mcpsec fuzz --http http://localhost:8080/mcp --debug
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Command to launch the target server via stdio. |
| `--http` | | `<str>` | URL of the target HTTP endpoint. |
| `--intensity` | `-i` | `<str>` | Fuzzing depth: `low`, `medium`, `high`, `insane` (default: `medium`). |
| `--framing` | | `<str>` | Message framing: `auto`, `crlf`, `json`, `sse` (default: `auto`). |
| `--timeout` | `-t` | `<float>` | Per-test execution timeout in seconds (default: `2.0`). |
| `--startup-timeout` | | `<float>` | Initial server startup timeout in seconds (default: `15.0`). |
| `--generators` | `-g` | `<str>` | Comma-separated list of specific generators to run. |
| `--output` | `-o` | `<str>` | Path to save fuzzing report. |
| `--format` | `-f` | `<str>` | Output format: `json` or `sarif` (default: `json`). |
| `--header` | `-H` | `<str>` | HTTP request header in `Key: Value` format. |
| `--ai` | | flag | Generate contextual fuzzing payloads using AI. |
| `--chained` | | flag | Run stateful chained mutations across tools. |
| `--debug` | `-d` | flag | Print verbose wire messages and framing details. |

---

## evolve

Run coverage-guided evolutionary fuzzing against an MCP server.

Mutates inputs iteratively and saves seeds that trigger new response shapes or error conditions.

```bash
mcpsec evolve --stdio "python server.py" --max-iterations 1000 --max-time 600
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Subprocess command to launch. |
| `--http` | | `<str>` | Target HTTP endpoint URL. |
| `--corpus-dir` | | `<str>` | Directory to read and store interesting test cases (default: `corpus`). |
| `--crash-dir` | | `<str>` | Directory to save crashing test cases (default: `crashes`). |
| `--seed-dir` | | `<str>` | Directory containing initial seed inputs. |
| `--max-iterations` | `-n` | `<int>` | Maximum mutation iterations to run. |
| `--max-time` | `-t` | `<int>` | Maximum fuzzing duration in seconds (default: `3600`). |
| `--timeout` | | `<float>` | Per-execution timeout in seconds (default: `5.0`). |
| `--mcp-weight` | | `<float>` | Probability weight for MCP-aware mutations (0.0 to 1.0, default: `0.8`). |
| `--debug` | | flag | Display mutation trace logs. |

---

## sql

Run specialized SQL injection and database exploitation tests.

Performs database engine fingerprinting and directional boolean-differential probes against tools that query databases.

```bash
mcpsec sql --stdio "python db_server.py" --fingerprint --level 3
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Subprocess command to run. |
| `--http` | | `<str>` | HTTP endpoint URL. |
| `--tool` | `-t` | `<str>` | Test only the specified tool name. |
| `--level` | `-l` | `<int>` | Test intensity level from 1 to 5 (default: `1`). |
| `--fingerprint` | | flag | Identify database backend (SQLite, PostgreSQL, MySQL, MSSQL, Oracle). |
| `--exploit` | | flag | Attempt automated extraction proof upon confirmed injection. |
| `--timeout` | | `<float>` | Per-query timeout in seconds (default: `10.0`). |

---

## chains

Analyze servers for dangerous multi-tool attack sequences.

Detects combinations where the output of one tool can be piped into another to bypass security boundaries (for example: `download_file` followed by `execute_script`).

```bash
mcpsec chains --stdio "python server.py" --min-severity high
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Subprocess command to run. |
| `--http` | | `<str>` | HTTP endpoint URL. |
| `--min-severity` | `-m` | `<str>` | Filter chains by minimum severity: `low`, `medium`, `high`, `critical`. |
| `--output` | `-o` | `<str>` | Save identified attack chains to JSON. |

---

## chained

Execute stateful multi-step attack chains against an MCP server.

```bash
mcpsec chained --stdio "python server.py" --ai --intensity medium
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Target server command. |
| `--http` | | `<str>` | Target server HTTP URL. |
| `--ai / --no-ai` | | flag | Use AI for dependency graph analysis (default: `--ai`). |
| `--intensity` | `-i` | `<str>` | Fuzzing intensity: `low`, `medium`, `high` (default: `medium`). |
| `--output` | `-o` | `<str>` | Save execution results to JSON. |
| `--header` | `-H` | `<str>` | HTTP request header. |
| `--verbose` | `-v` | flag | Enable verbose output. |

---

## exploit

Launch an interactive exploitation REPL session against a target MCP server.

Provides an interactive console to inspect schemas, invoke tools manually, and replay confirmed exploit payloads.

```bash
# Launch interactive REPL directly
mcpsec exploit --stdio "python vulnerable_server.py"

# Launch REPL preloaded with findings from a previous scan
mcpsec exploit --stdio "python vulnerable_server.py" --from-scan results.json
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--stdio` | `-s` | `<str>` | Subprocess command to connect to. |
| `--http` | | `<str>` | HTTP endpoint URL to connect to. |
| `--from-scan` | | `<str>` | Path to scan results JSON file to preload candidate exploits. |
| `--ai` | | flag | Enable interactive AI exploitation assistant. |
| `--header` | `-H` | `<str>` | HTTP request header in `Key: Value` format. |

---

## rogue-server

Start a rogue MCP server to test client security.

Flips the security model to test whether MCP clients (such as Claude Desktop, Cursor, or IDE plugins) validate server responses, sanitize tool descriptions, or guard against path traversal in resource downloads.

```bash
# Start rogue server listening on HTTP port 8080
mcpsec rogue-server --port 8080 --attack all

# Start rogue server over stdio for direct client configuration
mcpsec rogue-server --stdio --attack tool-injection
```

### Options

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--port` | `-p` | `<int>` | Port to bind for HTTP transport (default: `8080`). |
| `--host` | | `<str>` | Host address to bind for HTTP transport (default: `127.0.0.1`). |
| `--stdio` | | flag | Communicate over stdio instead of HTTP. |
| `--attack` | `-a` | `<str>` | Attack scenario: `all`, `tool-injection`, `prompt-injection`, `traversal`, `dos` (default: `all`). |
| `--auth` | | `<str>` | Require specified Bearer token for client connections. |
| `--list` | `-l` | flag | List available client-side attack scenarios. |

---

## list-scanners

Display all available runtime security scanners with their names and descriptions.

```bash
mcpsec list-scanners
```

---

## setup

Configure AI provider credentials and model selection.

Runs an interactive setup wizard that configures `~/.mcpsec/config.json`.

```bash
mcpsec setup
```

Supported providers:
- DeepSeek (`deepseek-chat`)
- Groq (`llama-3.3-70b-versatile`)
- OpenAI (`gpt-4o-mini`)
- Anthropic (`claude-sonnet-4-20250514`)
- Google (`gemini-2.0-flash`)
- Ollama (`llama3.2`, local)

You can also configure providers using environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_API_KEY="AIza..."
export GROQ_API_KEY="gsk_..."
export DEEPSEEK_API_KEY="sk-..."
```
