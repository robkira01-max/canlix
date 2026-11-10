# MCPProbe

**Open-source security scanner for MCP servers and AI agents.**

Scan your Claude Code, Cursor, or VS Code MCP configurations in seconds — no account, no cloud, no data upload.

```
$ mcpprobe scan

╭─────────────────────────────────────────────────────────────────────────────╮
│ MCPProbe  ·  3 server(s) scanned  ·  4 finding(s)  ·  Score 72/100  ·  3 ms │
╰─────────────────────────────────────────────────────────────────────────────╯

HIGH (1)
 Rule       Server       Message                                       Conf.
 ─────────────────────────────────────────────────────────────────────────────
 NET-001    analytics    HTTP transport sends data unencrypted         HIGH

MEDIUM (2)
 EXEC-001   sqlite-db    Command 'mcp-server-sqlite' uses a            HIGH
                         relative path — vulnerable to PATH hijacking
 EXEC-004   code-tools   npx -y without version pin — supply chain     MEDIUM
                         risk

LOW (1)
 PERM-003   sqlite-db    MCP server accesses a user-level database     MEDIUM
```

---

## Why MCPProbe

[MCP](https://modelcontextprotocol.io) is the standard that connects AI agents to your tools, files, and databases. Every MCP server you install runs code on your machine — and most developers have several installed.

**MCPProbe gives you visibility before something goes wrong.**

| | MCPProbe | Snyk Agent Scan |
|---|---|---|
| Config scanning (stdio / HTTP / SSE) | ✅ | stdio only |
| Source code analysis (Python AST + TypeScript/JS regex) | ✅ | ❌ |
| Active live server probing | ✅ | ❌ |
| Prompt-injection detection | ✅ | ❌ |
| Local-first, zero data upload | ✅ | ❌ |
| CI/CD JSON output + exit codes | ✅ | ✅ |
| Open source (MIT) | ✅ | partial |

---

## Install

```bash
pip install mcpprobe
```

Requires Python 3.10+. No external dependencies beyond `typer` and `rich`.

---

## Three commands

### `scan` — static config analysis

```bash
# Auto-detect Claude Code, Cursor and VS Code configs
mcpprobe scan

# Scan a specific config file
mcpprobe scan --config path/to/mcp-config.json

# JSON output for CI/CD — exits 1 if HIGH or above
mcpprobe scan --output json --fail-on HIGH

# Skip source code analysis
mcpprobe scan --no-source
```

Auto-detects configs from:
- **Claude Code** — `~/.claude.json`, `.claude/settings.json`
- **Cursor** — `~/.cursor/mcp.json`, `.cursor/mcp.json`
- **VS Code / Copilot** — `.vscode/mcp.json`, `.vscode/settings.json`

---

### `analyze` — source code analysis (Python + TypeScript/JavaScript)

```bash
# Scan a single file
mcpprobe analyze server.py
mcpprobe analyze server.ts

# Scan a whole project directory (auto-detects .py, .ts, .js, .mjs, .cjs)
mcpprobe analyze ./my-mcp-server/

# JSON output
mcpprobe analyze server.py --output json
```

Detects hardcoded secrets, `eval()`, dangerous process execution, prototype pollution — Python via the built-in `ast` module, TypeScript/JavaScript via regex. Zero external dependencies, no Node.js required.

---

### `probe` — active live server testing

```bash
# Probe an HTTP MCP server
mcpprobe probe https://my-server.example.com/mcp

# Probe a server from your config by name
mcpprobe probe my-server-name

# Enable active tool-call probes (use only on servers you own)
mcpprobe probe https://my-server.example.com/mcp --active

# JSON output
mcpprobe probe https://my-server.example.com/mcp --output json
```

Connects to a live MCP server, enumerates its tools and resources, and runs passive + optional active security probes. Detects prompt-injection in tool descriptions, dangerous execution tools, and unrestricted filesystem parameters — without sending tool calls by default.

---

## CI/CD — GitHub Actions

```yaml
- name: Scan MCP servers
  run: |
    pip install mcpprobe
    mcpprobe scan --output json --fail-on HIGH

- name: Analyze MCP server source
  run: mcpprobe analyze ./src --output json --fail-on CRITICAL
```

`mcpprobe` exits `0` on clean, `1` if a finding meets or exceeds `--fail-on`, `2` on config errors.

### GitHub Code Scanning (SARIF upload)

```yaml
- name: MCPProbe — scan and upload to GitHub Security tab
  run: |
    pip install mcpprobe
    mcpprobe scan   --output sarif > scan.sarif
    mcpprobe analyze ./src --output sarif > analyze.sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif

- name: Upload source analysis SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: analyze.sarif
```

SARIF output is supported by all three commands (`scan`, `analyze`, `probe`) and is compatible with [VS Code SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) and any tool that supports SARIF 2.1.0.

---

## Complete rule reference

### Config rules (21) — `mcpprobe scan`

#### Secrets
| Rule | Severity | Description |
|---|---|---|
| SEC-001 | CRITICAL | API key or token in plain text in `env` block |
| SEC-002 | CRITICAL | Secret value passed as a CLI argument |
| SEC-003 | HIGH | Env variable name suggests it holds a secret |
| SEC-004 | MEDIUM | Non-empty env values in a git-tracked config |

#### Execution
| Rule | Severity | Description |
|---|---|---|
| EXEC-001 | MEDIUM | Relative command path — vulnerable to PATH hijacking |
| EXEC-002 | HIGH | Shell interpreter (`bash`, `sh`, `zsh`) as MCP entry point |
| EXEC-003 | HIGH | Shell `-c` flag enables arbitrary command injection |
| EXEC-004 | MEDIUM | `npx -y` without version pin — supply chain risk |
| EXEC-005 | MEDIUM | `uvx`/`pipx` without version pin |

#### Network
| Rule | Severity | Description |
|---|---|---|
| NET-001 | HIGH | Unencrypted HTTP transport |
| NET-002 | MEDIUM | Remote URL — data leaves your machine |
| NET-003 | MEDIUM | Remote server with no authentication headers |
| NET-004 | LOW | Sensitive path in args (DB, secrets directory) |
| NET-005 | HIGH | TLS verification explicitly disabled |

#### Permissions
| Rule | Severity | Description |
|---|---|---|
| PERM-001 | HIGH | Access to broad filesystem path (`/`, `/home`, `/etc`) |
| PERM-002 | LOW | Server name suggests elevated capabilities |
| PERM-003 | LOW | Unrestricted access to user-level database |

#### Configuration
| Rule | Severity | Description |
|---|---|---|
| CFG-001 | MEDIUM | No command and no URL — misconfigured server |
| CFG-002 | LOW | HTTP/SSE transport without URL |
| CFG-003 | LOW | Unrecognised transport type |
| CFG-004 | LOW | Both command and URL set — ambiguous |
| CFG-005 | LOW | Duplicate server name across config files |

---

### Source rules — `mcpprobe analyze`

#### Python rules (6) — `.py` files, AST-based

| Rule | Severity | Description |
|---|---|---|
| SRC-001 | CRITICAL / HIGH | Hardcoded API key or token (`sk-`, `ghp_`, `AKIA…`) / secret variable name |
| SRC-002 | HIGH | `eval()` or `exec()` — arbitrary code execution |
| SRC-003 | HIGH | `subprocess.run(shell=True)` — command injection |
| SRC-004 | HIGH | `os.system()` / `os.popen()` — command injection |
| SRC-005 | MEDIUM | `pickle.loads()` — unsafe deserialization of untrusted data |
| SRC-006 | MEDIUM | `yaml.load()` without `Loader=` — arbitrary Python execution |

#### TypeScript / JavaScript rules (6) — `.ts`, `.js`, `.mjs`, `.cjs` files, regex-based, no Node.js required

| Rule | Severity | Description |
|---|---|---|
| TS-001 | CRITICAL / HIGH | Hardcoded API key or token (`sk-`, `ghp_`, `AKIA…`, JWT header) / secret variable name |
| TS-002 | HIGH | `eval()` — arbitrary code execution |
| TS-003 | HIGH | `execSync()` — always shell-equivalent; use `execFileSync(cmd, args)` instead |
| TS-004 | HIGH | `shell: true` in `spawn()`/`exec()` options — command injection via unsanitised input |
| TS-005 | HIGH | `exec()` with template literal — string interpolation enables command injection |
| TS-006 | MEDIUM | `__proto__` assignment / `constructor["prototype"]` — prototype pollution |

---

### Probe rules (7) — `mcpprobe probe`

#### Passive (always run — no tool calls)
| Rule | Severity | Description |
|---|---|---|
| PROBE-001 | CRITICAL | Prompt-injection pattern in a tool description |
| PROBE-002 | HIGH | Tool name or description suggests arbitrary command execution |
| PROBE-003 | MEDIUM | Filesystem tool with unconstrained `path` parameter |
| PROBE-004 | HIGH | Input schema has a `code`, `command`, `script`, or `eval` parameter |
| PROBE-005 | INFO | Server exposes >15 tools — large attack surface |

#### Active (opt-in with `--active`)
| Rule | Severity | Description |
|---|---|---|
| PROBE-010 | CRITICAL / HIGH | Path traversal succeeds (`../../../../etc/passwd`) |
| PROBE-011 | MEDIUM | Error message leaks an internal filesystem path |

---

## Scoring

Every scan produces a **0–100 score** (100 = clean):

| Severity | Deduction |
|---|---|
| CRITICAL | −40 |
| HIGH | −20 |
| MEDIUM | −8 |
| LOW | −2 |
| INFO | 0 |

The floor is 0. The exit code is always based on `--fail-on`, not the score.

---

## Contributing

```bash
git clone https://github.com/robkira01-max/mcpprobe
cd mcpprobe
pip install -e ".[dev]"
pytest tests/ -v
ruff check .
```

**New config rule** → add to `mcpprobe/rules/<category>.py`, return `Finding | None`, add a test in `tests/test_rules.py`.

**New source rule** → extend `_Visitor` in `mcpprobe/analyzers/python_ast.py`, add a test in `tests/test_analyzers.py`.

**New probe rule** → add to `mcpprobe/probes/metadata.py` (passive) or `mcpprobe/probes/active.py` (active), add a test in `tests/test_probes.py`.

---

## License

MIT © 2026 robkira01-max

---

## Disclaimer

MCPProbe identifies potential security issues in MCP configurations, source files, and live servers. A passing scan does not guarantee security — review all findings in context. Run active probes (`--active`) only on servers you own or have explicit written permission to test.
