# MCPProbe

**Open-source security scanner for MCP servers and AI agents.**

Scan your Claude Code, Cursor, or VS Code MCP configurations in seconds — no account, no cloud, no data upload.

```
$ mcpprobe scan

╭──────────────────────────────────────────────────────────────────────────────╮
│ MCPProbe  ·  2 server(s) scanned  ·  6 finding(s)  ·  Score 76/100  ·  2 ms  │
╰──────────────────────────────────────────────────────────────────────────────╯

MEDIUM (2)
  Rule       Server        Message                                   Confidence
 ──────────────────────────────────────────────────────────────────────────────
  EXEC-001   deepfake-db   Command 'mcp-server-sqlite' uses a        HIGH
                           relative path — vulnerable to PATH hijacking
  EXEC-001   osint-db      Command 'mcp-server-sqlite' uses a        HIGH
                           relative path — vulnerable to PATH hijacking

LOW (4)
  PERM-003   deepfake-db   MCP server accesses a user-level database  MEDIUM
  NET-004    deepfake-db   MCP server has unrestricted access to DB   LOW
  PERM-003   osint-db      MCP server accesses a user-level database  MEDIUM
  NET-004    osint-db      MCP server has unrestricted access to DB   LOW
```

---

## Why MCPProbe

[MCP](https://modelcontextprotocol.io) is the standard way AI agents connect to tools and data. Every MCP server you install runs code on your machine with access to your files, databases, and network.

**MCPProbe gives you visibility before something goes wrong.**

| | MCPProbe | Snyk Agent Scan |
|---|---|---|
| Stdio transport | ✅ | ✅ |
| HTTP / SSE transport | ✅ | ❌ |
| Source code analysis (M2) | ✅ | ❌ |
| Active security testing (M3) | ✅ | ❌ |
| Runtime behavior analysis (M3) | ✅ | ❌ |
| Local-first, no account | ✅ | ❌ |
| Zero data upload by default | ✅ | ❌ |
| Open source (MIT) | ✅ | ⚠️ partial |

---

## Install

```bash
pip install mcpprobe
```

Requires Python 3.10+.

---

## Usage

```bash
# Auto-detect Claude Code, Cursor and VS Code configs
mcpprobe scan

# Scan a specific config file
mcpprobe scan --config path/to/mcp-config.json

# JSON output for CI/CD pipelines
mcpprobe scan --output json

# Fail the pipeline on HIGH or above
mcpprobe scan --fail-on HIGH
```

---

## CI/CD — GitHub Actions

```yaml
- name: Scan MCP servers
  run: |
    pip install mcpprobe
    mcpprobe scan --output json --fail-on HIGH
```

---

## What MCPProbe checks (20 rules)

### Secrets
| Rule | Description | Severity |
|---|---|---|
| SEC-001 | API key in plain text in env block | CRITICAL |
| SEC-002 | Secret passed as a CLI argument | CRITICAL |
| SEC-003 | Env variable name suggests it holds a secret | HIGH |
| SEC-004 | Non-empty env values in a git-tracked config | MEDIUM |

### Execution
| Rule | Description | Severity |
|---|---|---|
| EXEC-001 | Relative command — vulnerable to PATH hijacking | MEDIUM |
| EXEC-002 | Shell interpreter as MCP entry point | HIGH |
| EXEC-003 | Shell `-c` flag enables arbitrary command injection | HIGH |
| EXEC-004 | `npx -y` without version pin — supply chain risk | MEDIUM |
| EXEC-005 | `uvx`/`pipx` without version pin | MEDIUM |

### Network
| Rule | Description | Severity |
|---|---|---|
| NET-001 | Unencrypted HTTP transport | HIGH |
| NET-002 | Remote URL — data may leave your machine | MEDIUM |
| NET-003 | Remote server with no authentication headers | MEDIUM |
| NET-004 | Sensitive path in args (DB, secrets dir) | LOW |
| NET-005 | TLS verification explicitly disabled | HIGH |

### Permissions
| Rule | Description | Severity |
|---|---|---|
| PERM-001 | Access to broad filesystem path (`/`, `/home`, `/etc`) | HIGH |
| PERM-002 | Server name suggests elevated capabilities | LOW |
| PERM-003 | Unrestricted access to user-level database | LOW |

### Configuration
| Rule | Description | Severity |
|---|---|---|
| CFG-001 | No command and no URL — misconfigured server | MEDIUM |
| CFG-002 | HTTP/SSE transport without URL | LOW |
| CFG-004 | Both command and URL set — ambiguous | LOW |
| CFG-005 | Duplicate server name across config files | LOW |

---

## Supported editors

| Editor | Config location |
|---|---|
| **Claude Code** | `~/.claude.json`, `.claude/settings.json` |
| **Cursor** | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| **VS Code / Copilot** | `.vscode/mcp.json`, `.vscode/settings.json` |
| **Custom** | `mcpprobe scan --config your-file.json` |

---

## Roadmap

- **M1** (now) — Static config scanner, 20 rules, Claude + Cursor + VS Code
- **M2** — Source code analysis (Python + TypeScript AST), Semgrep rules
- **M3** — Active security testing on live MCP servers (stdio + HTTP + SSE)
- **M4** — Runtime behavior analyzer
- **M5** — SaaS dashboard (multi-project, history, alerts)

---

## Contributing

```bash
git clone https://github.com/YOUR_USERNAME/mcpprobe
cd mcpprobe
pip install -e ".[dev]"
pytest tests/ -v
```

New rules go in `mcpprobe/rules/`. Each rule is a `@rule`-decorated function that takes an `MCPServer` and returns `Finding | None`. Add a test in `tests/test_rules.py`.

---

## License

MIT

---

## Disclaimer

MCPProbe identifies potential security issues in MCP configurations. A passing scan does not guarantee security. Review all findings in context. Run active tests (M3) only on servers you own or have explicit permission to test.
