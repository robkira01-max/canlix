# MCPProbe

**Open-source security scanner for MCP servers and AI agents.**

Scan your Claude Code, Cursor, or VS Code MCP configurations in seconds — no account, no cloud, no data upload.

```
$ mcpprobe scan

╭──────────────────────────────────────────────────────────────────────────────╮
│ MCPProbe  ·  3 server(s) scanned  ·  4 finding(s)  ·  Score 72/100  ·  3 ms │
╰──────────────────────────────────────────────────────────────────────────────╯

HIGH (1)
 Rule       Server       Message                                        Conf.
 ─────────────────────────────────────────────────────────────────────────────
 NET-001    analytics    HTTP transport sends data unencrypted          HIGH

MEDIUM (2)
 EXEC-001   sqlite-db    Command 'mcp-server-sqlite' uses a             HIGH
                         relative path — vulnerable to PATH hijacking
 EXEC-004   code-tools   npx -y without version pin — supply chain      MEDIUM
                         risk

LOW (1)
 PERM-003   sqlite-db    MCP server accesses a user-level database      MEDIUM
```

---

## Why MCPProbe

[MCP](https://modelcontextprotocol.io) is the standard that connects AI agents to your tools, files, and databases. Every MCP server you install runs code on your machine — and most developers have several installed.

**MCPProbe gives you visibility before something goes wrong.**

| | MCPProbe | Snyk Agent Scan |
|---|---|---|
| Config scanning (stdio / HTTP / SSE) | ✅ | stdio only |
| Source code analysis — **51 Python + 51 JS/TS rules** | ✅ | ❌ |
| Active live server probing | ✅ | ❌ |
| Prompt-injection detection | ✅ | ❌ |
| Local-first, zero data upload | ✅ | ❌ |
| CI/CD JSON + SARIF output + exit codes | ✅ | ✅ |
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

# Scan a whole project directory
mcpprobe analyze ./my-mcp-server/

# JSON output
mcpprobe analyze server.py --output json

# SARIF for GitHub Code Scanning
mcpprobe analyze ./src --output sarif > results.sarif
```

Detects 51 Python AST patterns and 51 TypeScript/JavaScript regex patterns — covering injection, secrets, weak crypto, path traversal, deserialization, and more. Zero external dependencies, no Node.js required.

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
- name: MCPProbe — scan and analyze
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

---

## Complete rule reference

### Config rules (21) — `mcpprobe scan`

#### Secrets
| Rule | Sev. | Description |
|---|---|---|
| SEC-001 | CRITICAL | API key or token in plain text in `env` block |
| SEC-002 | CRITICAL | Secret value passed as a CLI argument |
| SEC-003 | HIGH | Env variable name suggests it holds a secret |
| SEC-004 | MEDIUM | Non-empty env values in a git-tracked config |

#### Execution
| Rule | Sev. | Description |
|---|---|---|
| EXEC-001 | MEDIUM | Relative command path — vulnerable to PATH hijacking |
| EXEC-002 | HIGH | Shell interpreter (`bash`, `sh`, `zsh`) as MCP entry point |
| EXEC-003 | HIGH | Shell `-c` flag enables arbitrary command injection |
| EXEC-004 | MEDIUM | `npx -y` without version pin — supply chain risk |
| EXEC-005 | MEDIUM | `uvx`/`pipx` without version pin |

#### Network
| Rule | Sev. | Description |
|---|---|---|
| NET-001 | HIGH | Unencrypted HTTP transport |
| NET-002 | MEDIUM | Remote URL — data leaves your machine |
| NET-003 | MEDIUM | Remote server with no authentication headers |
| NET-004 | LOW | Sensitive path in args (DB, secrets directory) |
| NET-005 | HIGH | TLS verification explicitly disabled |

#### Permissions
| Rule | Sev. | Description |
|---|---|---|
| PERM-001 | HIGH | Access to broad filesystem path (`/`, `/home`, `/etc`) |
| PERM-002 | LOW | Server name suggests elevated capabilities |
| PERM-003 | LOW | Unrestricted access to user-level database |

#### Configuration
| Rule | Sev. | Description |
|---|---|---|
| CFG-001 | MEDIUM | No command and no URL — misconfigured server |
| CFG-002 | LOW | HTTP/SSE transport without URL |
| CFG-003 | LOW | Unrecognised transport type |
| CFG-004 | LOW | Both command and URL set — ambiguous |
| CFG-005 | LOW | Duplicate server name across config files |

---

### Python source rules (51) — `mcpprobe analyze` on `.py` files

AST-based analysis — no false positives from comments or strings.

#### Injection
| Rule | Sev. | Description |
|---|---|---|
| SRC-001 | CRITICAL/HIGH | Hardcoded API key / token prefix, or secret variable name |
| SRC-002 | HIGH | `eval()` / `exec()` — arbitrary code execution |
| SRC-003 | HIGH | `subprocess.run(shell=True)` — command injection |
| SRC-004 | HIGH | `os.system()` / `os.popen()` — command injection |
| SRC-009 | HIGH | SQL built with f-string or `+`/`%` — SQL injection |
| SRC-040 | HIGH | `compile(user_input)` — dynamic bytecode compilation |
| SRC-043 | HIGH | SQL built with `.format(param)` — SQL injection |
| SRC-047 | HIGH | `importlib.import_module(param)` — module injection |
| SRC-050 | CRITICAL | `ctypes.CDLL(param)` — user-controlled native library |
| SRC-051 | HIGH | `Thread(target=param)` — user-controlled callable |

#### Path traversal & file access
| Rule | Sev. | Description |
|---|---|---|
| SRC-008 | MEDIUM | `open(param)` / `Path(param)` / `os.remove(param)` — path traversal |
| SRC-027 | MEDIUM | `os.path.join(base, param)` — `../` sequences escape base dir |
| SRC-038 | MEDIUM | `os.chmod(path, 0o777)` — world-writable permissions |
| SRC-045 | HIGH | `send_file(param)` / `send_from_directory(param)` — user-controlled path |
| SRC-048 | HIGH | `extractall()` without `filter=` — zip/tar slip |

#### Deserialization
| Rule | Sev. | Description |
|---|---|---|
| SRC-005 | MEDIUM | `pickle.loads()` — arbitrary code execution |
| SRC-006 | MEDIUM | `yaml.load()` without `Loader=` — arbitrary Python execution |
| SRC-019 | HIGH | `shelve`, `jsonpickle`, `dill` deserialization |
| SRC-034 | MEDIUM | `yaml.load(Loader=FullLoader)` — still executes Python objects |
| SRC-042 | CRITICAL | `marshal.loads()` — arbitrary code execution via crafted bytes |

#### Network & SSRF
| Rule | Sev. | Description |
|---|---|---|
| SRC-007 | MEDIUM | `requests.get(param)` / `httpx.get(param)` — SSRF |
| SRC-011 | HIGH | `verify=False` or `_create_unverified_context()` — MITM |
| SRC-049 | LOW | `socket.setdefaulttimeout(None)` — infinite timeout, DoS risk |

#### Authentication & cryptography
| Rule | Sev. | Description |
|---|---|---|
| SRC-010 | MEDIUM | `random.*` assigned to `token`/`secret`/`otp` — insecure PRNG |
| SRC-012 | MEDIUM | `hashlib.md5()` / `hashlib.sha1()` — cryptographically broken |
| SRC-013 | MEDIUM | `==` on a secret value — timing-attack leaks |
| SRC-016 | HIGH | JWT decoded with `algorithms=['none']` — auth bypass |
| SRC-017 | MEDIUM | `set_cookie()` without `httponly=True` — XSS steals cookie |
| SRC-020 | HIGH | Hardcoded key/IV passed to cipher constructor |
| SRC-028 | MEDIUM | `random.seed(constant)` — fixed seed, predictable PRNG |
| SRC-029 | HIGH | `sha256(password)` / `sha512(password)` — not suitable for passwords |
| SRC-030 | HIGH | `assert is_authenticated(user)` — `python -O` strips assertions |
| SRC-032 | HIGH | Hardcoded JWT secret in `jwt.encode()` / `jwt.decode()` |
| SRC-033 | HIGH | `ssl.SSLContext(PROTOCOL_TLSv1)` — deprecated, known-vulnerable |
| SRC-039 | MEDIUM | `base64.b64encode(password)` — encoding ≠ encryption |
| SRC-046 | MEDIUM | `hashlib.new(algo_param)` — user-controlled algorithm |

#### Secrets & configuration
| Rule | Sev. | Description |
|---|---|---|
| SRC-014 | MEDIUM | `DEBUG = True` in source — must not be in production |
| SRC-031 | MEDIUM | `tempfile.mktemp()` — TOCTOU race condition |
| SRC-035 | MEDIUM | `os.environ.get("KEY", "literal")` — hardcoded fallback |
| SRC-041 | CRITICAL | `scheme://user:pass@host` in source — credentials in URL |

#### Access control & web
| Rule | Sev. | Description |
|---|---|---|
| SRC-015 | MEDIUM | `redirect(param)` — open redirect |
| SRC-021 | MEDIUM | `allow_origins=["*"]` — CORS wildcard |
| SRC-022 | HIGH | `jinja2.Template(param)` — SSTI |
| SRC-023 | MEDIUM | `re.compile(param)` — ReDoS via user-controlled regex |
| SRC-024 | MEDIUM | `logging.info(password)` — sensitive value in logs |
| SRC-025 | MEDIUM | `del response.headers["strict-transport-security"]` |
| SRC-026 | HIGH | `Model(**request_data)` — mass assignment |
| SRC-036 | MEDIUM | `redirect(request.args.get("next"))` — open redirect from request |
| SRC-037 | HIGH | `subprocess.run([program, ...])` with user-controlled executable |
| SRC-044 | MEDIUM | `response.headers["Location"] = param` — CRLF injection |

#### Unsafe XML
| Rule | Sev. | Description |
|---|---|---|
| SRC-018 | HIGH | `xml.etree.ElementTree.parse()` — XXE via entity expansion |

---

### TypeScript / JavaScript source rules (51) — `mcpprobe analyze` on `.ts`, `.js`, `.mjs`, `.cjs`

Regex-based line scanning — no Node.js required.

#### Injection
| Rule | Sev. | Description |
|---|---|---|
| TS-001 | CRITICAL/HIGH | Hardcoded API key / token prefix, or secret variable name |
| TS-002 | HIGH | `eval()` — arbitrary code execution |
| TS-003 | HIGH | `execSync()` — always shell-equivalent |
| TS-004 | HIGH | `shell: true` in `spawn()`/`exec()` options |
| TS-005 | HIGH | `exec(\`cmd ${input}\`)` — template literal command injection |
| TS-009 | HIGH | `` db.query(`SELECT ${input}`) `` — SQL injection via template literal |
| TS-022 | HIGH | `ejs.render(template)` with variable template — SSTI |
| TS-033 | HIGH | `innerHTML = input` / `document.write(input)` — DOM XSS |
| TS-040 | CRITICAL | `new Function(variable)` — runtime code compilation |
| TS-043 | HIGH | `db.query("SELECT " + input)` — SQL injection via concatenation |
| TS-047 | HIGH | `require(variable)` — dynamic module loading |
| TS-048 | CRITICAL | `fork(req.query.script)` — user-controlled Node.js script |

#### Path traversal & file access
| Rule | Sev. | Description |
|---|---|---|
| TS-008 | MEDIUM | `fs.readFile(variable)` / `fs.unlink(variable)` — path traversal |
| TS-027 | MEDIUM | `path.join(base, variable)` — `../` escape risk |
| TS-038 | MEDIUM | `fs.chmod(path, 0o777)` — world-writable permissions |
| TS-045 | HIGH | `res.sendFile(req.query.xxx)` — user-controlled path |
| TS-046 | HIGH | `fs.writeFile(req.query.xxx, ...)` — write to user-controlled path |

#### Deserialization
| Rule | Sev. | Description |
|---|---|---|
| TS-019 | HIGH | `serialize.unserialize()` — node-serialize code execution |
| TS-034 | MEDIUM | `yaml.load(input)` — unsafe YAML deserialization |

#### Network & SSRF
| Rule | Sev. | Description |
|---|---|---|
| TS-007 | MEDIUM | `fetch(variable)` / `axios.get(variable)` — SSRF |
| TS-011 | HIGH | `rejectUnauthorized: false` / `NODE_TLS_REJECT_UNAUTHORIZED=0` — MITM |

#### Authentication & cryptography
| Rule | Sev. | Description |
|---|---|---|
| TS-010 | MEDIUM | `Math.random()` assigned to `token`/`secret`/`otp` — insecure PRNG |
| TS-012 | MEDIUM | `crypto.createHash("md5")` / `("sha1")` — broken algorithm |
| TS-013 | MEDIUM | `===` on a security-sensitive name — timing-attack leaks |
| TS-016 | HIGH | JWT `algorithms: ["none"]` or verification disabled |
| TS-017 | MEDIUM | `res.cookie()` without `httpOnly`/`secure` — XSS / plain-HTTP theft |
| TS-020 | HIGH | Hardcoded key/IV in `createCipheriv()` |
| TS-028 | MEDIUM | `seedrandom("fixedSeed")` — deterministic PRNG |
| TS-029 | HIGH | `createHash("sha256").update(password)` — fast hash for passwords |
| TS-030 | HIGH | `assert(user.isAuthenticated)` — assertion bypass in prod |
| TS-032 | HIGH | Hardcoded JWT secret in `jwt.sign()` / `jwt.verify()` |
| TS-039 | MEDIUM | `btoa(password)` / `atob(secretKey)` — encoding ≠ encryption |

#### Secrets & configuration
| Rule | Sev. | Description |
|---|---|---|
| TS-014 | MEDIUM | `NODE_ENV = "development"` hardcoded |
| TS-031 | MEDIUM | `localStorage.setItem("token", ...)` — readable by any JS |
| TS-035 | MEDIUM | `process.env.JWT_SECRET \|\| "fallback"` — hardcoded fallback |
| TS-041 | CRITICAL | `scheme://user:pass@host` in source — credentials in URL |

#### Access control & web
| Rule | Sev. | Description |
|---|---|---|
| TS-006 | MEDIUM | `__proto__ = source` / `constructor.prototype` — prototype pollution |
| TS-015 | MEDIUM | `res.redirect(variable)` — open redirect |
| TS-018 | HIGH | `new DOMParser().parseFromString(variable, "text/xml")` — XXE |
| TS-021 | MEDIUM | `"Access-Control-Allow-Origin": "*"` — CORS wildcard |
| TS-023 | MEDIUM | `new RegExp(variable)` — ReDoS via user-controlled pattern |
| TS-024 | MEDIUM | `console.log(password)` — sensitive value in logs |
| TS-025 | MEDIUM | `res.removeHeader("x-frame-options")` — security header removed |
| TS-026 | HIGH | `Object.assign(user, req.body)` — mass assignment |
| TS-036 | MEDIUM | `res.redirect(req.query.next)` — open redirect from request |
| TS-037 | HIGH | `spawn(program, ...)` with variable executable |
| TS-044 | MEDIUM | `res.setHeader("Location", req.query.xxx)` — CRLF injection |
| TS-049 | MEDIUM | `setTimeout(handler, ...)` with variable callback |
| TS-050 | HIGH | `process.exit(req.query.code)` — user-controlled DoS |
| TS-051 | MEDIUM | `window.location = req.query.xxx` — DOM open redirect |
| TS-042 | HIGH | `vm.runInNewContext(variable)` — vm is not a sandbox |

---

### Dependency manifest rules (3) — `mcpprobe analyze`

Scanned automatically alongside source files.

#### `requirements*.txt`
| Rule | Sev. | Description |
|---|---|---|
| DEP-001 | MEDIUM | Package without exact `==` pin — supply chain risk |

#### `package.json`
| Rule | Sev. | Description |
|---|---|---|
| DEP-002 | HIGH | `"*"` or `"latest"` version — fully unpinned |
| DEP-003 | MEDIUM | `"^"`, `"~"`, `">="` range — permits unreviewed updates |

---

### Probe rules (7) — `mcpprobe probe`

#### Passive (always run)
| Rule | Sev. | Description |
|---|---|---|
| PROBE-001 | CRITICAL | Prompt-injection pattern in a tool description |
| PROBE-002 | HIGH | Tool name or description suggests arbitrary command execution |
| PROBE-003 | MEDIUM | Filesystem tool with unconstrained `path` parameter |
| PROBE-004 | HIGH | Input schema has a `code`, `command`, `script`, or `eval` parameter |
| PROBE-005 | INFO | Server exposes >15 tools — large attack surface |

#### Active (opt-in with `--active`)
| Rule | Sev. | Description |
|---|---|---|
| PROBE-010 | CRITICAL/HIGH | Path traversal succeeds (`../../../../etc/passwd`) |
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

Floor is 0. Exit code is controlled by `--fail-on`, not the score.

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

**New source rule** → extend `_Visitor` in `mcpprobe/analyzers/python_ast.py` (Python) or `_scan_line` in `mcpprobe/analyzers/ts_regex.py` (TypeScript), add a test in `tests/test_analyzers.py` or `tests/test_ts_analyzer.py`.

**New probe rule** → add to `mcpprobe/probes/metadata.py` (passive) or `mcpprobe/probes/active.py` (active), add a test in `tests/test_probes.py`.

---

## License

MIT © 2026 robkira01-max

---

## Disclaimer

MCPProbe identifies potential security issues in MCP configurations, source files, and live servers. A passing scan does not guarantee security — review all findings in context. Run active probes (`--active`) only on servers you own or have explicit written permission to test.
