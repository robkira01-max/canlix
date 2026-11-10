"""Tests for the TypeScript/JavaScript regex source analyzer — one test per rule."""

from __future__ import annotations

import textwrap
from pathlib import Path

from mcpprobe.analyzers import analyze_path
from mcpprobe.analyzers.ts_regex import analyze_typescript
from mcpprobe.models import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "source"


# ── Helpers ────────────────────────────────────────────────────────────────


def _ts(tmp_path: Path, code: str, suffix: str = ".ts") -> Path:
    """Write TypeScript/JS source to a temp file and return its path."""
    p = tmp_path / f"test_server{suffix}"
    p.write_text(textwrap.dedent(code))
    return p


# ── TS-001: hardcoded secret ───────────────────────────────────────────────


def test_TS001_detects_github_token_prefix(tmp_path):
    p = _ts(tmp_path, 'const TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-001" and f.severity == Severity.CRITICAL for f in findings)


def test_TS001_detects_openai_key_prefix(tmp_path):
    p = _ts(tmp_path, 'const KEY = "sk-1234567890abcdef1234567890abcdef1234";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-001" and f.severity == Severity.CRITICAL for f in findings)


def test_TS001_detects_aws_access_key(tmp_path):
    p = _ts(tmp_path, 'const AWS = "AKIAIOSFODNN7EXAMPLE";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-001" and f.severity == Severity.CRITICAL for f in findings)


def test_TS001_detects_secret_variable_name(tmp_path):
    p = _ts(tmp_path, 'const DATABASE_PASSWORD = "super_secret_passphrase_1234";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-001" for f in findings)


def test_TS001_detects_typed_secret_variable(tmp_path):
    # TypeScript type annotation — should still be detected
    p = _ts(tmp_path, 'const API_KEY: string = "definitely-a-real-key-abcde12345";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-001" for f in findings)


def test_TS001_passes_env_lookup(tmp_path):
    p = _ts(tmp_path, "const API_KEY = process.env.API_KEY ?? '';")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-001" for f in findings)


def test_TS001_passes_short_string(tmp_path):
    p = _ts(tmp_path, 'const TOKEN = "abc";')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-001" for f in findings)


# ── TS-002: eval ────────────────────────────────────────────────────────────


def test_TS002_detects_eval(tmp_path):
    p = _ts(tmp_path, "const result = eval(userInput);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-002" and f.severity == Severity.HIGH for f in findings)


def test_TS002_detects_eval_with_space(tmp_path):
    p = _ts(tmp_path, "eval (expression);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-002" for f in findings)


def test_TS002_passes_no_eval(tmp_path):
    p = _ts(tmp_path, "const val = JSON.parse(data);")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-002" for f in findings)


# ── TS-003: execSync ────────────────────────────────────────────────────────


def test_TS003_detects_execSync(tmp_path):
    p = _ts(tmp_path, "const out = execSync(cmd).toString();")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-003" and f.severity == Severity.HIGH for f in findings)


def test_TS003_detects_qualified_execSync(tmp_path):
    p = _ts(tmp_path, "child_process.execSync(cmd);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-003" for f in findings)


def test_TS003_does_not_flag_execFileSync(tmp_path):
    # execFileSync passes args array — no shell interpretation
    p = _ts(tmp_path, 'execFileSync("ls", ["-la"]);')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-003" for f in findings)


# ── TS-004: shell: true ─────────────────────────────────────────────────────


def test_TS004_detects_shell_true(tmp_path):
    p = _ts(tmp_path, "spawn(cmd, { shell: true });")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-004" and f.severity == Severity.HIGH for f in findings)


def test_TS004_detects_shell_true_in_exec(tmp_path):
    p = _ts(tmp_path, "exec(cmd, { shell: true, timeout: 1000 });")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-004" for f in findings)


def test_TS004_passes_shell_false(tmp_path):
    p = _ts(tmp_path, 'spawn("ls", ["-la"], { shell: false });')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-004" for f in findings)


# ── TS-005: exec with template literal ─────────────────────────────────────


def test_TS005_detects_exec_template_literal(tmp_path):
    p = _ts(tmp_path, "exec(`ls ${userInput}`);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-005" and f.severity == Severity.HIGH for f in findings)


def test_TS005_passes_exec_string_literal(tmp_path):
    # Static string — no interpolation, low risk
    p = _ts(tmp_path, 'exec("ls -la");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-005" for f in findings)


# ── TS-006: prototype pollution ─────────────────────────────────────────────


def test_TS006_detects_proto_assignment(tmp_path):
    p = _ts(tmp_path, "(obj as any).__proto__ = source;")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-006" and f.severity == Severity.MEDIUM for f in findings)


def test_TS006_detects_constructor_prototype(tmp_path):
    p = _ts(tmp_path, 'obj.constructor["prototype"] = {};')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-006" for f in findings)


def test_TS006_passes_safe_merge(tmp_path):
    p = _ts(tmp_path, "const copy = Object.assign({}, base, overrides);")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-006" for f in findings)


# ── Integration: fixture files ──────────────────────────────────────────────


def test_clean_ts_fixture_has_no_findings():
    findings = analyze_typescript(FIXTURES / "clean_server.ts")
    assert len(findings) == 0, [f.message for f in findings]


def test_vulnerable_ts_fixture_has_all_eleven_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {
        "TS-001",
        "TS-002",
        "TS-003",
        "TS-004",
        "TS-005",
        "TS-006",
        "TS-007",
        "TS-008",
        "TS-009",
        "TS-010",
        "TS-011",
    }
    assert expected.issubset(rule_ids)


def test_analyze_path_picks_up_ts_files(tmp_path):
    _ts(tmp_path, "const result = eval(x);")
    findings = analyze_path(tmp_path)
    assert any(f.rule_id == "TS-002" for f in findings)


def test_analyze_path_picks_up_js_files(tmp_path):
    _ts(tmp_path, "execSync(cmd);", suffix=".js")
    findings = analyze_path(tmp_path)
    assert any(f.rule_id == "TS-003" for f in findings)


def test_analyze_path_picks_up_mjs_files(tmp_path):
    _ts(tmp_path, "spawn(cmd, { shell: true });", suffix=".mjs")
    findings = analyze_path(tmp_path)
    assert any(f.rule_id == "TS-004" for f in findings)


def test_ts_line_numbers_are_accurate(tmp_path):
    p = _ts(
        tmp_path,
        """
        const a = 1;
        const b = 2;
        const result = eval(userInput);
        """,
    )
    findings = analyze_typescript(p)
    ts002 = [f for f in findings if f.rule_id == "TS-002"]
    assert ts002
    assert ts002[0].line_number > 1
    assert "eval" in ts002[0].code_snippet


# ── TS-007: SSRF — HTTP client with variable URL ────────────────────────────


def test_TS007_detects_fetch_with_variable(tmp_path):
    p = _ts(tmp_path, "const response = fetch(userUrl);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-007" and f.severity == Severity.MEDIUM for f in findings)


def test_TS007_detects_axios_get_with_variable(tmp_path):
    p = _ts(tmp_path, "const data = axios.get(endpoint);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-007" for f in findings)


def test_TS007_detects_got_with_variable(tmp_path):
    p = _ts(tmp_path, "const res = got(remoteUrl);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-007" for f in findings)


def test_TS007_passes_fetch_with_literal_url(tmp_path):
    p = _ts(tmp_path, 'const res = fetch("https://api.example.com/data");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-007" for f in findings)


def test_TS007_passes_axios_with_literal_url(tmp_path):
    p = _ts(tmp_path, 'const res = axios.get("https://api.example.com/items");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-007" for f in findings)


# ── TS-008: path traversal — fs I/O with variable path ──────────────────────


def test_TS008_detects_fs_readFile_with_variable(tmp_path):
    p = _ts(tmp_path, "fs.readFile(userPath, 'utf8', callback);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-008" and f.severity == Severity.MEDIUM for f in findings)


def test_TS008_detects_fs_readFileSync_with_variable(tmp_path):
    p = _ts(tmp_path, "const data = fs.readFileSync(filePath);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-008" for f in findings)


def test_TS008_detects_fs_writeFile_with_variable(tmp_path):
    p = _ts(tmp_path, "fs.writeFile(outputPath, content, callback);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-008" for f in findings)


def test_TS008_detects_fs_unlink_with_variable(tmp_path):
    p = _ts(tmp_path, "fs.unlink(targetPath, callback);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-008" for f in findings)


def test_TS008_passes_fs_readFile_with_literal(tmp_path):
    p = _ts(tmp_path, 'const data = fs.readFile("/etc/hostname", "utf8", cb);')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-008" for f in findings)


# ── TS-009: SQL injection — template literal in DB query ────────────────────


def test_TS009_detects_query_template_literal(tmp_path):
    p = _ts(tmp_path, "const rows = db.query(`SELECT * FROM users WHERE id = ${userId}`);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-009" and f.severity == Severity.HIGH for f in findings)


def test_TS009_detects_execute_template_literal(tmp_path):
    p = _ts(tmp_path, "conn.execute(`DELETE FROM sessions WHERE token = ${token}`);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-009" for f in findings)


def test_TS009_detects_knex_raw(tmp_path):
    p = _ts(tmp_path, "knex.raw(`SELECT * FROM users WHERE name = '${name}'`);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-009" for f in findings)


def test_TS009_passes_parameterised_query(tmp_path):
    p = _ts(tmp_path, 'db.query("SELECT * FROM users WHERE id = $1", [userId]);')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-009" for f in findings)


def test_TS009_passes_static_template_literal(tmp_path):
    # Template literal with no interpolation — no $ in it
    p = _ts(tmp_path, "db.query(`SELECT * FROM users WHERE active = true`);")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-009" for f in findings)


# ── TS-010: insecure PRNG — Math.random() in security context ───────────────


def test_TS010_detects_math_random_for_token(tmp_path):
    p = _ts(tmp_path, "const token = Math.random().toString(36).substring(2);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-010" and f.severity == Severity.MEDIUM for f in findings)


def test_TS010_detects_math_random_for_secret(tmp_path):
    p = _ts(tmp_path, "const secret = Math.random();")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-010" for f in findings)


def test_TS010_detects_math_random_for_otp(tmp_path):
    p = _ts(tmp_path, "const otp = Math.floor(Math.random() * 1000000);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-010" for f in findings)


def test_TS010_detects_math_random_for_session_id(tmp_path):
    p = _ts(tmp_path, "const session_id = Math.random().toString(36);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-010" for f in findings)


def test_TS010_detects_math_random_for_password(tmp_path):
    p = _ts(tmp_path, "const password = Math.random().toString(36).slice(2, 10);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-010" for f in findings)


def test_TS010_passes_math_random_for_index(tmp_path):
    p = _ts(tmp_path, "const index = Math.floor(Math.random() * array.length);")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-010" for f in findings)


def test_TS010_passes_math_random_for_color(tmp_path):
    p = _ts(tmp_path, "const randomColor = Math.random();")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-010" for f in findings)


def test_TS010_passes_crypto_random_bytes_for_token(tmp_path):
    p = _ts(tmp_path, "const token = crypto.randomBytes(32).toString('hex');")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-010" for f in findings)


def test_TS010_fixture_fires_on_vulnerable_server(tmp_path):
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-010" for f in findings)


# ── TS-011: TLS verification disabled ───────────────────────────────────────


def test_TS011_detects_reject_unauthorized_false(tmp_path):
    p = _ts(tmp_path, "const opts = { rejectUnauthorized: false };")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-011" and f.severity == Severity.HIGH for f in findings)


def test_TS011_detects_reject_unauthorized_false_in_https_options(tmp_path):
    p = _ts(tmp_path, "https.request({ hostname: 'example.com', rejectUnauthorized: false });")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-011" for f in findings)


def test_TS011_detects_node_tls_env_string(tmp_path):
    p = _ts(tmp_path, 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-011" for f in findings)


def test_TS011_detects_node_tls_env_bare(tmp_path):
    p = _ts(tmp_path, "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-011" for f in findings)


def test_TS011_passes_reject_unauthorized_true(tmp_path):
    p = _ts(tmp_path, "const opts = { rejectUnauthorized: true };")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-011" for f in findings)


def test_TS011_passes_no_tls_options(tmp_path):
    p = _ts(tmp_path, 'const opts = { hostname: "example.com", port: 443 };')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-011" for f in findings)


def test_TS011_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-011" for f in findings)
