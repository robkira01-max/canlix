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


def test_vulnerable_ts_fixture_has_first_twelve_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 13)}
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


# ── TS-012: weak hash algorithm ──────────────────────────────────────────────


def test_TS012_detects_createHash_md5(tmp_path):
    p = _ts(tmp_path, "const h = crypto.createHash('md5').update(data).digest('hex');")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-012" and f.severity == Severity.MEDIUM for f in findings)


def test_TS012_detects_createHash_sha1(tmp_path):
    p = _ts(tmp_path, 'const h = crypto.createHash("sha1").update(data).digest("hex");')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-012" for f in findings)


def test_TS012_detects_createHash_sha_dash_1(tmp_path):
    p = _ts(tmp_path, "const h = crypto.createHash('sha-1');")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-012" for f in findings)


def test_TS012_detects_createHash_md5_uppercase(tmp_path):
    p = _ts(tmp_path, "const h = crypto.createHash('MD5');")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-012" for f in findings)


def test_TS012_passes_createHash_sha256(tmp_path):
    p = _ts(tmp_path, "const h = crypto.createHash('sha256').update(data).digest('hex');")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-012" for f in findings)


def test_TS012_passes_createHash_sha3(tmp_path):
    p = _ts(tmp_path, "const h = crypto.createHash('sha3-256');")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-012" for f in findings)


def test_TS012_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-012" for f in findings)


# ── TS-013: non-constant-time comparison ─────────────────────────────────────


def test_TS013_detects_strict_eq_on_token(tmp_path):
    p = _ts(tmp_path, "if (storedToken === userToken) { return true; }")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-013" and f.severity == Severity.MEDIUM for f in findings)


def test_TS013_detects_strict_neq_on_password(tmp_path):
    p = _ts(tmp_path, "if (password !== expectedPassword) { throw new Error(); }")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-013" for f in findings)


def test_TS013_detects_loose_eq_on_secret(tmp_path):
    p = _ts(tmp_path, "const ok = (secret == stored);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-013" for f in findings)


def test_TS013_passes_comparison_against_string_literal(tmp_path):
    p = _ts(tmp_path, 'if (token === "") { throw new Error("empty"); }')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-013" for f in findings)


def test_TS013_passes_comparison_against_null(tmp_path):
    p = _ts(tmp_path, "if (token === null) { return false; }")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-013" for f in findings)


def test_TS013_passes_comparison_against_undefined(tmp_path):
    p = _ts(tmp_path, "if (token === undefined) { return false; }")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-013" for f in findings)


def test_TS013_passes_non_security_name_eq(tmp_path):
    p = _ts(tmp_path, "if (statusCode === 200) { return true; }")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-013" for f in findings)


def test_TS013_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-013" for f in findings)


# ── Full fixture — all 13 rules ───────────────────────────────────────────────


# ── TS-014: debug mode hardcoded ─────────────────────────────────────────────


def test_TS014_detects_NODE_ENV_development(tmp_path):
    p = _ts(tmp_path, 'const NODE_ENV = "development";')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-014" and f.severity == Severity.MEDIUM for f in findings)


def test_TS014_detects_NODE_ENV_dev(tmp_path):
    p = _ts(tmp_path, "const NODE_ENV = 'dev';")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-014" for f in findings)


def test_TS014_detects_DEBUG_true(tmp_path):
    p = _ts(tmp_path, "const DEBUG = true;")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-014" for f in findings)


def test_TS014_passes_NODE_ENV_production(tmp_path):
    p = _ts(tmp_path, 'const NODE_ENV = "production";')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-014" for f in findings)


def test_TS014_passes_NODE_ENV_from_process_env(tmp_path):
    p = _ts(tmp_path, "const env = process.env.NODE_ENV;")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-014" for f in findings)


def test_TS014_passes_DEBUG_false(tmp_path):
    p = _ts(tmp_path, "const DEBUG = false;")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-014" for f in findings)


def test_TS014_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-014" for f in findings)


# ── Full fixture — all 14 rules ───────────────────────────────────────────────


# ── TS-015: open redirect ─────────────────────────────────────────────────────


def test_TS015_detects_res_redirect_variable(tmp_path):
    p = _ts(tmp_path, "res.redirect(url);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-015" and f.severity == Severity.MEDIUM for f in findings)


def test_TS015_detects_window_location_variable(tmp_path):
    p = _ts(tmp_path, "window.location.href = redirectUrl;")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-015" for f in findings)


def test_TS015_detects_response_redirect(tmp_path):
    p = _ts(tmp_path, "response.redirect(targetUrl);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-015" for f in findings)


def test_TS015_passes_res_redirect_literal(tmp_path):
    p = _ts(tmp_path, 'res.redirect("/dashboard");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-015" for f in findings)


def test_TS015_passes_window_location_literal(tmp_path):
    p = _ts(tmp_path, 'window.location.href = "/home";')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-015" for f in findings)


def test_TS015_passes_window_location_https(tmp_path):
    p = _ts(tmp_path, 'window.location.href = "https://example.com";')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-015" for f in findings)


def test_TS015_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-015" for f in findings)


# ── Full fixture — all 15 rules ───────────────────────────────────────────────


# ── TS-016: JWT algorithm confusion ──────────────────────────────────────────


def test_TS016_detects_algorithms_none(tmp_path):
    p = _ts(tmp_path, "const opts = { algorithms: ['none'] };")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-016" and f.severity == Severity.HIGH for f in findings)


def test_TS016_detects_algorithms_none_double_quote(tmp_path):
    p = _ts(tmp_path, 'const opts = { algorithms: ["none"] };')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-016" for f in findings)


def test_TS016_detects_verify_signature_false(tmp_path):
    p = _ts(tmp_path, "const opts = { verify_signature: false };")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-016" for f in findings)


def test_TS016_detects_ignoreExpiration_true(tmp_path):
    p = _ts(tmp_path, "const opts = { ignoreExpiration: true };")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-016" for f in findings)


def test_TS016_passes_valid_algorithm(tmp_path):
    p = _ts(tmp_path, "const opts = { algorithms: ['HS256'] };")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-016" for f in findings)


def test_TS016_passes_ignoreExpiration_false(tmp_path):
    p = _ts(tmp_path, "const opts = { ignoreExpiration: false };")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-016" for f in findings)


def test_TS016_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-016" for f in findings)


# ── Full fixture — all 16 rules ───────────────────────────────────────────────


# ── TS-017: insecure cookie ───────────────────────────────────────────────────


def test_TS017_detects_res_cookie_without_httpOnly(tmp_path):
    p = _ts(tmp_path, "res.cookie('session', token, { secure: true });")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-017" and f.severity == Severity.MEDIUM for f in findings)


def test_TS017_detects_res_cookie_without_secure(tmp_path):
    p = _ts(tmp_path, "res.cookie('session', token, { httpOnly: true });")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-017" for f in findings)


def test_TS017_detects_res_cookie_bare(tmp_path):
    p = _ts(tmp_path, "res.cookie('session', token);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-017" for f in findings)


def test_TS017_passes_res_cookie_with_both_flags(tmp_path):
    p = _ts(tmp_path, "res.cookie('session', token, { httpOnly: true, secure: true });")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-017" for f in findings)


def test_TS017_detects_response_cookie(tmp_path):
    p = _ts(tmp_path, "response.cookie('session', token, { sameSite: 'strict' });")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-017" for f in findings)


def test_TS017_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-017" for f in findings)


# ── Full fixture — all 17 rules ───────────────────────────────────────────────


# ── TS-018: XXE injection ─────────────────────────────────────────────────────


def test_TS018_detects_DOMParser_parseFromString_variable(tmp_path):
    p = _ts(tmp_path, 'const doc = new DOMParser().parseFromString(xmlData, "text/xml");')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-018" and f.severity == Severity.HIGH for f in findings)


def test_TS018_detects_parser_parseFromString_variable(tmp_path):
    p = _ts(tmp_path, "const doc = parser.parseFromString(xmlInput);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-018" for f in findings)


def test_TS018_detects_new_JSDOM_variable(tmp_path):
    p = _ts(tmp_path, "const dom = new JSDOM(htmlContent);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-018" for f in findings)


def test_TS018_passes_parseFromString_literal(tmp_path):
    p = _ts(tmp_path, 'const doc = parser.parseFromString("<root/>", "text/xml");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-018" for f in findings)


def test_TS018_passes_JSDOM_literal(tmp_path):
    p = _ts(tmp_path, 'const dom = new JSDOM("<html></html>");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-018" for f in findings)


def test_TS018_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-018" for f in findings)


# ── Full fixture — all 18 rules ───────────────────────────────────────────────


def test_vulnerable_ts_fixture_has_all_eighteen_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 19)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── TS-019: unsafe deserialization ───────────────────────────────────────────


def test_TS019_detects_node_serialize_unserialize(tmp_path):
    p = _ts(tmp_path, "const obj = serialize.unserialize(userInput);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-019" for f in findings)


def test_TS019_detects_eval_json_parse(tmp_path):
    p = _ts(tmp_path, "const obj = eval(JSON.parse(data));")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-019" for f in findings)


def test_TS019_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-019" for f in findings)


# ── TS-020: hardcoded crypto key ─────────────────────────────────────────────


def test_TS020_detects_createCipheriv_literal_key(tmp_path):
    p = _ts(tmp_path, 'crypto.createCipheriv("aes-256-gcm", "hardcoded_key_32_bytes_12345678", iv)')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-020" for f in findings)


def test_TS020_detects_createDecipheriv_literal_key(tmp_path):
    p = _ts(tmp_path, 'crypto.createDecipheriv("aes-256-cbc", "hardcoded_key", iv)')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-020" for f in findings)


def test_TS020_passes_variable_key(tmp_path):
    p = _ts(tmp_path, 'crypto.createCipheriv("aes-256-gcm", key, iv)')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-020" for f in findings)


def test_TS020_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-020" for f in findings)


# ── TS-021: CORS wildcard ────────────────────────────────────────────────────


def test_TS021_detects_cors_origin_wildcard(tmp_path):
    p = _ts(tmp_path, 'app.use(cors({ origin: "*" }));')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-021" for f in findings)


def test_TS021_detects_set_header_wildcard(tmp_path):
    p = _ts(tmp_path, 'res.setHeader("Access-Control-Allow-Origin", "*");')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-021" for f in findings)


def test_TS021_passes_specific_origin(tmp_path):
    p = _ts(tmp_path, 'res.setHeader("Access-Control-Allow-Origin", "https://example.com");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-021" for f in findings)


def test_TS021_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-021" for f in findings)


# ── Full fixture — all 21 rules ───────────────────────────────────────────────


def test_vulnerable_ts_fixture_has_all_twentyone_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 22)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"
