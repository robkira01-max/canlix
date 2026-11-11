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


# ── TS-022: SSTI ─────────────────────────────────────────────────────────────


def test_TS022_detects_ejs_render_variable(tmp_path):
    p = _ts(tmp_path, "const html = ejs.render(template, context);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-022" for f in findings)


def test_TS022_detects_handlebars_compile_variable(tmp_path):
    p = _ts(tmp_path, "const tmpl = Handlebars.compile(templateStr);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-022" for f in findings)


def test_TS022_passes_ejs_render_literal(tmp_path):
    p = _ts(tmp_path, 'const html = ejs.render("<h1>Hello</h1>", {});')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-022" for f in findings)


def test_TS022_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-022" for f in findings)


# ── TS-023: ReDoS ────────────────────────────────────────────────────────────


def test_TS023_detects_new_RegExp_variable(tmp_path):
    p = _ts(tmp_path, "const rx = new RegExp(pattern);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-023" for f in findings)


def test_TS023_passes_new_RegExp_literal(tmp_path):
    p = _ts(tmp_path, 'const rx = new RegExp("[a-z]+");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-023" for f in findings)


def test_TS023_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-023" for f in findings)


# ── TS-024: sensitive data in logs ───────────────────────────────────────────


def test_TS024_detects_console_log_password(tmp_path):
    p = _ts(tmp_path, "console.log('Login attempt', password);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-024" for f in findings)


def test_TS024_detects_logger_info_token(tmp_path):
    p = _ts(tmp_path, "logger.info('Got token:', authToken);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-024" for f in findings)


def test_TS024_passes_non_sensitive_log(tmp_path):
    p = _ts(tmp_path, "console.log('User logged in:', username);")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-024" for f in findings)


def test_TS024_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-024" for f in findings)


# ── Full fixture — all 24 rules ───────────────────────────────────────────────


def test_vulnerable_ts_fixture_has_all_twentyfour_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 25)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── TS-025: security header removed ──────────────────────────────────────────


def test_TS025_detects_removeHeader_xframe(tmp_path):
    p = _ts(tmp_path, 'res.removeHeader("x-frame-options");')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-025" for f in findings)


def test_TS025_detects_removeHeader_hsts(tmp_path):
    p = _ts(tmp_path, 'res.removeHeader("strict-transport-security");')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-025" for f in findings)


def test_TS025_passes_unrelated_header(tmp_path):
    p = _ts(tmp_path, 'res.removeHeader("accept");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-025" for f in findings)


def test_TS025_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-025" for f in findings)


# ── TS-026: mass assignment ───────────────────────────────────────────────────


def test_TS026_detects_Object_assign_req_body(tmp_path):
    p = _ts(tmp_path, "Object.assign(user, req.body);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-026" for f in findings)


def test_TS026_detects_spread_req_body(tmp_path):
    p = _ts(tmp_path, "const updated = { ...req.body };")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-026" for f in findings)


def test_TS026_passes_explicit_fields(tmp_path):
    p = _ts(tmp_path, "const { name, email } = req.body;")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-026" for f in findings)


def test_TS026_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-026" for f in findings)


# ── TS-027: path traversal via path.join ─────────────────────────────────────


def test_TS027_detects_path_join_variable(tmp_path):
    p = _ts(tmp_path, "const full = path.join(baseDir, filename);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-027" for f in findings)


def test_TS027_passes_all_literal(tmp_path):
    p = _ts(tmp_path, 'const full = path.join("/data", "report.csv");')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-027" for f in findings)


def test_TS027_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-027" for f in findings)


# ── Full fixture — all 27 rules ───────────────────────────────────────────────


def test_vulnerable_ts_fixture_has_all_twentyseven_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 28)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── TS-028: fixed PRNG seed ───────────────────────────────────────────────────


def test_TS028_detects_seedrandom_literal(tmp_path):
    p = _ts(tmp_path, 'const rng = seedrandom("fixedSeed");')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-028" for f in findings)


def test_TS028_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-028" for f in findings)


# ── TS-029: password hashed with fast algorithm ───────────────────────────────


def test_TS029_detects_sha256_update_password(tmp_path):
    p = _ts(tmp_path, 'crypto.createHash("sha256").update(password).digest("hex")')
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-029" for f in findings)


def test_TS029_passes_sha256_non_password(tmp_path):
    p = _ts(tmp_path, 'crypto.createHash("sha256").update(documentContent).digest("hex")')
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-029" for f in findings)


def test_TS029_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-029" for f in findings)


# ── TS-030: assert used for access control ────────────────────────────────────


def test_TS030_detects_assert_isAuthenticated(tmp_path):
    p = _ts(tmp_path, "assert(user.isAuthenticated);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-030" for f in findings)


def test_TS030_detects_assert_isAdmin(tmp_path):
    p = _ts(tmp_path, "assert(session.isAdmin);")
    findings = analyze_typescript(p)
    assert any(f.rule_id == "TS-030" for f in findings)


def test_TS030_passes_non_auth_assert(tmp_path):
    p = _ts(tmp_path, "assert(items.length > 0);")
    findings = analyze_typescript(p)
    assert not any(f.rule_id == "TS-030" for f in findings)


def test_TS030_fixture_fires_on_vulnerable_server():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    assert any(f.rule_id == "TS-030" for f in findings)


# ── TS-031: sensitive data in localStorage ────────────────────────────────────


def test_TS031_detects_token_in_local_storage(tmp_path):
    p = _ts(tmp_path, 'localStorage.setItem("token", tok);')
    assert any(f.rule_id == "TS-031" for f in analyze_typescript(p))


def test_TS031_detects_password_in_session_storage(tmp_path):
    p = _ts(tmp_path, 'sessionStorage.setItem("password", pwd);')
    assert any(f.rule_id == "TS-031" for f in analyze_typescript(p))


def test_TS031_passes_non_sensitive_key(tmp_path):
    p = _ts(tmp_path, 'localStorage.setItem("theme", "dark");')
    assert not any(f.rule_id == "TS-031" for f in analyze_typescript(p))


# ── TS-032: hardcoded JWT secret ──────────────────────────────────────────────


def test_TS032_detects_jwt_sign_literal_secret(tmp_path):
    p = _ts(tmp_path, 'jwt.sign(payload, "super_secret_key_123456");')
    assert any(f.rule_id == "TS-032" for f in analyze_typescript(p))


def test_TS032_detects_jsonwebtoken_verify_literal(tmp_path):
    p = _ts(tmp_path, 'jsonwebtoken.verify(tok, "my_hardcoded_secret_key");')
    assert any(f.rule_id == "TS-032" for f in analyze_typescript(p))


def test_TS032_passes_env_secret(tmp_path):
    p = _ts(tmp_path, "jwt.sign(payload, process.env.JWT_SECRET);")
    assert not any(f.rule_id == "TS-032" for f in analyze_typescript(p))


# ── TS-033: DOM XSS via innerHTML ─────────────────────────────────────────────


def test_TS033_detects_inner_html_variable(tmp_path):
    p = _ts(tmp_path, "el.innerHTML = userInput;")
    assert any(f.rule_id == "TS-033" for f in analyze_typescript(p))


def test_TS033_detects_document_write_variable(tmp_path):
    p = _ts(tmp_path, "document.write(response);")
    assert any(f.rule_id == "TS-033" for f in analyze_typescript(p))


def test_TS033_passes_literal_html(tmp_path):
    p = _ts(tmp_path, 'el.innerHTML = "<p>static</p>";')
    assert not any(f.rule_id == "TS-033" for f in analyze_typescript(p))


# ── TS-034: unsafe YAML deserialisation ──────────────────────────────────────


def test_TS034_detects_yaml_load_variable(tmp_path):
    p = _ts(tmp_path, "const data = yaml.load(input);")
    assert any(f.rule_id == "TS-034" for f in analyze_typescript(p))


def test_TS034_detects_jsYaml_load(tmp_path):
    p = _ts(tmp_path, "const cfg = jsYaml.load(raw);")
    assert any(f.rule_id == "TS-034" for f in analyze_typescript(p))


def test_TS034_passes_safe_load(tmp_path):
    p = _ts(tmp_path, "const data = yaml.safeLoad(input);")
    assert not any(f.rule_id == "TS-034" for f in analyze_typescript(p))


# ── TS-035: hardcoded env fallback ────────────────────────────────────────────


def test_TS035_detects_jwt_secret_fallback(tmp_path):
    p = _ts(tmp_path, 'const SECRET = process.env.JWT_SECRET || "fallback_key_1234";')
    assert any(f.rule_id == "TS-035" for f in analyze_typescript(p))


def test_TS035_detects_nullish_coalescing_fallback(tmp_path):
    p = _ts(tmp_path, 'const KEY = process.env.API_KEY ?? "hardcoded_api_key";')
    assert any(f.rule_id == "TS-035" for f in analyze_typescript(p))


def test_TS035_passes_nonsensitive_var(tmp_path):
    p = _ts(tmp_path, 'const PORT = process.env.PORT || "3000";')
    assert not any(f.rule_id == "TS-035" for f in analyze_typescript(p))


# ── TS-036: open redirect from request data ───────────────────────────────────


def test_TS036_detects_redirect_query(tmp_path):
    p = _ts(tmp_path, "res.redirect(req.query.next);")
    assert any(f.rule_id == "TS-036" for f in analyze_typescript(p))


def test_TS036_detects_redirect_body(tmp_path):
    p = _ts(tmp_path, "res.redirect(req.body.returnUrl);")
    assert any(f.rule_id == "TS-036" for f in analyze_typescript(p))


def test_TS036_passes_literal_redirect(tmp_path):
    p = _ts(tmp_path, 'res.redirect("/dashboard");')
    assert not any(f.rule_id == "TS-036" for f in analyze_typescript(p))


# ── TS-037: user-controlled executable in spawn / execFile ────────────────────


def test_TS037_detects_spawn_variable(tmp_path):
    p = _ts(tmp_path, "spawn(userCmd, ['--config', 'cfg.json']);")
    assert any(f.rule_id == "TS-037" for f in analyze_typescript(p))


def test_TS037_detects_execFile_variable(tmp_path):
    p = _ts(tmp_path, "execFile(program, args);")
    assert any(f.rule_id == "TS-037" for f in analyze_typescript(p))


def test_TS037_passes_spawn_literal(tmp_path):
    p = _ts(tmp_path, 'spawn("node", ["app.js"]);')
    assert not any(f.rule_id == "TS-037" for f in analyze_typescript(p))


# ── TS-038: world-writable file permissions ────────────────────────────────────


def test_TS038_detects_chmod_0o777(tmp_path):
    p = _ts(tmp_path, "fs.chmod(filePath, 0o777, cb);")
    assert any(f.rule_id == "TS-038" for f in analyze_typescript(p))


def test_TS038_detects_chmodSync_511(tmp_path):
    p = _ts(tmp_path, "fs.chmodSync(filePath, 511);")
    assert any(f.rule_id == "TS-038" for f in analyze_typescript(p))


def test_TS038_passes_chmod_0o644(tmp_path):
    p = _ts(tmp_path, "fs.chmod(filePath, 0o644, cb);")
    assert not any(f.rule_id == "TS-038" for f in analyze_typescript(p))


# ── TS-039: base64 as obfuscation on a sensitive value ────────────────────────


def test_TS039_detects_btoa_password(tmp_path):
    p = _ts(tmp_path, "const encoded = btoa(password);")
    assert any(f.rule_id == "TS-039" for f in analyze_typescript(p))


def test_TS039_detects_atob_secret(tmp_path):
    p = _ts(tmp_path, "const val = atob(secretKey);")
    assert any(f.rule_id == "TS-039" for f in analyze_typescript(p))


def test_TS039_passes_btoa_nonsensitive(tmp_path):
    p = _ts(tmp_path, "const img = btoa(imageData);")
    assert not any(f.rule_id == "TS-039" for f in analyze_typescript(p))


# ── TS-043: SQL injection via string concatenation ────────────────────────────


def test_TS043_detects_query_concat_string(tmp_path):
    p = _ts(tmp_path, 'db.query("SELECT * FROM users WHERE id = " + userId);')
    assert any(f.rule_id == "TS-043" for f in analyze_typescript(p))


def test_TS043_detects_execute_concat_string(tmp_path):
    p = _ts(tmp_path, 'conn.execute("SELECT * FROM t WHERE name = \'" + name + "\'");')
    assert any(f.rule_id == "TS-043" for f in analyze_typescript(p))


def test_TS043_passes_parameterized_query(tmp_path):
    p = _ts(tmp_path, 'db.query("SELECT * FROM users WHERE id = $1", [userId]);')
    assert not any(f.rule_id == "TS-043" for f in analyze_typescript(p))


# ── TS-044: HTTP header injection ─────────────────────────────────────────────


def test_TS044_detects_setHeader_from_query(tmp_path):
    p = _ts(tmp_path, 'res.setHeader("Location", req.query.returnUrl);')
    assert any(f.rule_id == "TS-044" for f in analyze_typescript(p))


def test_TS044_detects_append_from_body(tmp_path):
    p = _ts(tmp_path, 'res.append("X-Custom", req.body.value);')
    assert any(f.rule_id == "TS-044" for f in analyze_typescript(p))


def test_TS044_passes_literal_header_value(tmp_path):
    p = _ts(tmp_path, 'res.setHeader("Content-Type", "application/json");')
    assert not any(f.rule_id == "TS-044" for f in analyze_typescript(p))


# ── TS-045: file serving with user-controlled path ────────────────────────────


def test_TS045_detects_sendFile_from_query(tmp_path):
    p = _ts(tmp_path, "res.sendFile(req.query.file);")
    assert any(f.rule_id == "TS-045" for f in analyze_typescript(p))


def test_TS045_detects_download_from_body(tmp_path):
    p = _ts(tmp_path, "res.download(req.body.filename);")
    assert any(f.rule_id == "TS-045" for f in analyze_typescript(p))


def test_TS045_passes_sendFile_literal(tmp_path):
    p = _ts(tmp_path, 'res.sendFile("/var/www/html/index.html");')
    assert not any(f.rule_id == "TS-045" for f in analyze_typescript(p))


# ── TS-040: new Function() with dynamic argument ──────────────────────────────


def test_TS040_detects_new_Function_variable(tmp_path):
    p = _ts(tmp_path, "const fn = new Function(userCode);")
    assert any(f.rule_id == "TS-040" for f in analyze_typescript(p))


def test_TS040_detects_new_Function_multiple_args_variable(tmp_path):
    p = _ts(tmp_path, "const fn = new Function('a', bodyCode);")
    assert not any(f.rule_id == "TS-040" for f in analyze_typescript(p))


def test_TS040_passes_new_Function_literal(tmp_path):
    p = _ts(tmp_path, 'const fn = new Function("return 42");')
    assert not any(f.rule_id == "TS-040" for f in analyze_typescript(p))


# ── TS-041: credentials in connection-string URL ──────────────────────────────


def test_TS041_detects_postgresql_credentials(tmp_path):
    p = _ts(tmp_path, 'const URL = "postgresql://admin:password123@db.host/prod";')
    assert any(f.rule_id == "TS-041" for f in analyze_typescript(p))


def test_TS041_detects_mongodb_credentials(tmp_path):
    p = _ts(tmp_path, 'const MONGO = "mongodb://user:s3cret@mongo.example.com/mydb";')
    assert any(f.rule_id == "TS-041" for f in analyze_typescript(p))


def test_TS041_passes_url_without_password(tmp_path):
    p = _ts(tmp_path, 'const URL = "postgresql://localhost/mydb";')
    assert not any(f.rule_id == "TS-041" for f in analyze_typescript(p))


# ── TS-042: vm.runInNewContext / vm.Script with dynamic code ──────────────────


def test_TS042_detects_vm_runInNewContext_variable(tmp_path):
    p = _ts(tmp_path, "vm.runInNewContext(userCode, {});")
    assert any(f.rule_id == "TS-042" for f in analyze_typescript(p))


def test_TS042_detects_vm_runInThisContext_variable(tmp_path):
    p = _ts(tmp_path, "vm.runInThisContext(code);")
    assert any(f.rule_id == "TS-042" for f in analyze_typescript(p))


def test_TS042_passes_vm_runInNewContext_literal(tmp_path):
    p = _ts(tmp_path, 'vm.runInNewContext("1 + 1", {});')
    assert not any(f.rule_id == "TS-042" for f in analyze_typescript(p))


# ── TS-046: fs.writeFile with user-controlled path from request ───────────────


def test_TS046_detects_writeFile_req_query(tmp_path):
    p = _ts(tmp_path, "fs.writeFile(req.query.filename, data, () => {});")
    assert any(f.rule_id == "TS-046" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS046_detects_writeFileSync_req_params(tmp_path):
    p = _ts(tmp_path, "fs.writeFileSync(req.params.path, content);")
    assert any(f.rule_id == "TS-046" for f in analyze_typescript(p))


def test_TS046_passes_writeFile_literal_path(tmp_path):
    p = _ts(tmp_path, 'fs.writeFile("/tmp/output.txt", data, () => {});')
    assert not any(f.rule_id == "TS-046" for f in analyze_typescript(p))


# ── TS-047: require(variable) — dynamic module loading ───────────────────────


def test_TS047_detects_require_variable(tmp_path):
    p = _ts(tmp_path, "const mod = require(pluginName);")
    assert any(f.rule_id == "TS-047" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS047_passes_require_literal(tmp_path):
    p = _ts(tmp_path, 'const path = require("path");')
    assert not any(f.rule_id == "TS-047" for f in analyze_typescript(p))


# ── TS-048: child_process.fork() with user-controlled script ─────────────────


def test_TS048_detects_fork_req_query(tmp_path):
    p = _ts(tmp_path, "child_process.fork(req.query.script);")
    assert any(f.rule_id == "TS-048" and f.severity == Severity.CRITICAL for f in analyze_typescript(p))


def test_TS048_detects_fork_req_body(tmp_path):
    p = _ts(tmp_path, "fork(req.body.scriptPath, args);")
    assert any(f.rule_id == "TS-048" for f in analyze_typescript(p))


def test_TS048_passes_fork_literal_path(tmp_path):
    p = _ts(tmp_path, 'child_process.fork("./worker.js");')
    assert not any(f.rule_id == "TS-048" for f in analyze_typescript(p))


# ── TS-049: setTimeout/setInterval with variable callback ─────────────────────


def test_TS049_detects_setTimeout_variable(tmp_path):
    p = _ts(tmp_path, "setTimeout(handler, 1000);")
    assert any(f.rule_id == "TS-049" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS049_passes_setTimeout_arrow_function(tmp_path):
    p = _ts(tmp_path, "setTimeout(() => doWork(), 1000);")
    assert not any(f.rule_id == "TS-049" for f in analyze_typescript(p))


def test_TS049_passes_setTimeout_function_expression(tmp_path):
    p = _ts(tmp_path, "setTimeout(function() { doWork(); }, 1000);")
    assert not any(f.rule_id == "TS-049" for f in analyze_typescript(p))


# ── TS-050: process.exit() with user-controlled argument ─────────────────────


def test_TS050_detects_process_exit_req_query(tmp_path):
    p = _ts(tmp_path, "process.exit(req.query.code);")
    assert any(f.rule_id == "TS-050" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS050_passes_process_exit_literal(tmp_path):
    p = _ts(tmp_path, "process.exit(1);")
    assert not any(f.rule_id == "TS-050" for f in analyze_typescript(p))


# ── TS-051: DOM open redirect via window.location ────────────────────────────


def test_TS051_detects_window_location_req(tmp_path):
    p = _ts(tmp_path, "window.location = req.query.returnUrl;")
    assert any(f.rule_id == "TS-051" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS051_detects_location_href_req(tmp_path):
    p = _ts(tmp_path, "location.href = req.params.url;")
    assert any(f.rule_id == "TS-051" for f in analyze_typescript(p))


def test_TS051_passes_window_location_literal(tmp_path):
    p = _ts(tmp_path, 'window.location = "/dashboard";')
    assert not any(f.rule_id == "TS-051" for f in analyze_typescript(p))


# ── TS-052: document.getElementById with request data ────────────────────────


def test_TS052_detects_getElementById_req(tmp_path):
    p = _ts(tmp_path, "document.getElementById(req.query.section).classList.add('x');")
    assert any(f.rule_id == "TS-052" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS052_passes_getElementById_literal(tmp_path):
    p = _ts(tmp_path, 'document.getElementById("main").classList.add("active");')
    assert not any(f.rule_id == "TS-052" for f in analyze_typescript(p))


# ── TS-053: fetch with template literal URL from request data ─────────────────


def test_TS053_detects_fetch_template_req(tmp_path):
    p = _ts(tmp_path, "fetch(`/api/data/${req.query.resource}`);")
    assert any(f.rule_id == "TS-053" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS053_detects_axios_template_req(tmp_path):
    p = _ts(tmp_path, "axios.get(`/internal/${req.params.path}`);")
    assert any(f.rule_id == "TS-053" for f in analyze_typescript(p))


def test_TS053_passes_fetch_literal_url(tmp_path):
    p = _ts(tmp_path, 'fetch("/api/data");')
    assert not any(f.rule_id == "TS-053" for f in analyze_typescript(p))


# ── TS-054: localStorage.getItem("token") as auth source ─────────────────────


def test_TS054_detects_localStorage_token(tmp_path):
    p = _ts(tmp_path, 'const t = localStorage.getItem("token");')
    assert any(f.rule_id == "TS-054" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS054_detects_localStorage_session(tmp_path):
    p = _ts(tmp_path, "const s = localStorage.getItem('session');")
    assert any(f.rule_id == "TS-054" for f in analyze_typescript(p))


def test_TS054_passes_localStorage_non_sensitive(tmp_path):
    p = _ts(tmp_path, 'const pref = localStorage.getItem("theme");')
    assert not any(f.rule_id == "TS-054" for f in analyze_typescript(p))


# ── TS-055: crypto.randomBytes(req.xxx) — DoS via large allocation ───────────


def test_TS055_detects_randomBytes_req_query(tmp_path):
    p = _ts(tmp_path, "crypto.randomBytes(Number(req.query.size));")
    assert any(f.rule_id == "TS-055" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS055_passes_randomBytes_literal(tmp_path):
    p = _ts(tmp_path, "crypto.randomBytes(32);")
    assert not any(f.rule_id == "TS-055" for f in analyze_typescript(p))


# ── TS-056: res.download(req.xxx) — path traversal via Express download ───────


def test_TS056_detects_download_req_query(tmp_path):
    p = _ts(tmp_path, "res.download(req.query.file);")
    assert any(f.rule_id == "TS-056" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS056_detects_download_req_params(tmp_path):
    p = _ts(tmp_path, "res.download(req.params.filename);")
    assert any(f.rule_id == "TS-056" for f in analyze_typescript(p))


def test_TS056_passes_download_literal(tmp_path):
    p = _ts(tmp_path, 'res.download("/files/report.pdf");')
    assert not any(f.rule_id == "TS-056" for f in analyze_typescript(p))


# ── TS-057: exec(req.query.cmd) — direct command injection ───────────────────


def test_TS057_detects_exec_req_query(tmp_path):
    p = _ts(tmp_path, "exec(req.query.cmd);")
    assert any(f.rule_id == "TS-057" and f.severity == Severity.CRITICAL for f in analyze_typescript(p))


def test_TS057_detects_child_process_exec_req(tmp_path):
    p = _ts(tmp_path, "child_process.exec(req.body.command);")
    assert any(f.rule_id == "TS-057" for f in analyze_typescript(p))


def test_TS057_passes_exec_literal(tmp_path):
    p = _ts(tmp_path, 'exec("ls -la");')
    assert not any(f.rule_id == "TS-057" for f in analyze_typescript(p))


# ── TS-058: execFile(req.xxx) — user-controlled executable path ──────────────


def test_TS058_detects_execFile_req_query(tmp_path):
    p = _ts(tmp_path, "execFile(req.query.binary, ['--safe']);")
    assert any(f.rule_id == "TS-058" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS058_detects_child_process_execFile_req(tmp_path):
    p = _ts(tmp_path, "child_process.execFile(req.body.cmd);")
    assert any(f.rule_id == "TS-058" for f in analyze_typescript(p))


def test_TS058_passes_execFile_literal(tmp_path):
    p = _ts(tmp_path, 'execFile("/usr/bin/ls", ["-la"]);')
    assert not any(f.rule_id == "TS-058" for f in analyze_typescript(p))


# ── TS-059: net.createConnection(req.xxx) — raw TCP SSRF ─────────────────────


def test_TS059_detects_net_createConnection_req(tmp_path):
    p = _ts(tmp_path, "net.createConnection(req.query.port, req.query.host);")
    assert any(f.rule_id == "TS-059" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS059_detects_net_connect_req(tmp_path):
    p = _ts(tmp_path, "net.connect(80, req.params.host);")
    assert any(f.rule_id == "TS-059" for f in analyze_typescript(p))


def test_TS059_passes_net_createConnection_literal(tmp_path):
    p = _ts(tmp_path, 'net.createConnection(6379, "localhost");')
    assert not any(f.rule_id == "TS-059" for f in analyze_typescript(p))


# ── TS-060: res.jsonp(req.xxx) — JSONP callback injection ────────────────────


def test_TS060_detects_jsonp_req_query(tmp_path):
    p = _ts(tmp_path, "res.jsonp(req.query.data);")
    assert any(f.rule_id == "TS-060" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS060_detects_jsonp_req_body(tmp_path):
    p = _ts(tmp_path, "res.jsonp(req.body.payload);")
    assert any(f.rule_id == "TS-060" for f in analyze_typescript(p))


def test_TS060_passes_jsonp_literal(tmp_path):
    p = _ts(tmp_path, 'res.jsonp({ status: "ok" });')
    assert not any(f.rule_id == "TS-060" for f in analyze_typescript(p))


# ── TS-061: fs.readFileSync(req.xxx) — synchronous path traversal ────────────


def test_TS061_detects_readFileSync_req(tmp_path):
    p = _ts(tmp_path, 'fs.readFileSync(req.query.file, "utf8");')
    assert any(f.rule_id == "TS-061" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS061_detects_readFileSync_body(tmp_path):
    p = _ts(tmp_path, "fs.readFileSync(req.body.path);")
    assert any(f.rule_id == "TS-061" for f in analyze_typescript(p))


def test_TS061_passes_readFileSync_literal(tmp_path):
    p = _ts(tmp_path, 'fs.readFileSync("/etc/config.json");')
    assert not any(f.rule_id == "TS-061" for f in analyze_typescript(p))


# ── TS-062: spawnSync(req.xxx) — synchronous shell execution ─────────────────


def test_TS062_detects_spawnSync_req(tmp_path):
    p = _ts(tmp_path, "spawnSync(req.query.tool);")
    assert any(f.rule_id == "TS-062" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS062_detects_child_process_spawnSync(tmp_path):
    p = _ts(tmp_path, "child_process.spawnSync(req.body.binary);")
    assert any(f.rule_id == "TS-062" for f in analyze_typescript(p))


def test_TS062_passes_spawnSync_literal(tmp_path):
    p = _ts(tmp_path, 'spawnSync("ls", ["-la"]);')
    assert not any(f.rule_id == "TS-062" for f in analyze_typescript(p))


# ── TS-063: new vm.Script(req.xxx) — VM code injection ───────────────────────


def test_TS063_detects_vm_Script_req(tmp_path):
    p = _ts(tmp_path, "new vm.Script(req.query.code);")
    assert any(f.rule_id == "TS-063" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS063_detects_Script_req_body(tmp_path):
    p = _ts(tmp_path, "new Script(req.body.script);")
    assert any(f.rule_id == "TS-063" for f in analyze_typescript(p))


def test_TS063_passes_vm_Script_literal(tmp_path):
    p = _ts(tmp_path, 'new vm.Script("const x = 1;");')
    assert not any(f.rule_id == "TS-063" for f in analyze_typescript(p))


# ── TS-064: document.write(req.xxx) — DOM XSS ────────────────────────────────


def test_TS064_detects_document_write_req(tmp_path):
    p = _ts(tmp_path, "document.write(req.query.html);")
    assert any(f.rule_id == "TS-064" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS064_detects_document_writeln_req(tmp_path):
    p = _ts(tmp_path, "document.writeln(req.body.content);")
    assert any(f.rule_id == "TS-064" for f in analyze_typescript(p))


def test_TS064_passes_document_write_literal(tmp_path):
    p = _ts(tmp_path, 'document.write("<p>Hello</p>");')
    assert not any(f.rule_id == "TS-064" for f in analyze_typescript(p))


# ── TS-065: window.open(req.xxx) — open redirect ─────────────────────────────


def test_TS065_detects_window_open_req(tmp_path):
    p = _ts(tmp_path, "window.open(req.query.url);")
    assert any(f.rule_id == "TS-065" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS065_passes_window_open_literal(tmp_path):
    p = _ts(tmp_path, 'window.open("https://example.com");')
    assert not any(f.rule_id == "TS-065" for f in analyze_typescript(p))


# ── TS-066: $(el).html(req.xxx) — jQuery innerHTML injection ─────────────────


def test_TS066_detects_jquery_html_req(tmp_path):
    p = _ts(tmp_path, '$("#output").html(req.query.content);')
    assert any(f.rule_id == "TS-066" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS066_detects_jquery_html_body(tmp_path):
    p = _ts(tmp_path, "$(el).html(req.body.markup);")
    assert any(f.rule_id == "TS-066" for f in analyze_typescript(p))


def test_TS066_passes_jquery_html_literal(tmp_path):
    p = _ts(tmp_path, '$(el).html("<b>safe</b>");')
    assert not any(f.rule_id == "TS-066" for f in analyze_typescript(p))


# ── TS-067: Object.defineProperty(obj, req.xxx, ...) — property injection ────


def test_TS067_detects_defineProperty_req(tmp_path):
    p = _ts(tmp_path, 'Object.defineProperty(obj, req.query.prop, { value: "x" });')
    assert any(f.rule_id == "TS-067" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS067_detects_defineProperty_body(tmp_path):
    p = _ts(tmp_path, "Object.defineProperty(target, req.body.key, descriptor);")
    assert any(f.rule_id == "TS-067" for f in analyze_typescript(p))


def test_TS067_passes_defineProperty_literal(tmp_path):
    p = _ts(tmp_path, 'Object.defineProperty(obj, "value", { writable: false });')
    assert not any(f.rule_id == "TS-067" for f in analyze_typescript(p))


# ── TS-068: crypto.createCipheriv(req.xxx, ...) — algorithm confusion ─────────


def test_TS068_detects_createCipheriv_req(tmp_path):
    p = _ts(tmp_path, "crypto.createCipheriv(req.query.algo, key, iv);")
    assert any(f.rule_id == "TS-068" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS068_detects_createDecipheriv_req(tmp_path):
    p = _ts(tmp_path, "crypto.createDecipheriv(req.body.cipher, key, iv);")
    assert any(f.rule_id == "TS-068" for f in analyze_typescript(p))


def test_TS068_passes_createCipheriv_literal(tmp_path):
    p = _ts(tmp_path, 'crypto.createCipheriv("aes-256-gcm", key, iv);')
    assert not any(f.rule_id == "TS-068" for f in analyze_typescript(p))


# ── TS-069: fs.writeFileSync(req.xxx, ...) — write path traversal ────────────


def test_TS069_detects_writeFileSync_req(tmp_path):
    p = _ts(tmp_path, "fs.writeFileSync(req.query.path, data);")
    assert any(f.rule_id == "TS-069" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS069_detects_writeFileSync_body(tmp_path):
    p = _ts(tmp_path, "fs.writeFileSync(req.body.filename, content);")
    assert any(f.rule_id == "TS-069" for f in analyze_typescript(p))


def test_TS069_passes_writeFileSync_literal(tmp_path):
    p = _ts(tmp_path, 'fs.writeFileSync("/tmp/output.txt", data);')
    assert not any(f.rule_id == "TS-069" for f in analyze_typescript(p))


# ── TS-070: res.set(req.xxx, ...) — CRLF injection ───────────────────────────


def test_TS070_detects_res_set_req(tmp_path):
    p = _ts(tmp_path, "res.set(req.query.name, 'value');")
    assert any(f.rule_id == "TS-070" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS070_detects_res_header_req(tmp_path):
    p = _ts(tmp_path, "res.header(req.body.key, 'x');")
    assert any(f.rule_id == "TS-070" for f in analyze_typescript(p))


def test_TS070_passes_res_set_literal(tmp_path):
    p = _ts(tmp_path, 'res.set("Content-Type", "application/json");')
    assert not any(f.rule_id == "TS-070" for f in analyze_typescript(p))


# ── TS-071: new Worker(req.xxx) — arbitrary code load ────────────────────────


def test_TS071_detects_new_worker_req(tmp_path):
    p = _ts(tmp_path, "new Worker(req.query.script);")
    assert any(f.rule_id == "TS-071" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS071_detects_new_worker_params(tmp_path):
    p = _ts(tmp_path, "new Worker(req.params.url);")
    assert any(f.rule_id == "TS-071" for f in analyze_typescript(p))


def test_TS071_passes_new_worker_literal(tmp_path):
    p = _ts(tmp_path, 'new Worker("./worker.js");')
    assert not any(f.rule_id == "TS-071" for f in analyze_typescript(p))


# ── TS-072: xhr.open("METHOD", req.xxx) — SSRF via XHR ───────────────────────


def test_TS072_detects_xhr_open_req(tmp_path):
    p = _ts(tmp_path, 'xhr.open("GET", req.query.url);')
    assert any(f.rule_id == "TS-072" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS072_detects_xhr_open_post_req(tmp_path):
    p = _ts(tmp_path, 'xhr.open("POST", req.body.endpoint);')
    assert any(f.rule_id == "TS-072" for f in analyze_typescript(p))


def test_TS072_passes_xhr_open_literal(tmp_path):
    p = _ts(tmp_path, 'xhr.open("GET", "https://api.example.com/data");')
    assert not any(f.rule_id == "TS-072" for f in analyze_typescript(p))


# ── TS-073: res.render(req.xxx, ...) — user-controlled template name ─────────


def test_TS073_detects_render_req(tmp_path):
    p = _ts(tmp_path, "res.render(req.query.view, { data: 'x' });")
    assert any(f.rule_id == "TS-073" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS073_detects_render_body(tmp_path):
    p = _ts(tmp_path, "res.render(req.body.template);")
    assert any(f.rule_id == "TS-073" for f in analyze_typescript(p))


def test_TS073_passes_render_literal(tmp_path):
    p = _ts(tmp_path, 'res.render("index", { user: req.user });')
    assert not any(f.rule_id == "TS-073" for f in analyze_typescript(p))


# ── TS-074: fs.appendFile(req.xxx, ...) — write path traversal ───────────────


def test_TS074_detects_appendFile_req(tmp_path):
    p = _ts(tmp_path, "fs.appendFile(req.query.logFile, msg, () => {});")
    assert any(f.rule_id == "TS-074" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS074_detects_appendFileSync_req(tmp_path):
    p = _ts(tmp_path, "fs.appendFileSync(req.body.path, data);")
    assert any(f.rule_id == "TS-074" for f in analyze_typescript(p))


def test_TS074_passes_appendFile_literal(tmp_path):
    p = _ts(tmp_path, 'fs.appendFile("/var/log/app.log", entry, () => {});')
    assert not any(f.rule_id == "TS-074" for f in analyze_typescript(p))


# ── TS-075: crypto.pbkdf2(req.xxx, ...) — KDF DoS ────────────────────────────


def test_TS075_detects_pbkdf2_req(tmp_path):
    p = _ts(tmp_path, "crypto.pbkdf2(req.query.password, salt, 100000, 64, 'sha256', cb);")
    assert any(f.rule_id == "TS-075" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS075_passes_pbkdf2_literal(tmp_path):
    p = _ts(tmp_path, "crypto.pbkdf2(storedHash, salt, 100000, 64, 'sha256', cb);")
    assert not any(f.rule_id == "TS-075" for f in analyze_typescript(p))


# ── TS-076: .find(req.xxx) — NoSQL injection ─────────────────────────────────


def test_TS076_detects_find_req(tmp_path):
    p = _ts(tmp_path, "db.collection('users').find(req.query, {});")
    assert any(f.rule_id == "TS-076" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS076_detects_find_body(tmp_path):
    p = _ts(tmp_path, "Model.find(req.body);")
    assert any(f.rule_id == "TS-076" for f in analyze_typescript(p))


def test_TS076_passes_find_literal(tmp_path):
    p = _ts(tmp_path, 'Model.find({ role: "user" });')
    assert not any(f.rule_id == "TS-076" for f in analyze_typescript(p))


# ── TS-077: spawn(`...${req.xxx}`) — template literal command injection ───────


def test_TS077_detects_spawn_template_req(tmp_path):
    p = _ts(tmp_path, "spawn(`/usr/bin/${req.query.tool}`, ['--run']);")
    assert any(f.rule_id == "TS-077" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS077_detects_spawnSync_template_req(tmp_path):
    p = _ts(tmp_path, "spawnSync(`/bin/${req.params.cmd}`, []);")
    assert any(f.rule_id == "TS-077" for f in analyze_typescript(p))


def test_TS077_passes_spawn_literal(tmp_path):
    p = _ts(tmp_path, 'spawn("/usr/bin/ls", ["-la"]);')
    assert not any(f.rule_id == "TS-077" for f in analyze_typescript(p))


# ── TS-078: res.cookie(name, req.xxx) — user-controlled cookie value ──────────


def test_TS078_detects_cookie_value_req(tmp_path):
    p = _ts(tmp_path, 'res.cookie("theme", req.query.theme, { httpOnly: true });')
    assert any(f.rule_id == "TS-078" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS078_detects_cookie_body_value(tmp_path):
    p = _ts(tmp_path, 'res.cookie("lang", req.body.locale);')
    assert any(f.rule_id == "TS-078" for f in analyze_typescript(p))


def test_TS078_passes_cookie_literal_value(tmp_path):
    p = _ts(tmp_path, 'res.cookie("session", token, { httpOnly: true, secure: true });')
    assert not any(f.rule_id == "TS-078" for f in analyze_typescript(p))


# ── TS-079: fs.createReadStream(req.xxx) — read path traversal ───────────────


def test_TS079_detects_createReadStream_req(tmp_path):
    p = _ts(tmp_path, "fs.createReadStream(req.query.file).pipe(res);")
    assert any(f.rule_id == "TS-079" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS079_detects_createReadStream_body(tmp_path):
    p = _ts(tmp_path, "fs.createReadStream(req.body.path);")
    assert any(f.rule_id == "TS-079" for f in analyze_typescript(p))


def test_TS079_passes_createReadStream_literal(tmp_path):
    p = _ts(tmp_path, 'fs.createReadStream("/static/logo.png");')
    assert not any(f.rule_id == "TS-079" for f in analyze_typescript(p))


# ── TS-080: exec("..." + req.xxx) — string concat in exec ────────────────────


def test_TS080_detects_exec_concat_req(tmp_path):
    p = _ts(tmp_path, 'exec("cat " + req.query.filename);')
    assert any(f.rule_id == "TS-080" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS080_detects_child_process_exec_concat(tmp_path):
    p = _ts(tmp_path, 'child_process.exec("ls " + req.body.dir);')
    assert any(f.rule_id == "TS-080" for f in analyze_typescript(p))


def test_TS080_passes_exec_no_concat_req(tmp_path):
    p = _ts(tmp_path, 'exec("ls -la /tmp");')
    assert not any(f.rule_id == "TS-080" for f in analyze_typescript(p))


# ── TS-081: mongoose.connect(req.xxx) — user-controlled DB URI ───────────────


def test_TS081_detects_mongoose_connect_req(tmp_path):
    p = _ts(tmp_path, "mongoose.connect(req.query.dbUri);")
    assert any(f.rule_id == "TS-081" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS081_detects_MongoClient_req(tmp_path):
    p = _ts(tmp_path, "new MongoClient(req.body.uri);")
    assert any(f.rule_id == "TS-081" for f in analyze_typescript(p))


def test_TS081_passes_mongoose_literal(tmp_path):
    p = _ts(tmp_path, 'mongoose.connect("mongodb://localhost:27017/mydb");')
    assert not any(f.rule_id == "TS-081" for f in analyze_typescript(p))


# ── TS-082: fs.chmod(req.xxx, ...) — user-controlled path in chmod ───────────


def test_TS082_detects_chmod_path_req(tmp_path):
    p = _ts(tmp_path, "fs.chmod(req.query.file, 0o644, () => {});")
    assert any(f.rule_id == "TS-082" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS082_detects_chmodSync_path_req(tmp_path):
    p = _ts(tmp_path, "fs.chmodSync(req.body.path, 0o755);")
    assert any(f.rule_id == "TS-082" for f in analyze_typescript(p))


def test_TS082_passes_chmod_literal(tmp_path):
    p = _ts(tmp_path, 'fs.chmod("/tmp/out.txt", 0o600, () => {});')
    assert not any(f.rule_id == "TS-082" for f in analyze_typescript(p))


# ── TS-083: res.type(req.xxx) — user-controlled Content-Type ─────────────────


def test_TS083_detects_res_type_req(tmp_path):
    p = _ts(tmp_path, "res.type(req.query.format);")
    assert any(f.rule_id == "TS-083" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS083_detects_res_type_body(tmp_path):
    p = _ts(tmp_path, "res.type(req.body.mime);")
    assert any(f.rule_id == "TS-083" for f in analyze_typescript(p))


def test_TS083_passes_res_type_literal(tmp_path):
    p = _ts(tmp_path, 'res.type("application/json");')
    assert not any(f.rule_id == "TS-083" for f in analyze_typescript(p))


# ── TS-084: import(req.xxx) — dynamic import of user-controlled module ────────


def test_TS084_detects_dynamic_import_req(tmp_path):
    p = _ts(tmp_path, "const mod = await import(req.query.plugin);")
    assert any(f.rule_id == "TS-084" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS084_detects_import_params(tmp_path):
    p = _ts(tmp_path, "import(req.params.module).then(m => m.run());")
    assert any(f.rule_id == "TS-084" for f in analyze_typescript(p))


def test_TS084_passes_import_literal(tmp_path):
    p = _ts(tmp_path, 'import("./plugins/default");')
    assert not any(f.rule_id == "TS-084" for f in analyze_typescript(p))


# ── TS-085: req.session[req.xxx] — user-controlled session key ───────────────


def test_TS085_detects_session_key_req(tmp_path):
    p = _ts(tmp_path, "const val = req.session[req.query.key];")
    assert any(f.rule_id == "TS-085" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS085_detects_session_body_key(tmp_path):
    p = _ts(tmp_path, "req.session[req.body.prop] = 'x';")
    assert any(f.rule_id == "TS-085" for f in analyze_typescript(p))


def test_TS085_passes_session_literal_key(tmp_path):
    p = _ts(tmp_path, 'const user = req.session["userId"];')
    assert not any(f.rule_id == "TS-085" for f in analyze_typescript(p))


# ── TS-086: sequelize.query(req.xxx) — raw ORM SQL injection ─────────────────


def test_TS086_detects_sequelize_query_req(tmp_path):
    p = _ts(tmp_path, "sequelize.query(req.query.sql);")
    assert any(f.rule_id == "TS-086" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_TS086_detects_db_query_req(tmp_path):
    p = _ts(tmp_path, "db.query(req.body.statement);")
    assert any(f.rule_id == "TS-086" for f in analyze_typescript(p))


def test_TS086_passes_sequelize_literal(tmp_path):
    p = _ts(tmp_path, 'sequelize.query("SELECT * FROM users WHERE id = :id", { replacements: { id } });')
    assert not any(f.rule_id == "TS-086" for f in analyze_typescript(p))


# ── TS-087: res.locals[req.xxx] — user-controlled property key ───────────────


def test_TS087_detects_locals_key_req(tmp_path):
    p = _ts(tmp_path, "res.locals[req.query.key] = 'value';")
    assert any(f.rule_id == "TS-087" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_TS087_detects_locals_body_key(tmp_path):
    p = _ts(tmp_path, "res.locals[req.body.prop] = data;")
    assert any(f.rule_id == "TS-087" for f in analyze_typescript(p))


def test_TS087_passes_locals_literal_key(tmp_path):
    p = _ts(tmp_path, 'res.locals["userId"] = req.user.id;')
    assert not any(f.rule_id == "TS-087" for f in analyze_typescript(p))


# ── TS-088: fs.mkdir/mkdirSync(req.xxx) — arbitrary directory creation ────────


def test_ts_088_fires_on_mkdirSync_with_req(tmp_path: Path) -> None:
    code = "import * as fs from 'fs';\nfunction mkd(req:any){fs.mkdirSync(req.query.dir,{recursive:true});}\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-088" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_088_fires_on_mkdir_with_req_params(tmp_path: Path) -> None:
    p = _ts(tmp_path, "import * as fs from 'fs';\nfunction mkd(req:any){fs.mkdir(req.params.dir,()=>{});}\n")
    assert any(f.rule_id == "TS-088" for f in analyze_typescript(p))


def test_ts_088_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _ts(tmp_path, "import * as fs from 'fs';\nfunction mkd(){fs.mkdirSync('/tmp/safe');}\n")
    assert not any(f.rule_id == "TS-088" for f in analyze_typescript(p))


# ── TS-089: execFileSync(req.xxx) — synchronous command injection ─────────────


def test_ts_089_fires_on_execfilesync_with_req(tmp_path: Path) -> None:
    code = (
        "import {execFileSync} from 'child_process';\n"
        "function run(req:any){execFileSync(req.query.binary,['--safe']);}\n"
    )
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-089" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_089_no_fire_on_hardcoded_binary(tmp_path: Path) -> None:
    code = "import {execFileSync} from 'child_process';\nfunction run(){execFileSync('/usr/bin/tool',['--safe']);}\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-089" for f in analyze_typescript(p))


# ── TS-090: process.env[req.xxx] — user-controlled env variable read ──────────


def test_ts_090_fires_on_process_env_req_key(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function getEnv(req:any){return process.env[req.query.envKey];}\n")
    assert any(f.rule_id == "TS-090" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_090_fires_on_req_body_key(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function getEnv(req:any){return process.env[req.body.name];}\n")
    assert any(f.rule_id == "TS-090" for f in analyze_typescript(p))


def test_ts_090_no_fire_on_fixed_key(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function getEnv(){return process.env['NODE_ENV'];}\n")
    assert not any(f.rule_id == "TS-090" for f in analyze_typescript(p))


# ── TS-091: axios.get/post(req.xxx) — SSRF via axios ─────────────────────────


def test_ts_091_fires_on_axios_get_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "import axios from 'axios';\nasync function f(req:any){return axios.get(req.query.url);}\n")
    assert any(f.rule_id == "TS-091" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_091_fires_on_axios_post_with_req_params(tmp_path: Path) -> None:
    p = _ts(tmp_path, "import axios from 'axios';\nasync function f(req:any){return axios.post(req.params.url);}\n")
    assert any(f.rule_id == "TS-091" for f in analyze_typescript(p))


def test_ts_091_no_fire_on_hardcoded_url(tmp_path: Path) -> None:
    p = _ts(
        tmp_path, "import axios from 'axios';\nasync function f(){return axios.get('https://api.example.com/data');}\n"
    )
    assert not any(f.rule_id == "TS-091" for f in analyze_typescript(p))


# ── TS-092: res.send(req.xxx) — unsanitized value in response body ────────────


def test_ts_092_fires_on_res_send_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(res:any,req:any){res.send(req.query.message);}\n")
    assert any(f.rule_id == "TS-092" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_092_no_fire_on_safe_send(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(res:any){res.send('OK');}\n")
    assert not any(f.rule_id == "TS-092" for f in analyze_typescript(p))


# ── TS-093: JSON.parse(req.xxx) — prototype pollution / DoS via nested JSON ───


def test_ts_093_fires_on_json_parse_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return JSON.parse(req.body.data);}\n")
    assert any(f.rule_id == "TS-093" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_093_fires_on_json_parse_req_query(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return JSON.parse(req.query.payload);}\n")
    assert any(f.rule_id == "TS-093" for f in analyze_typescript(p))


def test_ts_093_no_fire_on_hardcoded_json(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return JSON.parse(\'{"key":"val"}\');}\n')
    assert not any(f.rule_id == "TS-093" for f in analyze_typescript(p))


# ── TS-094: fs.symlink(req.xxx) — user-controlled symlink target ──────────────


def test_ts_094_fires_on_fs_symlink_with_req(tmp_path: Path) -> None:
    code = "import * as fs from 'fs';\nfunction lnk(req:any){fs.symlink(req.query.target,'/app/lnk',()=>{});}\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-094" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_094_no_fire_on_hardcoded_target(tmp_path: Path) -> None:
    p = _ts(tmp_path, "import * as fs from 'fs';\nfunction lnk(){fs.symlink('/safe/target','/app/lnk',()=>{});}\n")
    assert not any(f.rule_id == "TS-094" for f in analyze_typescript(p))


# ── TS-095: mongoose.model(req.xxx) — arbitrary collection access ─────────────


def test_ts_095_fires_on_mongoose_model_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return mongoose.model(req.query.collection);}\n")
    assert any(f.rule_id == "TS-095" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_095_no_fire_on_hardcoded_model(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(){return mongoose.model('User');}\n")
    assert not any(f.rule_id == "TS-095" for f in analyze_typescript(p))


# ── TS-096: Buffer.allocUnsafe(req.xxx) — user-controlled buffer size (DoS) ───


def test_ts_096_fires_on_buffer_alloc_unsafe_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return Buffer.allocUnsafe(req.query.size);}\n")
    assert any(f.rule_id == "TS-096" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_096_no_fire_on_hardcoded_size(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(){return Buffer.allocUnsafe(1024);}\n")
    assert not any(f.rule_id == "TS-096" for f in analyze_typescript(p))


# ── TS-097: Handlebars.compile(req.xxx) — SSTI ───────────────────────────────


def test_ts_097_fires_on_handlebars_compile_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return Handlebars.compile(req.query.tmpl);}\n")
    assert any(f.rule_id == "TS-097" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_097_no_fire_on_literal_template(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return Handlebars.compile("Hello {{name}}");}\n')
    assert not any(f.rule_id == "TS-097" for f in analyze_typescript(p))


# ── TS-098: fs.unlink(req.xxx) — user-controlled file deletion ───────────────


def test_ts_098_fires_on_fs_unlink_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){fs.unlink(req.query.file, ()=>{});}\n")
    assert any(f.rule_id == "TS-098" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_098_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){fs.unlink("/tmp/safe.txt", ()=>{});}\n')
    assert not any(f.rule_id == "TS-098" for f in analyze_typescript(p))


# ── TS-099: http.get(req.xxx) — SSRF via Node.js http module ─────────────────


def test_ts_099_fires_on_http_get_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){http.get(req.query.url, ()=>{});}\n")
    assert any(f.rule_id == "TS-099" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_099_no_fire_on_hardcoded_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){http.get("https://api.example.com/data", ()=>{});}\n')
    assert not any(f.rule_id == "TS-099" for f in analyze_typescript(p))


# ── TS-100: res.attachment(req.xxx) — user-controlled Content-Disposition ─────


def test_ts_100_fires_on_res_attachment_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(res:any,req:any){res.attachment(req.query.filename);}\n")
    assert any(f.rule_id == "TS-100" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_100_no_fire_on_literal_filename(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(res:any){res.attachment("report.pdf");}\n')
    assert not any(f.rule_id == "TS-100" for f in analyze_typescript(p))


# ── TS-101: socket.emit(req.xxx) — user-controlled Socket.IO event name ───────


def test_ts_101_fires_on_socket_emit_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(socket:any,req:any){socket.emit(req.query.event, {});}\n")
    assert any(f.rule_id == "TS-101" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_101_no_fire_on_literal_event(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(socket:any){socket.emit("update", {});}\n')
    assert not any(f.rule_id == "TS-101" for f in analyze_typescript(p))


# ── TS-102: $.ajax({url: req.xxx}) — jQuery SSRF ─────────────────────────────


def test_ts_102_fires_on_jquery_ajax_url_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){$.ajax({url: req.query.endpoint, method: 'GET'});}\n")
    assert any(f.rule_id == "TS-102" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_102_no_fire_on_literal_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){$.ajax({url: "https://api.example.com/data"});}\n')
    assert not any(f.rule_id == "TS-102" for f in analyze_typescript(p))


# ── TS-103: createClient({url: req.xxx}) — SSRF via Redis URL ────────────────


def test_ts_103_fires_on_redis_create_client_url_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){createClient({url: req.query.redisUrl});}\n")
    assert any(f.rule_id == "TS-103" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_103_no_fire_on_hardcoded_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){createClient({url: "redis://localhost:6379"});}\n')
    assert not any(f.rule_id == "TS-103" for f in analyze_typescript(p))


# ── TS-104: amqplib.connect(req.xxx) — SSRF via RabbitMQ URL ─────────────────


def test_ts_104_fires_on_amqplib_connect_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "async function f(req:any){await amqplib.connect(req.query.brokerUrl);}\n")
    assert any(f.rule_id == "TS-104" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_104_no_fire_on_hardcoded_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'async function f(){await amqplib.connect("amqp://localhost");}\n')
    assert not any(f.rule_id == "TS-104" for f in analyze_typescript(p))


# ── TS-105: pg.connect(req.xxx) — SSRF via PostgreSQL connection string ───────


def test_ts_105_fires_on_pg_connect_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "async function f(req:any){await pg.connect(req.query.connStr);}\n")
    assert any(f.rule_id == "TS-105" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_105_no_fire_on_hardcoded_conn_string(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'async function f(){await pg.connect("postgresql://user:pass@localhost/db");}\n')
    assert not any(f.rule_id == "TS-105" for f in analyze_typescript(p))


# ── TS-106: new WebSocket(req.xxx) — SSRF via WebSocket URL ──────────────────


def test_ts_106_fires_on_websocket_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return new WebSocket(req.query.wsUrl);}\n")
    assert any(f.rule_id == "TS-106" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_106_no_fire_on_literal_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return new WebSocket("wss://ws.example.com");}\n')
    assert not any(f.rule_id == "TS-106" for f in analyze_typescript(p))


# ── TS-107: new EventSource(req.xxx) — SSRF via SSE URL ──────────────────────


def test_ts_107_fires_on_event_source_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return new EventSource(req.query.sseUrl);}\n")
    assert any(f.rule_id == "TS-107" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_107_no_fire_on_literal_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return new EventSource("/events");}\n')
    assert not any(f.rule_id == "TS-107" for f in analyze_typescript(p))


# ── TS-108: new Client({node: req.xxx}) — SSRF via Elasticsearch node URL ─────


def test_ts_108_fires_on_es_client_node_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return new Client({node: req.query.esNode});}\n")
    assert any(f.rule_id == "TS-108" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_108_no_fire_on_hardcoded_node(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return new Client({node: "http://localhost:9200"});}\n')
    assert not any(f.rule_id == "TS-108" for f in analyze_typescript(p))


# ── TS-109: res.cookie(req.xxx, ...) — user-controlled cookie name ───────────


def test_ts_109_fires_on_cookie_name_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(res:any,req:any){res.cookie(req.query.name, 'v', {});}\n")
    assert any(f.rule_id == "TS-109" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_109_no_fire_on_literal_cookie_name(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(res:any,req:any){res.cookie('session', req.query.v);}\n")
    assert not any(f.rule_id == "TS-109" for f in analyze_typescript(p))


# ── TS-110: crypto.scrypt(req.xxx, ...) — DoS via user-controlled password ───


def test_ts_110_fires_on_crypto_scrypt_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any,salt:Buffer){crypto.scrypt(req.query.pw, salt, 64, ()=>{});}\n")
    assert any(f.rule_id == "TS-110" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_110_no_fire_on_hardcoded_password(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(salt:Buffer){crypto.scrypt("static", salt, 64, ()=>{});}\n')
    assert not any(f.rule_id == "TS-110" for f in analyze_typescript(p))


# ── TS-111: new URL(req.xxx) — SSRF / open redirect via URL constructor ───────


def test_ts_111_fires_on_new_url_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return new URL(req.query.target);}\n")
    assert any(f.rule_id == "TS-111" and f.severity == Severity.MEDIUM for f in analyze_typescript(p))


def test_ts_111_no_fire_on_literal_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return new URL("https://example.com");}\n')
    assert not any(f.rule_id == "TS-111" for f in analyze_typescript(p))


# ── TS-112: mysql.createConnection({host: req.xxx}) — MySQL SSRF ─────────────


def test_ts_112_fires_on_mysql_create_connection_with_req_host(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){mysql.createConnection({host:req.query.dbHost});}\n")
    assert any(f.rule_id == "TS-112" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_112_no_fire_on_hardcoded_mysql_host(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){mysql.createConnection({host:"db.internal"});}\n')
    assert not any(f.rule_id == "TS-112" for f in analyze_typescript(p))


# ── TS-113: new Redis(req.xxx) — SSRF via ioredis connection string ───────────


def test_ts_113_fires_on_new_redis_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){return new Redis(req.query.redisUrl);}\n")
    assert any(f.rule_id == "TS-113" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_113_no_fire_on_hardcoded_redis(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){return new Redis("redis://localhost:6379");}\n')
    assert not any(f.rule_id == "TS-113" for f in analyze_typescript(p))


# ── TS-114: createConnection({host: req.xxx}) — TypeORM SSRF ─────────────────


def test_ts_114_fires_on_typeorm_create_connection_with_req_host(tmp_path: Path) -> None:
    p = _ts(tmp_path, "async function f(req:any){createConnection({host:req.query.dbHost,type:'postgres'});}\n")
    assert any(f.rule_id == "TS-114" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_114_no_fire_on_hardcoded_typeorm_host(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'async function f(){createConnection({host:"db.internal",type:"postgres"});}\n')
    assert not any(f.rule_id == "TS-114" for f in analyze_typescript(p))


# ── TS-115: undici.request(req.xxx) — SSRF via undici ────────────────────────


def test_ts_115_fires_on_undici_request_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "async function f(req:any){undici.request(req.query.targetUrl);}\n")
    assert any(f.rule_id == "TS-115" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_115_no_fire_on_hardcoded_undici_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'async function f(){undici.request("https://api.example.com");}\n')
    assert not any(f.rule_id == "TS-115" for f in analyze_typescript(p))


# ── TS-116: superagent.get(req.xxx) — SSRF via superagent ────────────────────


def test_ts_116_fires_on_superagent_get_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){superagent.get(req.query.apiUrl);}\n")
    assert any(f.rule_id == "TS-116" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_116_no_fire_on_hardcoded_superagent_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){superagent.get("https://api.example.com");}\n')
    assert not any(f.rule_id == "TS-116" for f in analyze_typescript(p))


# ── TS-117: ky.get(req.xxx) / ky(req.xxx) — SSRF via ky HTTP client ──────────


def test_ts_117_fires_on_ky_get_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "async function f(req:any){ky.get(req.query.serviceUrl).json();}\n")
    assert any(f.rule_id == "TS-117" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_117_no_fire_on_hardcoded_ky_url(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'async function f(){ky.get("https://api.example.com").json();}\n')
    assert not any(f.rule_id == "TS-117" for f in analyze_typescript(p))


# ── TS-118: element.setAttribute("src", req.xxx) — DOM attribute injection ───


def test_ts_118_fires_on_set_attribute_src_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(el:HTMLElement,req:any){el.setAttribute('src',req.query.imgUrl);}\n")
    assert any(f.rule_id == "TS-118" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_118_no_fire_on_hardcoded_setAttribute(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(el:HTMLElement){el.setAttribute("src","https://cdn.example.com/img.png");}\n')
    assert not any(f.rule_id == "TS-118" for f in analyze_typescript(p))


# ── TS-119: location.assign(req.xxx) — open redirect via location ─────────────


def test_ts_119_fires_on_location_assign_with_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){location.assign(req.query.returnUrl);}\n")
    assert any(f.rule_id == "TS-119" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_119_no_fire_on_hardcoded_location(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){location.assign("https://example.com/dashboard");}\n')
    assert not any(f.rule_id == "TS-119" for f in analyze_typescript(p))


# ── TS-120: new S3Client({endpoint: req.xxx}) — AWS SDK SSRF ─────────────────


def test_ts_120_fires_on_s3client_endpoint_req(tmp_path: Path) -> None:
    p = _ts(tmp_path, "function f(req:any){new S3Client({endpoint:req.query.s3Endpoint});}\n")
    assert any(f.rule_id == "TS-120" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_120_no_fire_on_hardcoded_s3_endpoint(tmp_path: Path) -> None:
    p = _ts(tmp_path, 'function f(){new S3Client({endpoint:"https://s3.amazonaws.com"});}\n')
    assert not any(f.rule_id == "TS-120" for f in analyze_typescript(p))


# ── Full fixture — all 111 rules ──────────────────────────────────────────────


def test_vulnerable_ts_fixture_has_all_one_hundred_eleven_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 112)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


def test_vulnerable_ts_fixture_has_all_one_hundred_fourteen_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 115)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


def test_vulnerable_ts_fixture_has_all_one_hundred_seventeen_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 118)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


def test_vulnerable_ts_fixture_has_all_one_hundred_twenty_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 121)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── TS-121: new Kafka({ brokers: req.xxx }) — KafkaJS broker SSRF ────────────


def test_ts_121_fires_on_kafka_brokers_req(tmp_path: Path) -> None:
    code = "const k = new Kafka({ brokers: req.query.brokers });\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-121" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_121_no_fire_on_hardcoded_kafka_brokers(tmp_path: Path) -> None:
    code = "const k = new Kafka({ brokers: ['broker:9092'] });\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-121" for f in analyze_typescript(p))


# ── TS-122: tls.connect({ host: req.xxx }) — TLS host SSRF ───────────────────


def test_ts_122_fires_on_tls_connect_host_req(tmp_path: Path) -> None:
    code = "tls.connect({ host: req.query.host, port: 443 });\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-122" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_122_no_fire_on_hardcoded_tls_host(tmp_path: Path) -> None:
    code = "tls.connect({ host: 'example.com', port: 443 });\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-122" for f in analyze_typescript(p))


# ── TS-123: nats.connect(req.xxx) — NATS server SSRF ─────────────────────────


def test_ts_123_fires_on_nats_connect_req(tmp_path: Path) -> None:
    code = "await nats.connect(req.query.natsServer);\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-123" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_123_no_fire_on_hardcoded_nats_server(tmp_path: Path) -> None:
    code = "await nats.connect('nats://localhost:4222');\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-123" for f in analyze_typescript(p))


def test_vulnerable_ts_fixture_has_all_one_hundred_twenty_three_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 124)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── TS-124: new InfluxDB({ url: req.xxx }) — InfluxDB URL SSRF ───────────────


def test_ts_124_fires_on_influxdb_url_req(tmp_path: Path) -> None:
    code = "const c = new InfluxDB({ url: req.query.influxUrl });\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-124" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_124_no_fire_on_hardcoded_influxdb_url(tmp_path: Path) -> None:
    code = "const c = new InfluxDB({ url: 'http://localhost:8086' });\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-124" for f in analyze_typescript(p))


# ── TS-125: neo4j.driver(req.xxx) — Neo4j URI SSRF ───────────────────────────


def test_ts_125_fires_on_neo4j_driver_req(tmp_path: Path) -> None:
    code = "const d = neo4j.driver(req.query.neo4jUri);\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-125" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_125_no_fire_on_hardcoded_neo4j_uri(tmp_path: Path) -> None:
    code = "const d = neo4j.driver('bolt://localhost:7687');\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-125" for f in analyze_typescript(p))


# ── TS-126: new ClickHouse({ host: req.xxx }) — ClickHouse host SSRF ─────────


def test_ts_126_fires_on_clickhouse_host_req(tmp_path: Path) -> None:
    code = "const ch = new ClickHouse({ host: req.query.chHost });\n"
    p = _ts(tmp_path, code)
    assert any(f.rule_id == "TS-126" and f.severity == Severity.HIGH for f in analyze_typescript(p))


def test_ts_126_no_fire_on_hardcoded_clickhouse_host(tmp_path: Path) -> None:
    code = "const ch = new ClickHouse({ host: 'localhost' });\n"
    p = _ts(tmp_path, code)
    assert not any(f.rule_id == "TS-126" for f in analyze_typescript(p))


def test_vulnerable_ts_fixture_has_all_one_hundred_twenty_six_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"TS-{i:03d}" for i in range(1, 127)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"
