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


def test_vulnerable_ts_fixture_has_all_six_rules():
    findings = analyze_typescript(FIXTURES / "vulnerable_server.ts")
    rule_ids = {f.rule_id for f in findings}
    assert {"TS-001", "TS-002", "TS-003", "TS-004", "TS-005", "TS-006"}.issubset(rule_ids)


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
