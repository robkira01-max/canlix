"""Tests for the Python AST source analyzer — one test per rule."""

from __future__ import annotations

import textwrap
from pathlib import Path

from mcpprobe.analyzers import analyze_path
from mcpprobe.analyzers.python_ast import analyze_python
from mcpprobe.models import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "source"


# ── Helpers ────────────────────────────────────────────────────────────────


def _py(tmp_path: Path, code: str) -> Path:
    """Write Python source to a temp file and return its path."""
    p = tmp_path / "test_server.py"
    p.write_text(textwrap.dedent(code))
    return p


# ── SRC-001: hardcoded secret ───────────────────────────────────────────────


def test_SRC001_detects_github_token_prefix(tmp_path):
    p = _py(tmp_path, 'TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab"')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-001" and f.severity == Severity.CRITICAL for f in findings)


def test_SRC001_detects_openai_key_prefix(tmp_path):
    p = _py(tmp_path, 'KEY = "sk-1234567890abcdef1234567890abcdef1234"')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-001" and f.severity == Severity.CRITICAL for f in findings)


def test_SRC001_detects_aws_access_key(tmp_path):
    p = _py(tmp_path, 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-001" and f.severity == Severity.CRITICAL for f in findings)


def test_SRC001_detects_secret_variable_name(tmp_path):
    p = _py(tmp_path, 'DATABASE_PASSWORD = "super_secret_passphrase_123456789"')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-001" for f in findings)


def test_SRC001_passes_env_lookup(tmp_path):
    p = _py(tmp_path, 'import os\nAPI_KEY = os.environ.get("API_KEY", "")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-001" for f in findings)


def test_SRC001_passes_short_values(tmp_path):
    p = _py(tmp_path, 'TOKEN = "abc"')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-001" for f in findings)


# ── SRC-002: eval / exec ────────────────────────────────────────────────────


def test_SRC002_detects_eval(tmp_path):
    p = _py(tmp_path, "def run(x):\n    return eval(x)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-002" and f.severity == Severity.HIGH for f in findings)


def test_SRC002_detects_exec(tmp_path):
    p = _py(tmp_path, "exec(user_code)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-002" for f in findings)


def test_SRC002_passes_no_eval(tmp_path):
    p = _py(tmp_path, "import ast\nresult = ast.literal_eval(data)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-002" for f in findings)


# ── SRC-003: subprocess shell=True ─────────────────────────────────────────


def test_SRC003_detects_subprocess_shell_true(tmp_path):
    p = _py(tmp_path, "import subprocess\nsubprocess.run(cmd, shell=True)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-003" and f.severity == Severity.HIGH for f in findings)


def test_SRC003_passes_shell_false(tmp_path):
    p = _py(tmp_path, 'import subprocess\nsubprocess.run(["ls", "-la"], shell=False)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-003" for f in findings)


def test_SRC003_passes_no_shell_kwarg(tmp_path):
    p = _py(tmp_path, 'import subprocess\nsubprocess.run(["ls"])')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-003" for f in findings)


# ── SRC-004: os.system / os.popen ──────────────────────────────────────────


def test_SRC004_detects_os_system(tmp_path):
    p = _py(tmp_path, 'import os\nos.system("rm -rf /tmp/test")')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-004" and f.severity == Severity.HIGH for f in findings)


def test_SRC004_detects_os_popen(tmp_path):
    p = _py(tmp_path, 'import os\nos.popen("cat /etc/passwd")')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-004" for f in findings)


# ── SRC-005: pickle deserialization ────────────────────────────────────────


def test_SRC005_detects_pickle_loads(tmp_path):
    p = _py(tmp_path, "import pickle\nobj = pickle.loads(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-005" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC005_detects_pickle_load(tmp_path):
    p = _py(tmp_path, 'import pickle\nwith open("x", "rb") as f:\n    obj = pickle.load(f)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-005" for f in findings)


# ── SRC-006: yaml.load without Loader ──────────────────────────────────────


def test_SRC006_detects_yaml_load_no_loader(tmp_path):
    p = _py(tmp_path, "import yaml\ndata = yaml.load(config_str)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-006" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC006_passes_yaml_safe_load(tmp_path):
    p = _py(tmp_path, "import yaml\ndata = yaml.safe_load(config_str)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-006" for f in findings)


def test_SRC006_passes_yaml_load_with_loader(tmp_path):
    p = _py(tmp_path, "import yaml\ndata = yaml.load(config_str, Loader=yaml.SafeLoader)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-006" for f in findings)


# ── Integration : fixture files ─────────────────────────────────────────────


def test_clean_fixture_has_no_findings():
    findings = analyze_python(FIXTURES / "clean_server.py")
    assert len(findings) == 0


def test_vulnerable_fixture_has_all_seven_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    assert {"SRC-001", "SRC-002", "SRC-003", "SRC-004", "SRC-005", "SRC-006", "SRC-007"}.issubset(rule_ids)


def test_analyze_path_on_directory(tmp_path):
    _py(tmp_path, "eval(user_input)")
    findings = analyze_path(tmp_path)
    assert any(f.rule_id == "SRC-002" for f in findings)


def test_analyze_path_skips_non_python(tmp_path):
    (tmp_path / "config.json").write_text('{"key": "value"}')
    findings = analyze_path(tmp_path)
    assert len(findings) == 0


def test_analyze_path_skips_venv(tmp_path):
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "bad.py").write_text("eval(x)")
    findings = analyze_path(tmp_path)
    assert len(findings) == 0


def test_line_numbers_are_accurate(tmp_path):
    p = _py(
        tmp_path,
        """
        import os
        # line 2
        # line 3
        os.system("bad")
        """,
    )
    findings = analyze_python(p)
    src004 = [f for f in findings if f.rule_id == "SRC-004"]
    assert src004
    assert src004[0].line_number > 0
    assert "os.system" in src004[0].code_snippet


def test_syntax_error_returns_empty(tmp_path):
    p = tmp_path / "broken.py"
    p.write_text("def (broken syntax :")
    findings = analyze_python(p)
    assert findings == []


# ── SRC-007: SSRF — HTTP client with function parameter URL ────────────────


def test_SRC007_detects_requests_get_with_param(tmp_path):
    p = _py(tmp_path, "import requests\ndef fetch(url):\n    return requests.get(url)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-007" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC007_detects_httpx_post_with_param(tmp_path):
    p = _py(tmp_path, "import httpx\ndef post(endpoint):\n    return httpx.post(endpoint)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-007" for f in findings)


def test_SRC007_detects_kwarg_url(tmp_path):
    p = _py(
        tmp_path,
        "import requests\ndef call(endpoint):\n    return requests.request(method='GET', url=endpoint)",
    )
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-007" for f in findings)


def test_SRC007_detects_async_def(tmp_path):
    p = _py(tmp_path, "import httpx\nasync def fetch(url):\n    return httpx.get(url)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-007" for f in findings)


def test_SRC007_passes_literal_url(tmp_path):
    p = _py(tmp_path, 'import requests\nrequests.get("https://example.com/api")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-007" for f in findings)


def test_SRC007_passes_module_level_constant(tmp_path):
    # Variable is not a function parameter — no SSRF risk tracked
    p = _py(tmp_path, 'import requests\nURL = "https://example.com"\nrequests.get(URL)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-007" for f in findings)
