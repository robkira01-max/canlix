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


def test_vulnerable_fixture_has_first_twelve_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 13)}
    assert expected.issubset(rule_ids)


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


# ── SRC-008: path traversal — file I/O with function parameter path ─────────


def test_SRC008_detects_open_with_param(tmp_path):
    p = _py(tmp_path, "def read(filepath):\n    return open(filepath).read()")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-008" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC008_detects_path_constructor_with_param(tmp_path):
    # Path(p) is in _PATH_IO_FUNCS — fires on the constructor call, not the chained method
    p = _py(
        tmp_path,
        "from pathlib import Path\ndef get(p):\n    return Path(p).read_text()",
    )
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-008" for f in findings)


def test_SRC008_detects_os_remove_with_param(tmp_path):
    p = _py(tmp_path, "import os\ndef delete(path):\n    os.remove(path)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-008" for f in findings)


def test_SRC008_passes_literal_path(tmp_path):
    p = _py(tmp_path, 'open("/etc/hostname").read()')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-008" for f in findings)


def test_SRC008_passes_module_level_path_var(tmp_path):
    p = _py(tmp_path, 'PATH = "/tmp/data.txt"\nopen(PATH).read()')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-008" for f in findings)


# ── SRC-009: SQL injection — parameterised query check ──────────────────────


def test_SRC009_detects_fstring_in_execute(tmp_path):
    p = _py(tmp_path, 'def get(uid):\n    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-009" and f.severity == Severity.HIGH for f in findings)


def test_SRC009_detects_percent_format_in_execute(tmp_path):
    p = _py(tmp_path, 'def get(uid):\n    cursor.execute("SELECT * FROM users WHERE id = %s" % uid)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-009" for f in findings)


def test_SRC009_detects_plus_concat_in_query(tmp_path):
    p = _py(tmp_path, 'def search(term):\n    db.execute("SELECT * FROM items WHERE name = " + term)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-009" for f in findings)


def test_SRC009_detects_session_execute(tmp_path):
    p = _py(tmp_path, 'def get(uid):\n    session.execute(f"SELECT * FROM t WHERE id={uid}")')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-009" for f in findings)


def test_SRC009_passes_parameterised_query(tmp_path):
    p = _py(tmp_path, 'def get(uid):\n    cursor.execute("SELECT * FROM users WHERE id = %s", [uid])')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-009" for f in findings)


def test_SRC009_passes_literal_sql(tmp_path):
    p = _py(tmp_path, 'cursor.execute("SELECT * FROM users")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-009" for f in findings)


# ── SRC-010: insecure PRNG — random.* in security-sensitive context ──────────


def test_SRC010_detects_randint_assigned_to_token(tmp_path):
    p = _py(tmp_path, "import random\ntoken = random.randint(0, 999999)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-010" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC010_detects_random_assigned_to_secret(tmp_path):
    p = _py(tmp_path, "import random\nsecret = random.random()")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_detects_choice_assigned_to_password(tmp_path):
    p = _py(tmp_path, "import random\nchars = 'abc'\npassword = random.choice(chars)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_detects_randint_assigned_to_otp(tmp_path):
    p = _py(tmp_path, "import random\notp = random.randint(100000, 999999)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_detects_randrange_assigned_to_session_id(tmp_path):
    p = _py(tmp_path, "import random\nsession_id = random.randrange(0, 2**32)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_detects_return_in_security_named_function(tmp_path):
    p = _py(
        tmp_path,
        "import random\ndef generate_token():\n    return random.randint(0, 999999)",
    )
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_passes_random_for_non_security_use(tmp_path):
    p = _py(tmp_path, "import random\nindex = random.randint(0, 10)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_passes_random_choice_for_color(tmp_path):
    p = _py(tmp_path, "import random\ncolors = ['red', 'blue']\ncolor = random.choice(colors)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_passes_secrets_token_hex(tmp_path):
    p = _py(tmp_path, "import secrets\ntoken = secrets.token_hex(32)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-010" for f in findings)


def test_SRC010_fixture_fires_on_vulnerable_server(tmp_path):
    from mcpprobe.analyzers.python_ast import analyze_python as _ap

    findings = _ap(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-010" for f in findings)


# ── SRC-011: TLS verification disabled ──────────────────────────────────────


def test_SRC011_detects_verify_false_in_requests_get(tmp_path):
    p = _py(tmp_path, 'import requests\nrequests.get("https://example.com", verify=False)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-011" and f.severity == Severity.HIGH for f in findings)


def test_SRC011_detects_verify_false_in_requests_post(tmp_path):
    p = _py(tmp_path, 'import requests\nrequests.post("https://api.example.com", json={}, verify=False)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-011" for f in findings)


def test_SRC011_detects_verify_false_in_httpx(tmp_path):
    p = _py(tmp_path, 'import httpx\nhttpx.get("https://example.com", verify=False)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-011" for f in findings)


def test_SRC011_detects_ssl_create_unverified_context(tmp_path):
    p = _py(tmp_path, "import ssl\nctx = ssl._create_unverified_context()")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-011" for f in findings)


def test_SRC011_passes_verify_true(tmp_path):
    p = _py(tmp_path, 'import requests\nrequests.get("https://example.com", verify=True)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-011" for f in findings)


def test_SRC011_passes_no_verify_kwarg(tmp_path):
    p = _py(tmp_path, 'import requests\nrequests.get("https://example.com")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-011" for f in findings)


def test_SRC011_passes_ssl_create_default_context(tmp_path):
    p = _py(tmp_path, "import ssl\nctx = ssl.create_default_context()")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-011" for f in findings)


def test_SRC011_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-011" for f in findings)


# ── SRC-012: weak hash algorithm ─────────────────────────────────────────────


def test_SRC012_detects_hashlib_md5(tmp_path):
    p = _py(tmp_path, "import hashlib\nhashlib.md5(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-012" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC012_detects_hashlib_sha1(tmp_path):
    p = _py(tmp_path, "import hashlib\nhashlib.sha1(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-012" for f in findings)


def test_SRC012_detects_hashlib_new_md5(tmp_path):
    p = _py(tmp_path, 'import hashlib\nhashlib.new("md5", data)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-012" for f in findings)


def test_SRC012_detects_hashlib_new_sha1_variant(tmp_path):
    p = _py(tmp_path, 'import hashlib\nhashlib.new("sha-1", data)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-012" for f in findings)


def test_SRC012_passes_hashlib_sha256(tmp_path):
    p = _py(tmp_path, "import hashlib\nhashlib.sha256(data)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-012" for f in findings)


def test_SRC012_passes_hashlib_new_sha256(tmp_path):
    p = _py(tmp_path, 'import hashlib\nhashlib.new("sha256", data)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-012" for f in findings)


def test_SRC012_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-012" for f in findings)


# ── SRC-013: non-constant-time comparison ────────────────────────────────────


def test_SRC013_detects_eq_on_token(tmp_path):
    p = _py(tmp_path, "def check(stored_token, user_token):\n    return stored_token == user_token")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-013" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC013_detects_neq_on_password(tmp_path):
    p = _py(tmp_path, "def ok(password, expected):\n    return password != expected")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-013" for f in findings)


def test_SRC013_detects_eq_on_secret(tmp_path):
    p = _py(tmp_path, "if api_secret == received_secret:\n    pass")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-013" for f in findings)


def test_SRC013_passes_comparison_against_string_literal(tmp_path):
    # Comparing a token to "" is a defensive check, not a timing attack
    p = _py(tmp_path, 'if token == "":\n    raise ValueError("empty")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-013" for f in findings)


def test_SRC013_passes_comparison_against_none(tmp_path):
    p = _py(tmp_path, "if token == None:\n    raise ValueError")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-013" for f in findings)


def test_SRC013_passes_non_security_name_eq(tmp_path):
    p = _py(tmp_path, "if status == result:\n    pass")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-013" for f in findings)


def test_SRC013_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-013" for f in findings)


# ── Full fixture — all 13 rules ───────────────────────────────────────────────


# ── SRC-014: debug mode enabled ──────────────────────────────────────────────


def test_SRC014_detects_DEBUG_true(tmp_path):
    p = _py(tmp_path, "DEBUG = True")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-014" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC014_detects_FLASK_DEBUG_true(tmp_path):
    p = _py(tmp_path, "FLASK_DEBUG = True")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-014" for f in findings)


def test_SRC014_detects_DEBUG_MODE_true(tmp_path):
    p = _py(tmp_path, "DEBUG_MODE = True")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-014" for f in findings)


def test_SRC014_passes_DEBUG_false(tmp_path):
    p = _py(tmp_path, "DEBUG = False")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-014" for f in findings)


def test_SRC014_passes_DEBUG_from_env(tmp_path):
    p = _py(tmp_path, "import os\nDEBUG = os.environ.get('DEBUG', 'false') == 'true'")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-014" for f in findings)


def test_SRC014_passes_other_true_assignment(tmp_path):
    p = _py(tmp_path, "VERBOSE = True")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-014" for f in findings)


def test_SRC014_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-014" for f in findings)


# ── Full fixture — all 14 rules ───────────────────────────────────────────────


def test_vulnerable_fixture_has_all_fourteen_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 15)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"
