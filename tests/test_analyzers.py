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


# ── SRC-015: open redirect ────────────────────────────────────────────────────


def test_SRC015_detects_redirect_with_param(tmp_path):
    p = _py(tmp_path, "def go(url):\n    return redirect(url)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-015" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC015_detects_flask_redirect(tmp_path):
    p = _py(tmp_path, "def go(url):\n    return flask.redirect(url)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-015" for f in findings)


def test_SRC015_detects_werkzeug_redirect(tmp_path):
    p = _py(tmp_path, "def go(url):\n    return werkzeug.utils.redirect(url)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-015" for f in findings)


def test_SRC015_passes_redirect_with_literal(tmp_path):
    p = _py(tmp_path, 'def go():\n    return redirect("/home")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-015" for f in findings)


def test_SRC015_passes_redirect_outside_function(tmp_path):
    # No param scope — module-level variable is not a function parameter
    p = _py(tmp_path, 'destination = "/dashboard"\nredirect(destination)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-015" for f in findings)


def test_SRC015_passes_redirect_with_different_param(tmp_path):
    # `url` is not a parameter, `name` is — redirect(url) should not fire
    p = _py(tmp_path, 'def go(name):\n    url = "/home"\n    return redirect(url)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-015" for f in findings)


def test_SRC015_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-015" for f in findings)


# ── Full fixture — all 15 rules ───────────────────────────────────────────────


# ── SRC-016: JWT algorithm confusion ─────────────────────────────────────────


def test_SRC016_detects_algorithms_none(tmp_path):
    p = _py(tmp_path, 'import jwt\ndef decode(tok):\n    return jwt.decode(tok, algorithms=["none"])')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-016" and f.severity == Severity.HIGH for f in findings)


def test_SRC016_detects_verify_signature_false(tmp_path):
    p = _py(
        tmp_path,
        'import jwt\ndef decode(tok):\n    return jwt.decode(tok, options={"verify_signature": False})',
    )
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-016" for f in findings)


def test_SRC016_detects_algorithms_none_uppercase(tmp_path):
    p = _py(tmp_path, 'import jwt\ndef decode(tok):\n    return jwt.decode(tok, algorithms=["None"])')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-016" for f in findings)


def test_SRC016_passes_valid_algorithm(tmp_path):
    p = _py(tmp_path, 'import jwt\ndef decode(tok, secret):\n    return jwt.decode(tok, secret, algorithms=["HS256"])')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-016" for f in findings)


def test_SRC016_passes_verify_signature_true(tmp_path):
    p = _py(
        tmp_path,
        'import jwt\ndef decode(tok):\n    return jwt.decode(tok, options={"verify_signature": True})',
    )
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-016" for f in findings)


def test_SRC016_passes_non_jwt_decode(tmp_path):
    p = _py(tmp_path, 'import base64\nbase64.decode("data")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-016" for f in findings)


def test_SRC016_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-016" for f in findings)


# ── Full fixture — all 16 rules ───────────────────────────────────────────────


# ── SRC-017: insecure cookie ──────────────────────────────────────────────────


def test_SRC017_detects_set_cookie_without_httponly(tmp_path):
    p = _py(tmp_path, 'def handler(resp, sid):\n    resp.set_cookie("session", sid, secure=True)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-017" and f.severity == Severity.MEDIUM for f in findings)


def test_SRC017_detects_set_cookie_without_secure(tmp_path):
    p = _py(tmp_path, 'def handler(resp, sid):\n    resp.set_cookie("session", sid, httponly=True)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-017" for f in findings)


def test_SRC017_detects_bare_set_cookie(tmp_path):
    p = _py(tmp_path, 'def handler(resp, sid):\n    resp.set_cookie("session", sid)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-017" for f in findings)


def test_SRC017_passes_set_cookie_with_both_flags(tmp_path):
    p = _py(tmp_path, 'def h(resp, sid):\n    resp.set_cookie("s", sid, httponly=True, secure=True)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-017" for f in findings)


def test_SRC017_passes_unrelated_method_named_set_cookie(tmp_path):
    # Only fires on known response method names
    p = _py(tmp_path, 'def h(db, sid):\n    db.set_cookie("s", sid)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-017" for f in findings)


def test_SRC017_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-017" for f in findings)


# ── Full fixture — all 17 rules ───────────────────────────────────────────────


# ── SRC-018: XXE injection ────────────────────────────────────────────────────


def test_SRC018_detects_ElementTree_fromstring(tmp_path):
    p = _py(tmp_path, "import xml.etree.ElementTree as ET\nET.fromstring(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-018" and f.severity == Severity.HIGH for f in findings)


def test_SRC018_detects_ElementTree_parse(tmp_path):
    p = _py(tmp_path, "import xml.etree.ElementTree as ET\nET.parse(filename)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-018" for f in findings)


def test_SRC018_detects_minidom_parseString(tmp_path):
    p = _py(tmp_path, "from xml.dom import minidom\nminidom.parseString(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-018" for f in findings)


def test_SRC018_detects_lxml_fromstring(tmp_path):
    p = _py(tmp_path, "from lxml import etree\netree.fromstring(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-018" for f in findings)


def test_SRC018_passes_defusedxml(tmp_path):
    p = _py(tmp_path, "import defusedxml.ElementTree as ET\nET.fromstring(data)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-018" for f in findings)


def test_SRC018_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-018" for f in findings)


# ── Full fixture — all 18 rules ───────────────────────────────────────────────


def test_vulnerable_fixture_has_all_eighteen_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 19)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-019: unsafe deserialization beyond pickle ─────────────────────────────


def test_SRC019_detects_jsonpickle_decode(tmp_path):
    p = _py(tmp_path, "import jsonpickle\njsonpickle.decode(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-019" for f in findings)


def test_SRC019_detects_marshal_loads(tmp_path):
    p = _py(tmp_path, "import marshal\nmarshal.loads(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-019" for f in findings)


def test_SRC019_detects_dill_loads(tmp_path):
    p = _py(tmp_path, "import dill\ndill.loads(data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-019" for f in findings)


def test_SRC019_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-019" for f in findings)


# ── SRC-020: hardcoded cryptographic key ─────────────────────────────────────


def test_SRC020_detects_AES_new_literal_key(tmp_path):
    p = _py(tmp_path, 'from Crypto.Cipher import AES\nAES.new(b"mysecretkey12345", AES.MODE_GCM)')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-020" for f in findings)


def test_SRC020_detects_Fernet_literal_key(tmp_path):
    p = _py(tmp_path, 'from cryptography.fernet import Fernet\nFernet("some_hardcoded_key")')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-020" for f in findings)


def test_SRC020_passes_variable_key(tmp_path):
    p = _py(tmp_path, "AES.new(key, AES.MODE_GCM)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-020" for f in findings)


def test_SRC020_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-020" for f in findings)


# ── SRC-021: CORS wildcard ────────────────────────────────────────────────────


def test_SRC021_detects_allow_origins_wildcard(tmp_path):
    p = _py(tmp_path, 'app.add_middleware("CORSMiddleware", allow_origins=["*"])')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-021" for f in findings)


def test_SRC021_passes_specific_origin(tmp_path):
    p = _py(tmp_path, 'app.add_middleware("CORSMiddleware", allow_origins=["https://example.com"])')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-021" for f in findings)


def test_SRC021_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-021" for f in findings)


# ── Full fixture — all 21 rules ───────────────────────────────────────────────


def test_vulnerable_fixture_has_all_twentyone_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 22)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-022: SSTI ─────────────────────────────────────────────────────────────


def test_SRC022_detects_jinja2_Template_from_param(tmp_path):
    p = _py(tmp_path, "import jinja2\ndef render(tpl: str):\n    return jinja2.Template(tpl).render()")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-022" for f in findings)


def test_SRC022_passes_literal_template(tmp_path):
    p = _py(tmp_path, 'import jinja2\njinja2.Template("Hello {{ name }}")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-022" for f in findings)


def test_SRC022_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-022" for f in findings)


# ── SRC-023: ReDoS ───────────────────────────────────────────────────────────


def test_SRC023_detects_re_search_param(tmp_path):
    p = _py(tmp_path, "import re\ndef filter_items(pattern: str, items):\n    return re.search(pattern, items)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-023" for f in findings)


def test_SRC023_passes_literal_pattern(tmp_path):
    p = _py(tmp_path, 'import re\nre.search(r"[a-z]+", text)')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-023" for f in findings)


def test_SRC023_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-023" for f in findings)


# ── SRC-024: sensitive data in logs ──────────────────────────────────────────


def test_SRC024_detects_logging_password(tmp_path):
    p = _py(
        tmp_path,
        "import logging\ndef login(password: str):\n    logging.info(f'Login with password={password}')",
    )
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-024" for f in findings)


def test_SRC024_passes_non_sensitive_log(tmp_path):
    p = _py(tmp_path, "import logging\nlogging.info(f'User {username} logged in')")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-024" for f in findings)


def test_SRC024_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-024" for f in findings)


# ── Full fixture — all 24 rules ───────────────────────────────────────────────


def test_vulnerable_fixture_has_all_twentyfour_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 25)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-025: security header removed ─────────────────────────────────────────


def test_SRC025_detects_del_hsts(tmp_path):
    p = _py(tmp_path, 'del response.headers["strict-transport-security"]')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-025" for f in findings)


def test_SRC025_detects_del_csp(tmp_path):
    p = _py(tmp_path, 'del resp.headers["content-security-policy"]')
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-025" for f in findings)


def test_SRC025_passes_unrelated_del(tmp_path):
    p = _py(tmp_path, 'del response.headers["accept"]')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-025" for f in findings)


def test_SRC025_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-025" for f in findings)


# ── SRC-026: mass assignment ──────────────────────────────────────────────────


def test_SRC026_detects_double_star_param(tmp_path):
    p = _py(tmp_path, "def create(data: dict):\n    return Model(**data)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-026" for f in findings)


def test_SRC026_passes_local_dict(tmp_path):
    p = _py(tmp_path, "local = {'a': 1}\nModel(**local)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-026" for f in findings)


def test_SRC026_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-026" for f in findings)


# ── SRC-027: path traversal via path.join ────────────────────────────────────


def test_SRC027_detects_os_path_join_param(tmp_path):
    p = _py(tmp_path, "def serve(base: str, name: str):\n    return os.path.join(base, name)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-027" for f in findings)


def test_SRC027_passes_all_literal(tmp_path):
    p = _py(tmp_path, 'os.path.join("/data", "report.csv")')
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-027" for f in findings)


def test_SRC027_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-027" for f in findings)


# ── Full fixture — all 27 rules ───────────────────────────────────────────────


def test_vulnerable_fixture_has_all_twentyseven_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 28)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-028: fixed PRNG seed ──────────────────────────────────────────────────


def test_SRC028_detects_random_seed_int(tmp_path):
    p = _py(tmp_path, "import random\nrandom.seed(42)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-028" for f in findings)


def test_SRC028_detects_random_seed_zero(tmp_path):
    p = _py(tmp_path, "import random\nrandom.seed(0)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-028" for f in findings)


def test_SRC028_passes_random_seed_no_arg(tmp_path):
    p = _py(tmp_path, "import random\nrandom.seed()")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-028" for f in findings)


def test_SRC028_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-028" for f in findings)


# ── SRC-029: password hashed with fast algorithm ──────────────────────────────


def test_SRC029_detects_sha256_on_password_param(tmp_path):
    p = _py(tmp_path, "import hashlib\ndef store(password: str):\n    return hashlib.sha256(password)")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-029" for f in findings)


def test_SRC029_passes_non_sensitive_sha256(tmp_path):
    p = _py(tmp_path, "import hashlib\nhashlib.sha256(document_content)")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-029" for f in findings)


def test_SRC029_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-029" for f in findings)


# ── SRC-030: assert used for access control ───────────────────────────────────


def test_SRC030_detects_assert_is_authenticated(tmp_path):
    p = _py(tmp_path, "def route(user):\n    assert user.is_authenticated")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-030" for f in findings)


def test_SRC030_detects_assert_is_admin(tmp_path):
    p = _py(tmp_path, "def admin_route(user):\n    assert user.is_admin")
    findings = analyze_python(p)
    assert any(f.rule_id == "SRC-030" for f in findings)


def test_SRC030_passes_non_auth_assert(tmp_path):
    p = _py(tmp_path, "assert len(items) > 0")
    findings = analyze_python(p)
    assert not any(f.rule_id == "SRC-030" for f in findings)


def test_SRC030_fixture_fires_on_vulnerable_server():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    assert any(f.rule_id == "SRC-030" for f in findings)


# ── SRC-031: insecure tempfile ────────────────────────────────────────────────


def test_SRC031_detects_mktemp(tmp_path):
    p = _py(tmp_path, "import tempfile\ndef f(x):\n    return tempfile.mktemp(prefix=x)")
    assert any(f.rule_id == "SRC-031" for f in analyze_python(p))


def test_SRC031_passes_mkstemp(tmp_path):
    p = _py(tmp_path, "import tempfile\ndef f():\n    fd, path = tempfile.mkstemp()\n    return path")
    assert not any(f.rule_id == "SRC-031" for f in analyze_python(p))


# ── SRC-032: hardcoded JWT secret ─────────────────────────────────────────────


def test_SRC032_detects_jwt_encode_literal_key(tmp_path):
    code = 'import jwt\ndef f(payload):\n    return jwt.encode(payload, "s3cr3t_key_12345")'
    assert any(f.rule_id == "SRC-032" for f in analyze_python(_py(tmp_path, code)))


def test_SRC032_passes_env_key(tmp_path):
    p = _py(
        tmp_path,
        "import jwt, os\ndef f(payload):\n    return jwt.encode(payload, os.environ['JWT_SECRET'])",
    )
    assert not any(f.rule_id == "SRC-032" for f in analyze_python(p))


# ── SRC-033: weak TLS protocol ────────────────────────────────────────────────


def test_SRC033_detects_protocol_tls1(tmp_path):
    p = _py(tmp_path, "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)")
    assert any(f.rule_id == "SRC-033" for f in analyze_python(p))


def test_SRC033_detects_protocol_sslv3(tmp_path):
    p = _py(tmp_path, "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)")
    assert any(f.rule_id == "SRC-033" for f in analyze_python(p))


def test_SRC033_passes_tls_client(tmp_path):
    p = _py(tmp_path, "import ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)")
    assert not any(f.rule_id == "SRC-033" for f in analyze_python(p))


# ── SRC-034: unsafe YAML loader ───────────────────────────────────────────────


def test_SRC034_detects_full_loader(tmp_path):
    p = _py(tmp_path, "import yaml\nyaml.load(data, Loader=yaml.FullLoader)")
    assert any(f.rule_id == "SRC-034" for f in analyze_python(p))


def test_SRC034_detects_bare_loader(tmp_path):
    p = _py(tmp_path, "import yaml\nyaml.load(data, Loader=yaml.Loader)")
    assert any(f.rule_id == "SRC-034" for f in analyze_python(p))


def test_SRC034_passes_safe_loader(tmp_path):
    p = _py(tmp_path, "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)")
    assert not any(f.rule_id == "SRC-034" for f in analyze_python(p))


# ── SRC-035: hardcoded env fallback ───────────────────────────────────────────


def test_SRC035_detects_password_fallback(tmp_path):
    p = _py(tmp_path, 'import os\nPWD = os.environ.get("DB_PASSWORD", "hunter2_secret")')
    assert any(f.rule_id == "SRC-035" for f in analyze_python(p))


def test_SRC035_passes_nonsensitive_key(tmp_path):
    p = _py(tmp_path, 'import os\nPORT = os.environ.get("PORT", "8080")')
    assert not any(f.rule_id == "SRC-035" for f in analyze_python(p))


def test_SRC035_passes_empty_fallback(tmp_path):
    p = _py(tmp_path, 'import os\nK = os.environ.get("API_KEY", "")')
    assert not any(f.rule_id == "SRC-035" for f in analyze_python(p))


# ── SRC-036: open redirect from request data ──────────────────────────────────


def test_SRC036_detects_redirect_args_get(tmp_path):
    p = _py(
        tmp_path,
        "from flask import redirect, request\ndef f():\n    return redirect(request.args.get('next', '/'))",
    )
    assert any(f.rule_id == "SRC-036" for f in analyze_python(p))


def test_SRC036_passes_redirect_literal(tmp_path):
    p = _py(tmp_path, "from flask import redirect\ndef f():\n    return redirect('/home')")
    assert not any(f.rule_id == "SRC-036" for f in analyze_python(p))


# ── SRC-037: user-controlled executable in subprocess ─────────────────────────


def test_SRC037_detects_param_as_first_list_element(tmp_path):
    p = _py(
        tmp_path,
        "import subprocess\ndef run(cmd: str):\n    subprocess.run([cmd, '--flag'])",
    )
    assert any(f.rule_id == "SRC-037" for f in analyze_python(p))


def test_SRC037_passes_literal_executable(tmp_path):
    p = _py(tmp_path, "import subprocess\nsubprocess.run(['ls', '-la'])")
    assert not any(f.rule_id == "SRC-037" for f in analyze_python(p))


# ── SRC-038: world-writable file permissions ───────────────────────────────────


def test_SRC038_detects_chmod_0o777(tmp_path):
    p = _py(tmp_path, "import os\nos.chmod('/tmp/f', 0o777)")
    assert any(f.rule_id == "SRC-038" for f in analyze_python(p))


def test_SRC038_detects_chmod_0o002(tmp_path):
    p = _py(tmp_path, "import os\nos.chmod('/tmp/f', 0o002)")
    assert any(f.rule_id == "SRC-038" for f in analyze_python(p))


def test_SRC038_passes_chmod_0o644(tmp_path):
    p = _py(tmp_path, "import os\nos.chmod('/tmp/f', 0o644)")
    assert not any(f.rule_id == "SRC-038" for f in analyze_python(p))


# ── SRC-039: base64 as obfuscation on sensitive value ─────────────────────────


def test_SRC039_detects_b64encode_password(tmp_path):
    p = _py(tmp_path, "import base64\nbase64.b64encode(password.encode())")
    assert any(f.rule_id == "SRC-039" for f in analyze_python(p))


def test_SRC039_detects_b64decode_secret(tmp_path):
    p = _py(tmp_path, "import base64\nbase64.b64decode(secret_key)")
    assert any(f.rule_id == "SRC-039" for f in analyze_python(p))


def test_SRC039_passes_b64encode_nonsensitive(tmp_path):
    p = _py(tmp_path, "import base64\nbase64.b64encode(image_data)")
    assert not any(f.rule_id == "SRC-039" for f in analyze_python(p))


# ── SRC-043: SQL injection via str.format() ───────────────────────────────────


def test_SRC043_detects_format_in_execute(tmp_path):
    p = _py(
        tmp_path,
        "def search(term: str):\n    cursor.execute(\"SELECT * FROM users WHERE name = '{}'\".format(term))",
    )
    assert any(f.rule_id == "SRC-043" for f in analyze_python(p))


def test_SRC043_detects_format_in_query(tmp_path):
    p = _py(
        tmp_path,
        "def find(uid: str):\n    db.query(\"SELECT * FROM users WHERE id = '{}'\".format(uid))",
    )
    assert any(f.rule_id == "SRC-043" for f in analyze_python(p))


def test_SRC043_passes_parameterized_query(tmp_path):
    p = _py(tmp_path, "def search(term: str):\n    cursor.execute('SELECT * FROM users WHERE name = %s', (term,))")
    assert not any(f.rule_id == "SRC-043" for f in analyze_python(p))


# ── SRC-044: HTTP header injection ────────────────────────────────────────────


def test_SRC044_detects_header_param_assign(tmp_path):
    p = _py(tmp_path, "def redir(response, url: str):\n    response.headers['Location'] = url")
    assert any(f.rule_id == "SRC-044" for f in analyze_python(p))


def test_SRC044_detects_resp_header_assign(tmp_path):
    p = _py(tmp_path, "def set_hdr(resp, val: str):\n    resp.headers['X-Custom'] = val")
    assert any(f.rule_id == "SRC-044" for f in analyze_python(p))


def test_SRC044_passes_literal_header_value(tmp_path):
    p = _py(tmp_path, "response.headers['Content-Type'] = 'application/json'")
    assert not any(f.rule_id == "SRC-044" for f in analyze_python(p))


# ── SRC-045: file serving with user-controlled path ───────────────────────────


def test_SRC045_detects_send_file_param(tmp_path):
    p = _py(tmp_path, "from flask import send_file\ndef serve(filepath: str):\n    return send_file(filepath)")
    assert any(f.rule_id == "SRC-045" for f in analyze_python(p))


def test_SRC045_detects_send_from_directory_param(tmp_path):
    p = _py(
        tmp_path,
        "from flask import send_from_directory\ndef serve(d: str, fn: str):\n    return send_from_directory(d, fn)",
    )
    assert any(f.rule_id == "SRC-045" for f in analyze_python(p))


def test_SRC045_passes_send_file_literal(tmp_path):
    p = _py(tmp_path, "from flask import send_file\nsend_file('static/index.html')")
    assert not any(f.rule_id == "SRC-045" for f in analyze_python(p))


# ── SRC-040: compile() with dynamic source ────────────────────────────────────


def test_SRC040_detects_compile_with_param(tmp_path):
    p = _py(tmp_path, "def run(user_code: str):\n    return compile(user_code, '<string>', 'exec')")
    assert any(f.rule_id == "SRC-040" for f in analyze_python(p))


def test_SRC040_passes_compile_literal(tmp_path):
    p = _py(tmp_path, "compile('1 + 1', '<string>', 'eval')")
    assert not any(f.rule_id == "SRC-040" for f in analyze_python(p))


# ── SRC-041: credentials in connection-string URL ─────────────────────────────


def test_SRC041_detects_postgresql_credentials(tmp_path):
    p = _py(tmp_path, 'URL = "postgresql://admin:password123@db.host/prod"')
    assert any(f.rule_id == "SRC-041" for f in analyze_python(p))


def test_SRC041_detects_mongodb_credentials(tmp_path):
    p = _py(tmp_path, 'MONGO = "mongodb://user:s3cret@mongo.example.com/mydb"')
    assert any(f.rule_id == "SRC-041" for f in analyze_python(p))


def test_SRC041_passes_url_without_password(tmp_path):
    p = _py(tmp_path, 'URL = "postgresql://localhost/mydb"')
    assert not any(f.rule_id == "SRC-041" for f in analyze_python(p))


# ── SRC-042: marshal.loads() deserialization ──────────────────────────────────


def test_SRC042_detects_marshal_loads_variable(tmp_path):
    p = _py(tmp_path, "import marshal\ndef load(data: bytes):\n    return marshal.loads(data)")
    assert any(f.rule_id == "SRC-042" for f in analyze_python(p))


def test_SRC042_detects_marshal_load_variable(tmp_path):
    p = _py(tmp_path, "import marshal\ndef load(f):\n    return marshal.load(f)")
    assert any(f.rule_id == "SRC-042" for f in analyze_python(p))


def test_SRC042_passes_marshal_loads_constant(tmp_path):
    p = _py(tmp_path, r"import marshal" + "\nmarshal.loads(b'\\xdb\\x00\\x00\\x00')")
    assert not any(f.rule_id == "SRC-042" for f in analyze_python(p))


# ── SRC-046: hashlib.new() with user-controlled algorithm ────────────────────


def test_SRC046_detects_hashlib_new_param_algo(tmp_path):
    p = _py(tmp_path, "import hashlib\ndef h(algo: str):\n    return hashlib.new(algo, b'data')")
    assert any(f.rule_id == "SRC-046" for f in analyze_python(p))


def test_SRC046_passes_hashlib_new_literal_algo(tmp_path):
    p = _py(tmp_path, "import hashlib\nhashlib.new('sha256', b'data')")
    assert not any(f.rule_id == "SRC-046" for f in analyze_python(p))


# ── SRC-047: importlib.import_module() with user-controlled name ──────────────


def test_SRC047_detects_import_module_param(tmp_path):
    p = _py(tmp_path, "import importlib\ndef load(module_name: str):\n    return importlib.import_module(module_name)")
    assert any(f.rule_id == "SRC-047" for f in analyze_python(p))


def test_SRC047_passes_import_module_literal(tmp_path):
    p = _py(tmp_path, "import importlib\nimportlib.import_module('os')")
    assert not any(f.rule_id == "SRC-047" for f in analyze_python(p))


# ── SRC-048: extractall() without filter — zip/tar slip ──────────────────────


def test_SRC048_detects_zipfile_extractall_no_filter(tmp_path):
    p = _py(tmp_path, "import zipfile\nwith zipfile.ZipFile('a.zip') as z:\n    z.extractall('/tmp')")
    assert any(f.rule_id == "SRC-048" for f in analyze_python(p))


def test_SRC048_passes_extractall_with_filter(tmp_path):
    p = _py(tmp_path, "import zipfile\nwith zipfile.ZipFile('a.zip') as z:\n    z.extractall('/tmp', filter='data')")
    assert not any(f.rule_id == "SRC-048" for f in analyze_python(p))


# ── SRC-049: socket.setdefaulttimeout(None) ───────────────────────────────────


def test_SRC049_detects_setdefaulttimeout_none(tmp_path):
    p = _py(tmp_path, "import socket\nsocket.setdefaulttimeout(None)")
    assert any(f.rule_id == "SRC-049" and f.severity == Severity.LOW for f in analyze_python(p))


def test_SRC049_passes_setdefaulttimeout_finite(tmp_path):
    p = _py(tmp_path, "import socket\nsocket.setdefaulttimeout(30)")
    assert not any(f.rule_id == "SRC-049" for f in analyze_python(p))


# ── SRC-050: ctypes.CDLL with user-controlled path ───────────────────────────


def test_SRC050_detects_ctypes_CDLL_param(tmp_path):
    p = _py(tmp_path, "import ctypes\ndef load(lib_path: str):\n    ctypes.CDLL(lib_path)")
    assert any(f.rule_id == "SRC-050" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_SRC050_passes_ctypes_CDLL_literal(tmp_path):
    p = _py(tmp_path, "import ctypes\nctypes.CDLL('libssl.so')")
    assert not any(f.rule_id == "SRC-050" for f in analyze_python(p))


# ── SRC-051: threading.Thread(target=param) ───────────────────────────────────


def test_SRC051_detects_thread_target_param(tmp_path):
    p = _py(tmp_path, "import threading\ndef run(callback):\n    threading.Thread(target=callback).start()")
    assert any(f.rule_id == "SRC-051" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC051_passes_thread_target_literal_func(tmp_path):
    p = _py(tmp_path, "import threading\ndef worker(): pass\nthreading.Thread(target=worker).start()")
    assert not any(f.rule_id == "SRC-051" for f in analyze_python(p))


# ── SRC-052: getattr(obj, param) — user-controlled attribute access ───────────


def test_SRC052_detects_getattr_param(tmp_path):
    p = _py(tmp_path, "def call(obj, method: str):\n    return getattr(obj, method)()")
    assert any(f.rule_id == "SRC-052" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC052_passes_getattr_literal(tmp_path):
    p = _py(tmp_path, "getattr(obj, 'run')")
    assert not any(f.rule_id == "SRC-052" for f in analyze_python(p))


# ── SRC-053: os.environ.update(param) — environment injection ─────────────────


def test_SRC053_detects_environ_update_param(tmp_path):
    p = _py(tmp_path, "import os\ndef inject(env_data: dict):\n    os.environ.update(env_data)")
    assert any(f.rule_id == "SRC-053" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC053_passes_environ_update_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.environ.update({'KEY': 'value'})")
    assert not any(f.rule_id == "SRC-053" for f in analyze_python(p))


# ── SRC-054: xmlrpc.client.ServerProxy(param) — SSRF via XML-RPC ─────────────


def test_SRC054_detects_xmlrpc_param_url(tmp_path):
    p = _py(tmp_path, "import xmlrpc.client\ndef rpc(url: str):\n    xmlrpc.client.ServerProxy(url)")
    assert any(f.rule_id == "SRC-054" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC054_passes_xmlrpc_literal_url(tmp_path):
    p = _py(tmp_path, "import xmlrpc.client\nxmlrpc.client.ServerProxy('http://internal.example.com')")
    assert not any(f.rule_id == "SRC-054" for f in analyze_python(p))


# ── SRC-055: render_template_string(param) — Flask SSTI ──────────────────────


def test_SRC055_detects_render_template_string_param(tmp_path):
    p = _py(
        tmp_path,
        "from flask import render_template_string\n"
        "def view(template: str):\n"
        "    return render_template_string(template)",
    )
    assert any(f.rule_id == "SRC-055" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_SRC055_passes_render_template_string_literal(tmp_path):
    p = _py(tmp_path, "from flask import render_template_string\nrender_template_string('<h1>Hello</h1>')")
    assert not any(f.rule_id == "SRC-055" for f in analyze_python(p))


# ── SRC-056: Process(target=param) — user-controlled subprocess ───────────────


def test_SRC056_detects_Process_target_param(tmp_path):
    p = _py(
        tmp_path,
        "import multiprocessing\ndef run(callback):\n    multiprocessing.Process(target=callback).start()",
    )
    assert any(f.rule_id == "SRC-056" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC056_passes_Process_target_literal(tmp_path):
    p = _py(tmp_path, "import multiprocessing\ndef worker(): pass\nmultiprocessing.Process(target=worker).start()")
    assert not any(f.rule_id == "SRC-056" for f in analyze_python(p))


# ── SRC-057: webbrowser.open(param) — open redirect in OS browser ─────────────


def test_SRC057_detects_webbrowser_open_param(tmp_path):
    p = _py(tmp_path, "import webbrowser\ndef browse(url: str):\n    webbrowser.open(url)")
    assert any(f.rule_id == "SRC-057" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC057_passes_webbrowser_open_literal(tmp_path):
    p = _py(tmp_path, "import webbrowser\nwebbrowser.open('https://example.com')")
    assert not any(f.rule_id == "SRC-057" for f in analyze_python(p))


# ── SRC-058: ftplib.FTP(host) — SSRF via FTP ──────────────────────────────────


def test_SRC058_detects_FTP_host_param(tmp_path):
    p = _py(tmp_path, "import ftplib\ndef conn(host: str):\n    ftplib.FTP(host)")
    assert any(f.rule_id == "SRC-058" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC058_passes_FTP_literal(tmp_path):
    p = _py(tmp_path, "import ftplib\nftplib.FTP('ftp.example.com')")
    assert not any(f.rule_id == "SRC-058" for f in analyze_python(p))


# ── SRC-059: smtplib.SMTP(host) — SSRF via SMTP ──────────────────────────────


def test_SRC059_detects_SMTP_host_param(tmp_path):
    p = _py(tmp_path, "import smtplib\ndef mailer(host: str):\n    smtplib.SMTP(host)")
    assert any(f.rule_id == "SRC-059" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC059_passes_SMTP_literal(tmp_path):
    p = _py(tmp_path, "import smtplib\nsmtplib.SMTP('mail.example.com')")
    assert not any(f.rule_id == "SRC-059" for f in analyze_python(p))


# ── SRC-060: ldap3.Server(host) — LDAP SSRF ───────────────────────────────────


def test_SRC060_detects_ldap3_Server_param(tmp_path):
    p = _py(tmp_path, "import ldap3\ndef ldap_conn(host: str):\n    ldap3.Server(host)")
    assert any(f.rule_id == "SRC-060" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC060_passes_ldap3_Server_literal(tmp_path):
    p = _py(tmp_path, "import ldap3\nldap3.Server('ldap.example.com')")
    assert not any(f.rule_id == "SRC-060" for f in analyze_python(p))


# ── SRC-061: os.popen(cmd) — shell injection via popen ────────────────────────


def test_SRC061_detects_os_popen_param(tmp_path):
    p = _py(tmp_path, "import os\ndef run(cmd: str):\n    os.popen(cmd)")
    assert any(f.rule_id == "SRC-061" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC061_detects_os_popen_fstring(tmp_path):
    p = _py(tmp_path, "import os\ndef run(cmd: str):\n    os.popen(f'echo {cmd}')")
    assert any(f.rule_id == "SRC-061" for f in analyze_python(p))


def test_SRC061_passes_os_popen_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.popen('ls -la')")
    assert not any(f.rule_id == "SRC-061" for f in analyze_python(p))


# ── SRC-062: urllib.request.urlretrieve(url) — SSRF ──────────────────────────


def test_SRC062_detects_urlretrieve_param(tmp_path):
    p = _py(tmp_path, "import urllib.request\ndef fetch(url: str):\n    urllib.request.urlretrieve(url)")
    assert any(f.rule_id == "SRC-062" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC062_passes_urlretrieve_literal(tmp_path):
    p = _py(tmp_path, "import urllib.request\nurllib.request.urlretrieve('https://example.com/file')")
    assert not any(f.rule_id == "SRC-062" for f in analyze_python(p))


# ── SRC-063: zipimport.zipimporter(path) — arbitrary zip import ───────────────


def test_SRC063_detects_zipimporter_param(tmp_path):
    p = _py(tmp_path, "import zipimport\ndef load(path: str):\n    zipimport.zipimporter(path)")
    assert any(f.rule_id == "SRC-063" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC063_passes_zipimporter_literal(tmp_path):
    p = _py(tmp_path, "import zipimport\nzipimport.zipimporter('/opt/plugins/safe.zip')")
    assert not any(f.rule_id == "SRC-063" for f in analyze_python(p))


# ── SRC-064: setattr(obj, name, val) — attribute injection ────────────────────


def test_SRC064_detects_setattr_name_param(tmp_path):
    p = _py(tmp_path, "def patch(obj, attr: str, val):\n    setattr(obj, attr, val)")
    assert any(f.rule_id == "SRC-064" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC064_passes_setattr_literal_name(tmp_path):
    p = _py(tmp_path, "setattr(obj, 'name', 'Alice')")
    assert not any(f.rule_id == "SRC-064" for f in analyze_python(p))


# ── SRC-065: ssl=False — TLS disabled in aiohttp/websockets ──────────────────


def test_SRC065_detects_ssl_false_kwarg(tmp_path):
    p = _py(tmp_path, "import aiohttp\nasync def req():\n    await session.get(url, ssl=False)")
    assert any(f.rule_id == "SRC-065" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC065_passes_ssl_true(tmp_path):
    p = _py(tmp_path, "session.get(url, ssl=True)")
    assert not any(f.rule_id == "SRC-065" for f in analyze_python(p))


# ── SRC-066: asyncio.create_subprocess_shell(cmd) — async shell injection ────


def test_SRC066_detects_create_subprocess_shell_param(tmp_path):
    p = _py(
        tmp_path,
        "import asyncio\nasync def run(cmd: str):\n    await asyncio.create_subprocess_shell(cmd)",
    )
    assert any(f.rule_id == "SRC-066" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC066_passes_create_subprocess_shell_literal(tmp_path):
    p = _py(tmp_path, "import asyncio\nasync def run():\n    await asyncio.create_subprocess_shell('ls')")
    assert not any(f.rule_id == "SRC-066" for f in analyze_python(p))


# ── SRC-067: socket.create_connection((host, port)) — raw TCP SSRF ───────────


def test_SRC067_detects_create_connection_tuple_param(tmp_path):
    p = _py(tmp_path, "import socket\ndef conn(host: str):\n    socket.create_connection((host, 443))")
    assert any(f.rule_id == "SRC-067" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC067_passes_create_connection_literal_host(tmp_path):
    p = _py(tmp_path, "import socket\nsocket.create_connection(('example.com', 443))")
    assert not any(f.rule_id == "SRC-067" for f in analyze_python(p))


# ── SRC-068: pbkdf2_hmac(iterations=user) — KDF DoS ──────────────────────────


def test_SRC068_detects_pbkdf2_iterations_positional(tmp_path):
    p = _py(
        tmp_path,
        "import hashlib\ndef kdf(pwd: str, s: bytes, iters: int):\n"
        "    hashlib.pbkdf2_hmac('sha256', pwd.encode(), s, iters)",
    )
    assert any(f.rule_id == "SRC-068" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC068_detects_pbkdf2_iterations_kwarg(tmp_path):
    p = _py(
        tmp_path,
        "import hashlib\ndef kdf(pwd: str, s: bytes, n: int):\n"
        "    hashlib.pbkdf2_hmac('sha256', pwd.encode(), s, iterations=n)",
    )
    assert any(f.rule_id == "SRC-068" for f in analyze_python(p))


def test_SRC068_passes_pbkdf2_literal_iterations(tmp_path):
    p = _py(tmp_path, "import hashlib\nhashlib.pbkdf2_hmac('sha256', b'x', b's', 600000)")
    assert not any(f.rule_id == "SRC-068" for f in analyze_python(p))


# ── SRC-069: Popen(executable=user) — executable override ────────────────────


def test_SRC069_detects_subprocess_executable_param(tmp_path):
    p = _py(
        tmp_path,
        "import subprocess\ndef run(exe: str):\n    subprocess.run(['dummy'], executable=exe)",
    )
    assert any(f.rule_id == "SRC-069" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC069_passes_subprocess_executable_literal(tmp_path):
    p = _py(tmp_path, "import subprocess\nsubprocess.run(['ls'], executable='/bin/ls')")
    assert not any(f.rule_id == "SRC-069" for f in analyze_python(p))


# ── SRC-070: subprocess.getoutput(user_cmd) — shell injection ────────────────


def test_SRC070_detects_getoutput_param(tmp_path):
    p = _py(tmp_path, "import subprocess\ndef run(cmd: str):\n    return subprocess.getoutput(cmd)")
    assert any(f.rule_id == "SRC-070" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC070_detects_getstatusoutput_param(tmp_path):
    p = _py(tmp_path, "import subprocess\ndef run(cmd: str):\n    return subprocess.getstatusoutput(cmd)")
    assert any(f.rule_id == "SRC-070" for f in analyze_python(p))


def test_SRC070_passes_getoutput_literal(tmp_path):
    p = _py(tmp_path, "import subprocess\nsubprocess.getoutput('ls -la')")
    assert not any(f.rule_id == "SRC-070" for f in analyze_python(p))


# ── SRC-071: logging.basicConfig(filename=user_path) — write path traversal ──


def test_SRC071_detects_basicConfig_filename_param(tmp_path):
    p = _py(
        tmp_path,
        "import logging\ndef configure(log_file: str):\n    logging.basicConfig(filename=log_file)",
    )
    assert any(f.rule_id == "SRC-071" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC071_passes_basicConfig_literal_filename(tmp_path):
    p = _py(tmp_path, "import logging\nlogging.basicConfig(filename='/var/log/app.log')")
    assert not any(f.rule_id == "SRC-071" for f in analyze_python(p))


# ── SRC-072: send_from_directory(user_dir, ...) — directory escape ────────────


def test_SRC072_detects_send_from_directory_param(tmp_path):
    code = (
        "from flask import send_from_directory\n"
        "def serve(directory: str, name: str):\n"
        "    return send_from_directory(directory, name)"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-072" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC072_passes_send_from_directory_literal(tmp_path):
    p = _py(tmp_path, "from flask import send_from_directory\nsend_from_directory('/static', 'logo.png')")
    assert not any(f.rule_id == "SRC-072" for f in analyze_python(p))


# ── SRC-073: exec(user_code) — arbitrary code execution ──────────────────────


def test_SRC073_detects_exec_param(tmp_path):
    p = _py(tmp_path, "def run(user_code: str):\n    exec(user_code)")
    assert any(f.rule_id == "SRC-073" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC073_passes_exec_literal(tmp_path):
    p = _py(tmp_path, "exec('x = 1')")
    assert not any(f.rule_id == "SRC-073" for f in analyze_python(p))


# ── SRC-074: open(user_path, "w") — write path traversal ─────────────────────


def test_SRC074_detects_open_write_param(tmp_path):
    p = _py(tmp_path, "def write(path: str, data: bytes):\n    open(path, 'wb')")
    assert any(f.rule_id == "SRC-074" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC074_passes_open_read_param(tmp_path):
    p = _py(tmp_path, "def read(path: str):\n    open(path, 'r')")
    assert not any(f.rule_id == "SRC-074" for f in analyze_python(p))


def test_SRC074_passes_open_write_literal(tmp_path):
    p = _py(tmp_path, "open('/tmp/out.txt', 'w')")
    assert not any(f.rule_id == "SRC-074" for f in analyze_python(p))


# ── SRC-075: shlex.split(user_input) — shell tokenisation injection ───────────


def test_SRC075_detects_shlex_split_param(tmp_path):
    p = _py(tmp_path, "import shlex\ndef run(cmd: str):\n    return shlex.split(cmd)")
    assert any(f.rule_id == "SRC-075" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC075_passes_shlex_split_literal(tmp_path):
    p = _py(tmp_path, "import shlex\nshlex.split('ls -la /tmp')")
    assert not any(f.rule_id == "SRC-075" for f in analyze_python(p))


# ── SRC-076: globals()/locals() in parameterised function — namespace exposure ─


def test_SRC076_detects_globals_in_function(tmp_path):
    p = _py(tmp_path, "def lookup(key: str):\n    return globals()[key]")
    assert any(f.rule_id == "SRC-076" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC076_passes_globals_at_module_level(tmp_path):
    p = _py(tmp_path, "g = globals()")
    assert not any(f.rule_id == "SRC-076" for f in analyze_python(p))


# ── SRC-077: os.makedirs(user_path) — arbitrary directory creation ────────────


def test_SRC077_detects_makedirs_param(tmp_path):
    p = _py(tmp_path, "import os\ndef make(path: str):\n    os.makedirs(path)")
    assert any(f.rule_id == "SRC-077" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC077_passes_makedirs_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.makedirs('/tmp/app/data')")
    assert not any(f.rule_id == "SRC-077" for f in analyze_python(p))


# ── SRC-078: check_output(cmd, shell=True) with param — shell injection ────────


def test_SRC078_detects_check_output_shell_param(tmp_path):
    p = _py(
        tmp_path,
        "import subprocess\ndef run(cmd: str):\n    subprocess.check_output(cmd, shell=True)",
    )
    assert any(f.rule_id == "SRC-078" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC078_passes_check_output_no_shell(tmp_path):
    p = _py(tmp_path, "import subprocess\ndef run(cmd: str):\n    subprocess.check_output(cmd)")
    assert not any(f.rule_id == "SRC-078" for f in analyze_python(p))


# ── SRC-079: configparser.read(user_path) — attacker-chosen config source ─────


def test_SRC079_detects_configparser_read_param(tmp_path):
    p = _py(
        tmp_path,
        "import configparser\ndef load(path: str):\n    return configparser.ConfigParser().read(path)",
    )
    assert any(f.rule_id == "SRC-079" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC079_passes_configparser_read_literal(tmp_path):
    p = _py(tmp_path, "import configparser\ncfg = configparser.ConfigParser()\ncfg.read('/etc/app.cfg')")
    assert not any(f.rule_id == "SRC-079" for f in analyze_python(p))


# ── SRC-080: os.execv(user_path, ...) — user-controlled process replacement ───


def test_SRC080_detects_execv_param(tmp_path):
    p = _py(tmp_path, "import os\ndef run(exe: str):\n    os.execv(exe, [exe])")
    assert any(f.rule_id == "SRC-080" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC080_passes_execv_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.execv('/usr/bin/ls', ['ls', '-la'])")
    assert not any(f.rule_id == "SRC-080" for f in analyze_python(p))


# ── SRC-081: os.rename(user_src, ...) — user-controlled file rename ───────────


def test_SRC081_detects_rename_param(tmp_path):
    p = _py(tmp_path, "import os\ndef move(src: str, dst: str):\n    os.rename(src, dst)")
    assert any(f.rule_id == "SRC-081" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC081_passes_rename_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.rename('/tmp/a', '/tmp/b')")
    assert not any(f.rule_id == "SRC-081" for f in analyze_python(p))


# ── SRC-082: NamedTemporaryFile(dir=user_dir) — temp directory path traversal ─


def test_SRC082_detects_namedtempfile_dir_param(tmp_path):
    p = _py(
        tmp_path,
        "import tempfile\ndef make(tmp_dir: str):\n    tempfile.NamedTemporaryFile(dir=tmp_dir)",
    )
    assert any(f.rule_id == "SRC-082" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC082_passes_namedtempfile_no_dir(tmp_path):
    p = _py(tmp_path, "import tempfile\ntempfile.NamedTemporaryFile(suffix='.txt')")
    assert not any(f.rule_id == "SRC-082" for f in analyze_python(p))


# ── SRC-083: os.symlink(user_src, ...) — symlink attack ──────────────────────


def test_SRC083_detects_symlink_param(tmp_path):
    p = _py(tmp_path, "import os\ndef link(target: str, path: str):\n    os.symlink(target, path)")
    assert any(f.rule_id == "SRC-083" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC083_passes_symlink_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.symlink('/usr/bin/python3', '/tmp/py')")
    assert not any(f.rule_id == "SRC-083" for f in analyze_python(p))


# ── SRC-084: os.link(user_src, ...) — hard link attack ───────────────────────


def test_SRC084_detects_hardlink_param(tmp_path):
    p = _py(tmp_path, "import os\ndef hl(src: str, dst: str):\n    os.link(src, dst)")
    assert any(f.rule_id == "SRC-084" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC084_passes_hardlink_literal(tmp_path):
    p = _py(tmp_path, "import os\nos.link('/etc/passwd', '/tmp/p')")
    assert not any(f.rule_id == "SRC-084" for f in analyze_python(p))


# ── SRC-085: sock.connect((user_host, port)) — raw TCP SSRF ──────────────────


def test_SRC085_detects_socket_connect_param(tmp_path):
    p = _py(tmp_path, "def conn(sock, host: str):\n    sock.connect((host, 443))")
    assert any(f.rule_id == "SRC-085" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC085_passes_socket_connect_literal(tmp_path):
    p = _py(tmp_path, "import socket\ns = socket.socket()\ns.connect(('example.com', 443))")
    assert not any(f.rule_id == "SRC-085" for f in analyze_python(p))


# ── SRC-086: ast.literal_eval(user_input) — DoS via nested structures ─────────


def test_SRC086_detects_literal_eval_param(tmp_path):
    p = _py(tmp_path, "import ast\ndef parse(data: str):\n    return ast.literal_eval(data)")
    assert any(f.rule_id == "SRC-086" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_SRC086_passes_literal_eval_literal(tmp_path):
    p = _py(tmp_path, "import ast\nast.literal_eval('[1, 2, 3]')")
    assert not any(f.rule_id == "SRC-086" for f in analyze_python(p))


# ── SRC-087: Popen(f-string with param) — argument injection ──────────────────


def test_SRC087_detects_popen_fstring_param(tmp_path):
    p = _py(
        tmp_path,
        "import subprocess\ndef run(cmd: str):\n    subprocess.Popen(f'/bin/tool --input {cmd}')",
    )
    assert any(f.rule_id == "SRC-087" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_SRC087_passes_popen_literal_string(tmp_path):
    p = _py(tmp_path, "import subprocess\nsubprocess.Popen('/bin/ls -la')")
    assert not any(f.rule_id == "SRC-087" for f in analyze_python(p))


# ── SRC-088: logging.FileHandler(user_path) — write path traversal ────────────


def test_src_088_fires_on_filehandler_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import logging\ndef setup_log(log_path: str):\n    logging.FileHandler(log_path)\n")
    assert any(f.rule_id == "SRC-088" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_088_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import logging\ndef setup_log():\n    logging.FileHandler('/var/log/app.log')\n")
    assert not any(f.rule_id == "SRC-088" for f in analyze_python(p))


# ── SRC-089: os.kill(user_pid, sig) — arbitrary process kill (DoS) ────────────


def test_src_089_fires_on_kill_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import os, signal\ndef stop_proc(pid: int):\n    os.kill(pid, signal.SIGTERM)\n")
    assert any(f.rule_id == "SRC-089" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_089_no_fire_on_hardcoded_pid(tmp_path: Path) -> None:
    p = _py(tmp_path, "import os, signal\ndef stop_proc():\n    os.kill(1234, signal.SIGTERM)\n")
    assert not any(f.rule_id == "SRC-089" for f in analyze_python(p))


# ── SRC-090: tarfile.open(user_path) — user-controlled archive path ───────────


def test_src_090_fires_on_tarfile_open_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import tarfile\ndef read_archive(archive_path: str):\n    tarfile.open(archive_path)\n")
    assert any(f.rule_id == "SRC-090" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_090_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import tarfile\ndef read_archive():\n    tarfile.open('/tmp/static.tar.gz')\n")
    assert not any(f.rule_id == "SRC-090" for f in analyze_python(p))


# ── SRC-091: sqlite3.connect(user_path) — arbitrary DB file access ────────────


def test_src_091_fires_on_sqlite_connect_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import sqlite3\ndef open_db(db_path: str):\n    sqlite3.connect(db_path)\n")
    assert any(f.rule_id == "SRC-091" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_091_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import sqlite3\ndef open_db():\n    sqlite3.connect('/app/data.db')\n")
    assert not any(f.rule_id == "SRC-091" for f in analyze_python(p))


# ── SRC-092: os.chmod(user_path, mode) — user-controlled chmod target ─────────


def test_src_092_fires_on_chmod_with_param_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import os\ndef fix_perms(target_path: str):\n    os.chmod(target_path, 0o644)\n")
    assert any(f.rule_id == "SRC-092" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_092_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import os\ndef fix_perms():\n    os.chmod('/app/config.cfg', 0o644)\n")
    assert not any(f.rule_id == "SRC-092" for f in analyze_python(p))


# ── SRC-093: os.chown(user_path, uid, gid) — user-controlled chown target ─────


def test_src_093_fires_on_chown_with_param_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import os\ndef take_ownership(target_path: str):\n    os.chown(target_path, 0, 0)\n")
    assert any(f.rule_id == "SRC-093" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_093_no_fire_on_hardcoded_path(tmp_path: Path) -> None:
    p = _py(tmp_path, "import os\ndef take_ownership():\n    os.chown('/app/data', 1000, 1000)\n")
    assert not any(f.rule_id == "SRC-093" for f in analyze_python(p))


# ── SRC-094: sock.bind((user_host, port)) — service binds on wrong interface ──


def test_src_094_fires_on_bind_with_param_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "def start_server(sock, host: str):\n    sock.bind((host, 8080))\n")
    assert any(f.rule_id == "SRC-094" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_094_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "def start_server(sock):\n    sock.bind(('0.0.0.0', 8080))\n")
    assert not any(f.rule_id == "SRC-094" for f in analyze_python(p))


# ── SRC-095: imaplib.IMAP4(user_host) — SSRF via IMAP ────────────────────────


def test_src_095_fires_on_imap4_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import imaplib\ndef check_mail(host: str):\n    imaplib.IMAP4(host)\n")
    assert any(f.rule_id == "SRC-095" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_095_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import imaplib\ndef check_mail():\n    imaplib.IMAP4('mail.example.com')\n")
    assert not any(f.rule_id == "SRC-095" for f in analyze_python(p))


# ── SRC-096: poplib.POP3(user_host) — SSRF via POP3 ──────────────────────────


def test_src_096_fires_on_pop3_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import poplib\ndef fetch_mail(host: str):\n    poplib.POP3(host)\n")
    assert any(f.rule_id == "SRC-096" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_096_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import poplib\ndef fetch_mail():\n    poplib.POP3('pop.example.com')\n")
    assert not any(f.rule_id == "SRC-096" for f in analyze_python(p))


# ── SRC-097: nntplib.NNTP(user_host) — SSRF via NNTP ────────────────────────


def test_src_097_fires_on_nntp_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import nntplib\ndef fetch_news(host: str):\n    nntplib.NNTP(host)\n")
    assert any(f.rule_id == "SRC-097" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_097_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import nntplib\ndef fetch_news():\n    nntplib.NNTP('news.example.com')\n")
    assert not any(f.rule_id == "SRC-097" for f in analyze_python(p))


# ── SRC-098: telnetlib.Telnet(user_host) — cleartext protocol + SSRF ─────────


def test_src_098_fires_on_telnet_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import telnetlib\ndef open_shell(host: str):\n    telnetlib.Telnet(host)\n")
    assert any(f.rule_id == "SRC-098" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_098_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import telnetlib\ndef open_shell():\n    telnetlib.Telnet('10.0.0.1')\n")
    assert not any(f.rule_id == "SRC-098" for f in analyze_python(p))


# ── SRC-099: http.client.HTTPConnection(user_host) — SSRF via stdlib HTTP ────


def test_src_099_fires_on_http_connection_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import http.client\ndef call(host: str):\n    http.client.HTTPConnection(host)\n")
    assert any(f.rule_id == "SRC-099" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_099_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import http.client\ndef call():\n    http.client.HTTPConnection('api.example.com')\n")
    assert not any(f.rule_id == "SRC-099" for f in analyze_python(p))


# ── SRC-100: paramiko.Transport(user_host) — SSRF via SSH transport ──────────


def test_src_100_fires_on_paramiko_transport_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import paramiko\ndef conn(host: str):\n    paramiko.Transport(host)\n")
    assert any(f.rule_id == "SRC-100" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_100_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import paramiko\ndef conn():\n    paramiko.Transport('ssh.example.com')\n")
    assert not any(f.rule_id == "SRC-100" for f in analyze_python(p))


# ── SRC-101: grpc.insecure_channel(user_target) — SSRF via gRPC ──────────────


def test_src_101_fires_on_grpc_insecure_channel_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import grpc\ndef call(target: str):\n    grpc.insecure_channel(target)\n")
    assert any(f.rule_id == "SRC-101" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_101_no_fire_on_hardcoded_target(tmp_path: Path) -> None:
    p = _py(tmp_path, "import grpc\ndef call():\n    grpc.insecure_channel('localhost:50051')\n")
    assert not any(f.rule_id == "SRC-101" for f in analyze_python(p))


# ── SRC-102: pymongo.MongoClient(user_host) — SSRF via MongoDB client ─────────


def test_src_102_fires_on_mongo_client_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pymongo\ndef db(host: str):\n    pymongo.MongoClient(host)\n")
    assert any(f.rule_id == "SRC-102" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_102_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pymongo\ndef db():\n    pymongo.MongoClient('mongodb.example.com')\n")
    assert not any(f.rule_id == "SRC-102" for f in analyze_python(p))


# ── SRC-103: pika.ConnectionParameters(user_host) — SSRF via AMQP ────────────


def test_src_103_fires_on_pika_conn_params_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pika\ndef connect(host: str):\n    pika.ConnectionParameters(host)\n")
    assert any(f.rule_id == "SRC-103" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_103_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pika\ndef connect():\n    pika.ConnectionParameters('rabbitmq.example.com')\n")
    assert not any(f.rule_id == "SRC-103" for f in analyze_python(p))


# ── SRC-104: KazooClient(user_hosts) — SSRF via ZooKeeper ────────────────────


def test_src_104_fires_on_kazoo_client_with_param(tmp_path: Path) -> None:
    code = "from kazoo.client import KazooClient\ndef connect(hosts: str):\n    KazooClient(hosts)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-104" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_104_no_fire_on_hardcoded_hosts(tmp_path: Path) -> None:
    code = "from kazoo.client import KazooClient\ndef connect():\n    KazooClient('zk1:2181')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-104" for f in analyze_python(p))


# ── SRC-105: etcd3.client(user_host) — SSRF via etcd ─────────────────────────


def test_src_105_fires_on_etcd3_client_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import etcd3\ndef connect(host: str):\n    etcd3.client(host)\n")
    assert any(f.rule_id == "SRC-105" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_105_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import etcd3\ndef connect():\n    etcd3.client('etcd.example.com')\n")
    assert not any(f.rule_id == "SRC-105" for f in analyze_python(p))


# ── SRC-106: Cluster(user_contact_points) — SSRF via Cassandra ───────────────


def test_src_106_fires_on_cassandra_cluster_with_param(tmp_path: Path) -> None:
    code = "import cassandra.cluster\ndef conn(cp: str):\n    cassandra.cluster.Cluster(cp)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-106" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_106_no_fire_on_hardcoded_hosts(tmp_path: Path) -> None:
    code = "import cassandra.cluster\ndef conn():\n    cassandra.cluster.Cluster(['10.0.0.1'])\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-106" for f in analyze_python(p))


# ── SRC-107: Elasticsearch(user_hosts) — SSRF via Elasticsearch ──────────────


def test_src_107_fires_on_elasticsearch_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import elasticsearch\ndef conn(hosts: str):\n    elasticsearch.Elasticsearch(hosts)\n")
    assert any(f.rule_id == "SRC-107" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_107_no_fire_on_hardcoded_hosts(tmp_path: Path) -> None:
    p = _py(tmp_path, "import elasticsearch\ndef conn():\n    elasticsearch.Elasticsearch(['es.example.com'])\n")
    assert not any(f.rule_id == "SRC-107" for f in analyze_python(p))


# ── SRC-108: couchdb.Server(user_url) — SSRF via CouchDB ─────────────────────


def test_src_108_fires_on_couchdb_server_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import couchdb\ndef conn(url: str):\n    couchdb.Server(url)\n")
    assert any(f.rule_id == "SRC-108" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_108_no_fire_on_hardcoded_url(tmp_path: Path) -> None:
    p = _py(tmp_path, "import couchdb\ndef conn():\n    couchdb.Server('http://localhost:5984')\n")
    assert not any(f.rule_id == "SRC-108" for f in analyze_python(p))


# ── SRC-109: pty.spawn(user_cmd) — OS command execution via PTY ───────────────


def test_src_109_fires_on_pty_spawn_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pty\ndef run(cmd: str):\n    pty.spawn(cmd)\n")
    assert any(f.rule_id == "SRC-109" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_109_no_fire_on_hardcoded_cmd(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pty\ndef run():\n    pty.spawn('/bin/bash')\n")
    assert not any(f.rule_id == "SRC-109" for f in analyze_python(p))


# ── SRC-110: pexpect.spawn(user_cmd) — OS command execution via pexpect ───────


def test_src_110_fires_on_pexpect_spawn_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pexpect\ndef run(cmd: str):\n    pexpect.spawn(cmd)\n")
    assert any(f.rule_id == "SRC-110" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_110_no_fire_on_hardcoded_cmd(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pexpect\ndef run():\n    pexpect.spawn('ssh root@host')\n")
    assert not any(f.rule_id == "SRC-110" for f in analyze_python(p))


# ── SRC-111: Popen(cwd=user_path) — user-controlled working directory ─────────


def test_src_111_fires_on_popen_cwd_with_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import subprocess\ndef run(cwd: str):\n    subprocess.Popen(['ls'], cwd=cwd)\n")
    assert any(f.rule_id == "SRC-111" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_111_no_fire_on_hardcoded_cwd(tmp_path: Path) -> None:
    p = _py(tmp_path, "import subprocess\ndef run():\n    subprocess.Popen(['ls'], cwd='/tmp')\n")
    assert not any(f.rule_id == "SRC-111" for f in analyze_python(p))


# ── SRC-112: redis.Redis(host=user_host) — SSRF via Redis host ────────────────


def test_src_112_fires_on_redis_host_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import redis\ndef conn(host: str):\n    redis.Redis(host=host)\n")
    assert any(f.rule_id == "SRC-112" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_112_no_fire_on_hardcoded_redis_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import redis\ndef conn():\n    redis.Redis(host='localhost')\n")
    assert not any(f.rule_id == "SRC-112" for f in analyze_python(p))


# ── SRC-113: pymysql.connect(host=user_host) — SSRF via MySQL host ───────────


def test_src_113_fires_on_mysql_host_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pymysql\ndef conn(host: str):\n    pymysql.connect(host=host, user='root')\n")
    assert any(f.rule_id == "SRC-113" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_113_no_fire_on_hardcoded_mysql_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import pymysql\ndef conn():\n    pymysql.connect(host='db.internal', user='root')\n")
    assert not any(f.rule_id == "SRC-113" for f in analyze_python(p))


# ── SRC-114: psycopg2.connect(host=user_host) — SSRF via PostgreSQL host ─────


def test_src_114_fires_on_psycopg2_host_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import psycopg2\ndef conn(host: str):\n    psycopg2.connect(host=host, dbname='app')\n")
    assert any(f.rule_id == "SRC-114" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_114_no_fire_on_hardcoded_pg_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import psycopg2\ndef conn():\n    psycopg2.connect(host='db.internal', dbname='app')\n")
    assert not any(f.rule_id == "SRC-114" for f in analyze_python(p))


# ── SRC-115: asyncio.create_subprocess_exec(user_prog) — async command injection ─


def test_src_115_fires_on_async_exec_prog_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import asyncio\nasync def run(prog: str):\n    await asyncio.create_subprocess_exec(prog)\n")
    assert any(f.rule_id == "SRC-115" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_115_no_fire_on_hardcoded_async_prog(tmp_path: Path) -> None:
    p = _py(tmp_path, "import asyncio\nasync def run():\n    await asyncio.create_subprocess_exec('/bin/ls')\n")
    assert not any(f.rule_id == "SRC-115" for f in analyze_python(p))


# ── SRC-116: asyncio.open_connection(user_host) — SSRF via async TCP ─────────


def test_src_116_fires_on_open_connection_host_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import asyncio\nasync def conn(host: str):\n    await asyncio.open_connection(host, 80)\n")
    assert any(f.rule_id == "SRC-116" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_116_no_fire_on_hardcoded_host(tmp_path: Path) -> None:
    p = _py(tmp_path, "import asyncio\nasync def conn():\n    await asyncio.open_connection('localhost', 80)\n")
    assert not any(f.rule_id == "SRC-116" for f in analyze_python(p))


# ── SRC-117: httpx.stream(method, user_url) — SSRF via httpx streaming ───────


def test_src_117_fires_on_httpx_stream_url_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import httpx\ndef fetch(url: str):\n    httpx.stream('GET', url)\n")
    assert any(f.rule_id == "SRC-117" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_117_no_fire_on_hardcoded_stream_url(tmp_path: Path) -> None:
    p = _py(tmp_path, "import httpx\ndef fetch():\n    httpx.stream('GET', 'https://api.example.com')\n")
    assert not any(f.rule_id == "SRC-117" for f in analyze_python(p))


# ── SRC-118: boto3.client(endpoint_url=param) — SSRF via AWS endpoint ─────────


def test_src_118_fires_on_boto3_endpoint_url_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import boto3\ndef cli(endpoint_url: str):\n    boto3.client('s3', endpoint_url=endpoint_url)\n")
    assert any(f.rule_id == "SRC-118" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_118_no_fire_on_hardcoded_boto3_endpoint(tmp_path: Path) -> None:
    p = _py(tmp_path, "import boto3\ndef cli():\n    boto3.client('s3', endpoint_url='https://s3.amazonaws.com')\n")
    assert not any(f.rule_id == "SRC-118" for f in analyze_python(p))


# ── SRC-119: aiofiles.open(user_path) — async path traversal ─────────────────


def test_src_119_fires_on_aiofiles_open_param(tmp_path: Path) -> None:
    code = "import aiofiles\nasync def read(path: str):\n    async with aiofiles.open(path):\n        pass\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-119" and f.severity == Severity.MEDIUM for f in analyze_python(p))


def test_src_119_no_fire_on_hardcoded_aiofiles_path(tmp_path: Path) -> None:
    code = "import aiofiles\nasync def read():\n    async with aiofiles.open('/tmp/data.txt'):\n        pass\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-119" for f in analyze_python(p))


# ── SRC-120: subprocess.Popen(env=user_env) — env dict injection ─────────────


def test_src_120_fires_on_popen_env_param(tmp_path: Path) -> None:
    p = _py(tmp_path, "import subprocess\ndef run(env: dict):\n    subprocess.Popen(['app'], env=env)\n")
    assert any(f.rule_id == "SRC-120" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_120_no_fire_on_hardcoded_env(tmp_path: Path) -> None:
    p = _py(tmp_path, "import subprocess\ndef run():\n    subprocess.Popen(['app'], env={'PATH': '/usr/bin'})\n")
    assert not any(f.rule_id == "SRC-120" for f in analyze_python(p))


# ── Full fixture — all 111 rules ──────────────────────────────────────────────


def test_vulnerable_fixture_has_all_one_hundred_eleven_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 112)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


def test_vulnerable_fixture_has_all_one_hundred_fourteen_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 115)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


def test_vulnerable_fixture_has_all_one_hundred_seventeen_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 118)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


def test_vulnerable_fixture_has_all_one_hundred_twenty_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 121)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-121: motor.motor_asyncio.AsyncIOMotorClient(url) — async MongoDB SSRF ─


def test_src_121_fires_on_motor_client_param(tmp_path: Path) -> None:
    code = (
        "import motor.motor_asyncio\n"
        "async def connect(url: str):\n"
        "    return motor.motor_asyncio.AsyncIOMotorClient(url)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-121" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_121_no_fire_on_hardcoded_motor_url(tmp_path: Path) -> None:
    code = (
        "import motor.motor_asyncio\n"
        "async def connect():\n"
        "    return motor.motor_asyncio.AsyncIOMotorClient('mongodb://localhost')\n"
    )
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-121" for f in analyze_python(p))


# ── SRC-122: kafka.KafkaProducer(bootstrap_servers=url) — Kafka broker SSRF ──


def test_src_122_fires_on_kafka_producer_param(tmp_path: Path) -> None:
    code = (
        "import kafka\n"
        "def make_producer(bootstrap_servers: str):\n"
        "    return kafka.KafkaProducer(bootstrap_servers=bootstrap_servers)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-122" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_122_no_fire_on_hardcoded_kafka_servers(tmp_path: Path) -> None:
    code = "import kafka\ndef make_producer():\n    return kafka.KafkaProducer(bootstrap_servers='broker:9092')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-122" for f in analyze_python(p))


# ── SRC-123: celery.Celery(broker=url) — Celery broker SSRF ──────────────────


def test_src_123_fires_on_celery_broker_param(tmp_path: Path) -> None:
    code = "import celery\ndef make_app(broker: str):\n    return celery.Celery(broker=broker)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-123" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_123_no_fire_on_hardcoded_celery_broker(tmp_path: Path) -> None:
    code = "import celery\ndef make_app():\n    return celery.Celery(broker='redis://localhost:6379/0')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-123" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_twenty_three_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 124)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-124: InfluxDBClient(url=url) — InfluxDB SSRF ─────────────────────────


def test_src_124_fires_on_influx_client_url_param(tmp_path: Path) -> None:
    code = "import influxdb_client\ndef connect(url: str):\n    return influxdb_client.InfluxDBClient(url=url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-124" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_124_no_fire_on_hardcoded_influx_url(tmp_path: Path) -> None:
    code = "import influxdb_client\ndef connect():\n    return influxdb_client.InfluxDBClient(url='http://localhost:8086')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-124" for f in analyze_python(p))


# ── SRC-125: clickhouse_driver.Client(host=host) — ClickHouse SSRF ───────────


def test_src_125_fires_on_clickhouse_host_param(tmp_path: Path) -> None:
    code = "import clickhouse_driver\ndef connect(host: str):\n    return clickhouse_driver.Client(host=host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-125" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_125_no_fire_on_hardcoded_clickhouse_host(tmp_path: Path) -> None:
    code = "import clickhouse_driver\ndef connect():\n    return clickhouse_driver.Client(host='localhost')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-125" for f in analyze_python(p))


# ── SRC-126: neo4j.GraphDatabase.driver(uri) — Neo4j SSRF ────────────────────


def test_src_126_fires_on_neo4j_driver_param(tmp_path: Path) -> None:
    code = "import neo4j\ndef connect(uri: str):\n    return neo4j.GraphDatabase.driver(uri)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-126" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_126_no_fire_on_hardcoded_neo4j_uri(tmp_path: Path) -> None:
    code = "import neo4j\ndef connect():\n    return neo4j.GraphDatabase.driver('bolt://localhost:7687')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-126" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_twenty_six_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 127)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-127: weaviate.Client(url=url) — Weaviate SSRF ────────────────────────


def test_src_127_fires_on_weaviate_client_url_param(tmp_path: Path) -> None:
    code = "import weaviate\ndef connect(url: str):\n    return weaviate.Client(url=url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-127" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_127_no_fire_on_hardcoded_weaviate_url(tmp_path: Path) -> None:
    code = "import weaviate\ndef connect():\n    return weaviate.Client(url='http://localhost:8080')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-127" for f in analyze_python(p))


# ── SRC-128: QdrantClient(host=host) — Qdrant SSRF ───────────────────────────


def test_src_128_fires_on_qdrant_client_host_param(tmp_path: Path) -> None:
    code = "import qdrant_client\ndef connect(host: str):\n    return qdrant_client.QdrantClient(host=host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-128" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_128_no_fire_on_hardcoded_qdrant_host(tmp_path: Path) -> None:
    code = "import qdrant_client\ndef connect():\n    return qdrant_client.QdrantClient(host='localhost')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-128" for f in analyze_python(p))


# ── SRC-129: chromadb.HttpClient(host=host) — ChromaDB SSRF ──────────────────


def test_src_129_fires_on_chroma_host_param(tmp_path: Path) -> None:
    code = "import chromadb\ndef connect(host: str):\n    return chromadb.HttpClient(host=host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-129" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_129_no_fire_on_hardcoded_chroma_host(tmp_path: Path) -> None:
    code = "import chromadb\ndef connect():\n    return chromadb.HttpClient(host='localhost')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-129" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_twenty_nine_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 130)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-130: OpenAI(base_url=url) — API key exfiltration SSRF ────────────────


def test_src_130_fires_on_openai_base_url_param(tmp_path: Path) -> None:
    code = "import openai\ndef client(base_url: str):\n    return openai.OpenAI(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-130" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_130_no_fire_on_hardcoded_openai_base(tmp_path: Path) -> None:
    code = "import openai\ndef client():\n    return openai.OpenAI(base_url='https://api.openai.com/v1')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-130" for f in analyze_python(p))


# ── SRC-131: Anthropic(base_url=url) — API key exfiltration SSRF ─────────────


def test_src_131_fires_on_anthropic_base_url_param(tmp_path: Path) -> None:
    code = "import anthropic\ndef client(base_url: str):\n    return anthropic.Anthropic(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-131" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_131_no_fire_on_hardcoded_anthropic_base(tmp_path: Path) -> None:
    code = "import anthropic\ndef client():\n    return anthropic.Anthropic(base_url='https://api.anthropic.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-131" for f in analyze_python(p))


# ── SRC-132: pymilvus.MilvusClient(host=host) — Milvus SSRF ──────────────────


def test_src_132_fires_on_milvus_host_param(tmp_path: Path) -> None:
    code = "import pymilvus\ndef connect(host: str):\n    return pymilvus.MilvusClient(host=host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-132" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_132_no_fire_on_hardcoded_milvus_host(tmp_path: Path) -> None:
    code = "import pymilvus\ndef connect():\n    return pymilvus.MilvusClient(host='localhost')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-132" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_thirty_two_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 133)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-133: groq.Groq(base_url=url) — API key exfiltration SSRF ─────────────


def test_src_133_fires_on_groq_base_url_param(tmp_path: Path) -> None:
    code = "import groq\ndef client(base_url: str):\n    return groq.Groq(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-133" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_133_no_fire_on_hardcoded_groq_base(tmp_path: Path) -> None:
    code = "import groq\ndef client():\n    return groq.Groq(base_url='https://api.groq.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-133" for f in analyze_python(p))


# ── SRC-134: cohere.Client(base_url=url) — API key exfiltration SSRF ─────────


def test_src_134_fires_on_cohere_base_url_param(tmp_path: Path) -> None:
    code = "import cohere\ndef client(base_url: str):\n    return cohere.Client(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-134" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_134_no_fire_on_hardcoded_cohere_base(tmp_path: Path) -> None:
    code = "import cohere\ndef client():\n    return cohere.Client(base_url='https://api.cohere.ai')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-134" for f in analyze_python(p))


# ── SRC-135: mistralai.Mistral(server_url=url) — API key exfiltration SSRF ───


def test_src_135_fires_on_mistral_server_url_param(tmp_path: Path) -> None:
    code = "import mistralai\ndef client(server_url: str):\n    return mistralai.Mistral(server_url=server_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-135" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_135_no_fire_on_hardcoded_mistral_server(tmp_path: Path) -> None:
    code = "import mistralai\ndef client():\n    return mistralai.Mistral(server_url='https://api.mistral.ai')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-135" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_thirty_five_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 136)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-136: together.Together(base_url=url) — API key exfiltration SSRF ─────


def test_src_136_fires_on_together_base_url_param(tmp_path: Path) -> None:
    code = "import together\ndef client(base_url: str):\n    return together.Together(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-136" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_136_no_fire_on_hardcoded_together_base(tmp_path: Path) -> None:
    code = "import together\ndef client():\n    return together.Together(base_url='https://api.together.xyz')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-136" for f in analyze_python(p))


# ── SRC-137: replicate.Client(base_url=url) — API key exfiltration SSRF ──────


def test_src_137_fires_on_replicate_base_url_param(tmp_path: Path) -> None:
    code = "import replicate\ndef client(base_url: str):\n    return replicate.Client(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-137" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_137_no_fire_on_hardcoded_replicate_base(tmp_path: Path) -> None:
    code = "import replicate\ndef client():\n    return replicate.Client(base_url='https://api.replicate.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-137" for f in analyze_python(p))


# ── SRC-138: huggingface_hub.InferenceClient(base_url=url) — API key exfil ───


def test_src_138_fires_on_hf_inference_base_url_param(tmp_path: Path) -> None:
    code = (
        "import huggingface_hub\ndef client(base_url: str):\n"
        "    return huggingface_hub.InferenceClient(base_url=base_url)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-138" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_138_no_fire_on_hardcoded_hf_base(tmp_path: Path) -> None:
    code = "import huggingface_hub\ndef client():\n    return huggingface_hub.InferenceClient(base_url='https://api-inference.huggingface.co')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-138" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_thirty_eight_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 139)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-139: voyageai.Client(base_url=url) — API key exfiltration SSRF ───────


def test_src_139_fires_on_voyage_base_url_param(tmp_path: Path) -> None:
    code = "import voyageai\ndef client(base_url: str):\n    return voyageai.Client(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-139" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_139_no_fire_on_hardcoded_voyage_base(tmp_path: Path) -> None:
    code = "import voyageai\ndef client():\n    return voyageai.Client(base_url='https://api.voyageai.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-139" for f in analyze_python(p))


# ── SRC-140: azure.ai.inference.ChatCompletionsClient(endpoint=url) — SSRF ───


def test_src_140_fires_on_azure_inference_endpoint_param(tmp_path: Path) -> None:
    code = (
        "import azure.ai.inference\ndef client(endpoint: str):\n"
        "    return azure.ai.inference.ChatCompletionsClient(endpoint=endpoint)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-140" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_140_no_fire_on_hardcoded_azure_endpoint(tmp_path: Path) -> None:
    code = (
        "import azure.ai.inference\ndef client():\n"
        "    return azure.ai.inference.ChatCompletionsClient(endpoint='https://my.openai.azure.com')\n"
    )
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-140" for f in analyze_python(p))


# ── SRC-141: ai21.AI21Client(api_host=url) — API key exfiltration SSRF ───────


def test_src_141_fires_on_ai21_api_host_param(tmp_path: Path) -> None:
    code = "import ai21\ndef client(api_host: str):\n    return ai21.AI21Client(api_host=api_host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-141" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_141_no_fire_on_hardcoded_ai21_host(tmp_path: Path) -> None:
    code = "import ai21\ndef client():\n    return ai21.AI21Client(api_host='https://api.ai21.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-141" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_forty_one_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 142)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-142: httpx.Client(base_url=url) — SSRF via httpx persistent client ───


def test_src_142_fires_on_httpx_client_base_url_param(tmp_path: Path) -> None:
    code = "import httpx\ndef client(base_url: str):\n    return httpx.Client(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-142" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_142_no_fire_on_hardcoded_httpx_base(tmp_path: Path) -> None:
    code = "import httpx\ndef client():\n    return httpx.Client(base_url='https://api.example.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-142" for f in analyze_python(p))


# ── SRC-143: cerebras.Cerebras(base_url=url) — API key exfiltration SSRF ─────


def test_src_143_fires_on_cerebras_base_url_param(tmp_path: Path) -> None:
    code = "import cerebras\ndef client(base_url: str):\n    return cerebras.Cerebras(base_url=base_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-143" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_143_no_fire_on_hardcoded_cerebras_base(tmp_path: Path) -> None:
    code = "import cerebras\ndef client():\n    return cerebras.Cerebras(base_url='https://api.cerebras.ai')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-143" for f in analyze_python(p))


# ── SRC-144: BlobServiceClient(account_url=url) — Azure Blob SSRF ────────────


def test_src_144_fires_on_blob_service_client_account_url_param(tmp_path: Path) -> None:
    code = (
        "import azure.storage.blob\ndef client(account_url: str):\n"
        "    return azure.storage.blob.BlobServiceClient(account_url=account_url)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-144" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_144_no_fire_on_hardcoded_blob_url(tmp_path: Path) -> None:
    code = (
        "import azure.storage.blob\ndef client():\n"
        "    return azure.storage.blob.BlobServiceClient(account_url='https://myaccount.blob.core.windows.net')\n"
    )
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-144" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_forty_four_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 145)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-145: google.cloud.*.Client(client_options=param) — GCP SSRF ──────────


def test_src_145_fires_on_bigquery_client_options_param(tmp_path: Path) -> None:
    code = (
        "import google.cloud.bigquery\ndef client(client_options: dict):\n"
        "    return google.cloud.bigquery.Client(client_options=client_options)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-145" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_145_no_fire_on_hardcoded_client_options(tmp_path: Path) -> None:
    code = "import google.cloud.bigquery\ndef client():\n    return google.cloud.bigquery.Client(client_options=None)\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-145" for f in analyze_python(p))


# ── SRC-146: firebase_admin.initialize_app(options=param) — Firebase SSRF ────


def test_src_146_fires_on_firebase_options_param(tmp_path: Path) -> None:
    code = (
        "import firebase_admin\ndef init(options: dict):\n    return firebase_admin.initialize_app(options=options)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-146" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_146_no_fire_on_hardcoded_firebase_options(tmp_path: Path) -> None:
    code = "import firebase_admin\ndef init():\n    return firebase_admin.initialize_app(options=None)\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-146" for f in analyze_python(p))


# ── SRC-147: GCP AI client(client_options=param) — GCP AI service SSRF ───────


def test_src_147_fires_on_translate_client_options_param(tmp_path: Path) -> None:
    code = (
        "import google.cloud.translate\ndef client(client_options: dict):\n"
        "    return google.cloud.translate.TranslationServiceClient(client_options=client_options)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-147" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_147_no_fire_on_hardcoded_translate_options(tmp_path: Path) -> None:
    code = (
        "import google.cloud.translate\ndef client():\n"
        "    return google.cloud.translate.TranslationServiceClient(client_options=None)\n"
    )
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-147" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_forty_seven_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 148)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-148: snowflake.connector.connect(account=param) — credential exfil ───


def test_src_148_fires_on_snowflake_account_param(tmp_path: Path) -> None:
    code = (
        "import snowflake.connector\ndef conn(account: str):\n    return snowflake.connector.connect(account=account)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-148" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_148_no_fire_on_hardcoded_snowflake_account(tmp_path: Path) -> None:
    code = "import snowflake.connector\ndef conn():\n    return snowflake.connector.connect(account='myorg-acct')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-148" for f in analyze_python(p))


# ── SRC-149: pulsar.Client(service_url=param) — Pulsar broker SSRF ───────────


def test_src_149_fires_on_pulsar_service_url_param(tmp_path: Path) -> None:
    code = "import pulsar\ndef client(service_url: str):\n    return pulsar.Client(service_url=service_url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-149" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_149_fires_on_pulsar_positional_param(tmp_path: Path) -> None:
    code = "import pulsar\ndef client(url: str):\n    return pulsar.Client(url)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-149" for f in analyze_python(p))


def test_src_149_no_fire_on_hardcoded_pulsar_url(tmp_path: Path) -> None:
    code = "import pulsar\ndef client():\n    return pulsar.Client('pulsar://broker:6650')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-149" for f in analyze_python(p))


# ── SRC-150: databricks.sql.connect(server_hostname=param) — cred exfil ──────


def test_src_150_fires_on_databricks_hostname_param(tmp_path: Path) -> None:
    code = (
        "import databricks.sql\ndef conn(server_hostname: str):\n"
        "    return databricks.sql.connect(server_hostname=server_hostname)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-150" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_150_no_fire_on_hardcoded_databricks_hostname(tmp_path: Path) -> None:
    code = (
        "import databricks.sql\ndef conn():\n"
        "    return databricks.sql.connect(server_hostname='dbc-123.cloud.databricks.com')\n"
    )
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-150" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_fifty_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 151)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-151: minio.Minio(endpoint=param) — credential exfil / SSRF ───────────


def test_src_151_fires_on_minio_endpoint_param(tmp_path: Path) -> None:
    code = "import minio\ndef client(endpoint: str):\n    return minio.Minio(endpoint=endpoint)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-151" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_151_fires_on_minio_positional_param(tmp_path: Path) -> None:
    code = "import minio\ndef client(endpoint: str):\n    return minio.Minio(endpoint)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-151" for f in analyze_python(p))


def test_src_151_no_fire_on_hardcoded_minio_endpoint(tmp_path: Path) -> None:
    code = "import minio\ndef client():\n    return minio.Minio('storage.internal:9000')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-151" for f in analyze_python(p))


# ── SRC-152: pymemcache Client(server=param) — memcached SSRF ────────────────


def test_src_152_fires_on_pymemcache_server_param(tmp_path: Path) -> None:
    code = "import pymemcache\ndef client(server: str):\n    return pymemcache.Client(server=server)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-152" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_152_no_fire_on_hardcoded_memcache_server(tmp_path: Path) -> None:
    code = "import pymemcache\ndef client():\n    return pymemcache.Client(server='cache.internal:11211')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-152" for f in analyze_python(p))


# ── SRC-153: consul.Consul(host=param) — Consul agent SSRF ───────────────────


def test_src_153_fires_on_consul_host_param(tmp_path: Path) -> None:
    code = "import consul\ndef client(host: str):\n    return consul.Consul(host=host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-153" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_153_no_fire_on_hardcoded_consul_host(tmp_path: Path) -> None:
    code = "import consul\ndef client():\n    return consul.Consul(host='consul.internal')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-153" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_fifty_three_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 154)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"


# ── SRC-154: ollama.Client(host=param) — Ollama SSRF / prompt exfil ──────────


def test_src_154_fires_on_ollama_host_param(tmp_path: Path) -> None:
    code = "import ollama\ndef client(host: str):\n    return ollama.Client(host=host)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-154" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_154_no_fire_on_hardcoded_ollama_host(tmp_path: Path) -> None:
    code = "import ollama\ndef client():\n    return ollama.Client(host='http://localhost:11434')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-154" for f in analyze_python(p))


# ── SRC-155: AzureOpenAI(azure_endpoint=param) — API key exfiltration ────────


def test_src_155_fires_on_azure_openai_endpoint_param(tmp_path: Path) -> None:
    code = (
        "import openai\ndef client(azure_endpoint: str):\n"
        "    return openai.AzureOpenAI(azure_endpoint=azure_endpoint)\n"
    )
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-155" and f.severity == Severity.CRITICAL for f in analyze_python(p))


def test_src_155_no_fire_on_hardcoded_azure_openai_endpoint(tmp_path: Path) -> None:
    code = "import openai\ndef client():\n    return openai.AzureOpenAI(azure_endpoint='https://my.openai.azure.com')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-155" for f in analyze_python(p))


# ── SRC-156: sentry_sdk.init(dsn=param) — error-report exfiltration ──────────


def test_src_156_fires_on_sentry_dsn_param(tmp_path: Path) -> None:
    code = "import sentry_sdk\ndef setup(dsn: str):\n    sentry_sdk.init(dsn=dsn)\n"
    p = _py(tmp_path, code)
    assert any(f.rule_id == "SRC-156" and f.severity == Severity.HIGH for f in analyze_python(p))


def test_src_156_no_fire_on_hardcoded_sentry_dsn(tmp_path: Path) -> None:
    code = "import sentry_sdk\ndef setup():\n    sentry_sdk.init(dsn='https://key@o0.ingest.sentry.io/0')\n"
    p = _py(tmp_path, code)
    assert not any(f.rule_id == "SRC-156" for f in analyze_python(p))


def test_vulnerable_fixture_has_all_one_hundred_fifty_six_rules():
    findings = analyze_python(FIXTURES / "vulnerable_server.py")
    rule_ids = {f.rule_id for f in findings}
    expected = {f"SRC-{i:03d}" for i in range(1, 157)}
    assert expected <= rule_ids, f"Missing rules: {expected - rule_ids}"
