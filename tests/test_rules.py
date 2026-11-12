"""Unit tests for Canlix rules — one test per rule, clean + vulnerable fixture."""

from pathlib import Path

from canlix.engine import scan
from canlix.models import MCPServer, Severity, Transport
from canlix.parsers.generic import parse_json_file
from canlix.rules.config import CFG_001_no_command_no_url, CFG_004_command_with_url
from canlix.rules.execution import (
    EXEC_001_relative_command,
    EXEC_002_direct_shell,
    EXEC_003_shell_flag_in_args,
    EXEC_004_unpinned_npx,
    EXEC_005_unpinned_uvx,
)
from canlix.rules.network import (
    NET_001_http_url,
    NET_002_public_url,
    NET_004_sensitive_path_in_args,
    NET_005_tls_verification_disabled,
)
from canlix.rules.permissions import PERM_001_broad_filesystem_access, PERM_003_home_dir_db
from canlix.rules.secrets import (
    SEC_001_api_key_in_env,
    SEC_002_secret_in_args,
    SEC_003_secret_key_name_in_env,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def server(name="test", command="", args=None, env=None, transport=Transport.STDIO, url=""):
    return MCPServer(name=name, command=command, args=args or [], env=env or {}, transport=transport, url=url)


FIXTURES = Path(__file__).parent / "fixtures"


# ── Secrets ────────────────────────────────────────────────────────────────


def test_SEC001_detects_api_key_in_env():
    s = server(env={"API_KEY": "sk-1234567890abcdef1234567890abcdef"})
    assert SEC_001_api_key_in_env(s) is not None


def test_SEC001_passes_empty_env():
    s = server(env={})
    assert SEC_001_api_key_in_env(s) is None


def test_SEC002_detects_secret_in_args():
    # 36+ chars after ghp_ required by pattern
    s = server(args=["--token", "ghp_abcdefghijklmnopqrstuvwxyz1234567890ab"])
    assert SEC_002_secret_in_args(s) is not None


def test_SEC002_passes_normal_args():
    s = server(args=["--port", "8080"])
    assert SEC_002_secret_in_args(s) is None


def test_SEC003_detects_sensitive_key_name():
    s = server(env={"PASSWORD": "hunter2"})
    assert SEC_003_secret_key_name_in_env(s) is not None


def test_SEC003_passes_non_sensitive_key():
    s = server(env={"DEBUG": "true"})
    assert SEC_003_secret_key_name_in_env(s) is None


# ── Execution ───────────────────────────────────────────────────────────────


def test_EXEC001_detects_relative_command():
    s = server(command="mcp-server-sqlite")
    f = EXEC_001_relative_command(s)
    assert f is not None
    assert f.severity == Severity.MEDIUM


def test_EXEC001_passes_absolute_command():
    s = server(command="/usr/local/bin/mcp-server-sqlite")
    assert EXEC_001_relative_command(s) is None


def test_EXEC002_detects_shell():
    s = server(command="bash", args=["-c", "python3 server.py"])
    assert EXEC_002_direct_shell(s) is not None


def test_EXEC002_passes_non_shell():
    s = server(command="node", args=["server.js"])
    assert EXEC_002_direct_shell(s) is None


def test_EXEC003_detects_shell_flag():
    s = server(command="sh", args=["-c", "echo hi"])
    assert EXEC_003_shell_flag_in_args(s) is not None


def test_EXEC003_passes_no_shell_flag():
    s = server(command="node", args=["--port", "3000"])
    assert EXEC_003_shell_flag_in_args(s) is None


def test_EXEC004_detects_unpinned_npx():
    s = server(command="npx", args=["-y", "some-mcp-server"])
    assert EXEC_004_unpinned_npx(s) is not None


def test_EXEC004_passes_pinned_npx():
    s = server(command="npx", args=["-y", "some-mcp-server@1.2.3"])
    assert EXEC_004_unpinned_npx(s) is None


def test_EXEC004_passes_non_npx():
    s = server(command="node", args=["server.js"])
    assert EXEC_004_unpinned_npx(s) is None


def test_EXEC005_detects_unpinned_uvx():
    s = server(command="uvx", args=["some-mcp-package"])
    assert EXEC_005_unpinned_uvx(s) is not None


def test_EXEC005_passes_pinned_uvx():
    s = server(command="uvx", args=["some-mcp-package==1.2.3"])
    assert EXEC_005_unpinned_uvx(s) is None


def test_EXEC005_passes_pipx_at_version():
    s = server(command="pipx", args=["some-package@1.0.0"])
    assert EXEC_005_unpinned_uvx(s) is None


# ── Network ─────────────────────────────────────────────────────────────────


def test_NET001_detects_http():
    s = server(transport=Transport.HTTP, url="http://api.example.com/mcp")
    assert NET_001_http_url(s) is not None


def test_NET001_passes_https():
    s = server(transport=Transport.HTTP, url="https://api.example.com/mcp")
    assert NET_001_http_url(s) is None


def test_NET001_ignores_stdio():
    s = server(transport=Transport.STDIO, command="mcp-server")
    assert NET_001_http_url(s) is None


def test_NET002_detects_remote_url():
    s = server(transport=Transport.HTTP, url="https://remote.example.com/mcp")
    assert NET_002_public_url(s) is not None


def test_NET002_passes_localhost():
    s = server(transport=Transport.HTTP, url="http://localhost:3000/mcp")
    assert NET_002_public_url(s) is None


def test_NET004_detects_sensitive_db_path():
    s = server(command="/usr/bin/mcp-sqlite", args=["--db-path", "/home/kali/secret.db"])
    assert NET_004_sensitive_path_in_args(s) is not None


def test_NET005_detects_no_verify_env():
    s = server(env={"NODE_TLS_REJECT_UNAUTHORIZED": "0", "SSL_VERIFY": "false"})
    assert NET_005_tls_verification_disabled(s) is not None


def test_NET005_detects_insecure_arg():
    s = server(command="/usr/bin/mcp-server", args=["--insecure"])
    assert NET_005_tls_verification_disabled(s) is not None


def test_NET005_passes_normal_env():
    s = server(env={"DEBUG": "true", "PORT": "3000"})
    assert NET_005_tls_verification_disabled(s) is None


# ── Permissions ─────────────────────────────────────────────────────────────


def test_PERM001_detects_root_path():
    s = server(command="/usr/bin/mcp-fs", args=["/"])
    assert PERM_001_broad_filesystem_access(s) is not None


def test_PERM001_passes_scoped_path():
    s = server(command="/usr/bin/mcp-fs", args=["/home/user/project"])
    assert PERM_001_broad_filesystem_access(s) is None


def test_PERM003_detects_home_db():
    s = server(command="/usr/bin/mcp-sqlite", args=["/home/kali/data.db"])
    assert PERM_003_home_dir_db(s) is not None


# ── Config ───────────────────────────────────────────────────────────────────


def test_CFG001_detects_missing_command_and_url():
    s = server(command="", url="")
    assert CFG_001_no_command_no_url(s) is not None


def test_CFG001_passes_with_command():
    s = server(command="mcp-server")
    assert CFG_001_no_command_no_url(s) is None


def test_CFG004_detects_both_command_and_url():
    s = server(command="mcp-server", url="https://example.com/mcp")
    assert CFG_004_command_with_url(s) is not None


# ── CFG-005 : duplicate server names (engine-level) ─────────────────────────


def test_CFG005_detects_duplicate_names():
    s1 = server(name="my-tool", command="/usr/bin/tool-a")
    s2 = server(name="my-tool", command="/usr/bin/tool-b")
    result = scan([s1, s2])
    cfg005 = [f for f in result.findings if f.rule_id == "CFG-005"]
    assert len(cfg005) == 1


def test_CFG005_passes_unique_names():
    s1 = server(name="tool-a", command="/usr/bin/tool-a")
    s2 = server(name="tool-b", command="/usr/bin/tool-b")
    result = scan([s1, s2])
    cfg005 = [f for f in result.findings if f.rule_id == "CFG-005"]
    assert len(cfg005) == 0


# ── Integration : full scan on fixtures ─────────────────────────────────────


def test_clean_config_has_no_critical():
    servers = parse_json_file(FIXTURES / "clean_config.json")
    result = scan(servers)
    critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


def test_vulnerable_config_has_findings():
    servers = parse_json_file(FIXTURES / "vulnerable_config.json")
    result = scan(servers)
    assert len(result.findings) >= 5


def test_vulnerable_config_score_below_50():
    servers = parse_json_file(FIXTURES / "vulnerable_config.json")
    result = scan(servers)
    assert result.score < 50


def test_scan_duration_under_1000ms():
    servers = parse_json_file(FIXTURES / "vulnerable_config.json")
    result = scan(servers)
    assert result.scan_duration_ms < 1000
