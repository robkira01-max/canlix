from __future__ import annotations

from pathlib import Path

from canlix.engine import scan
from canlix.models import MCPServer, Severity, Transport
from canlix.rules.cross_server import check_cross_server

CFG = Path("/tmp/agent-a.json")


def _srv(name: str, command: str = "npx", args: list[str] | None = None, **kw) -> MCPServer:
    kw.setdefault("source_file", CFG)
    return MCPServer(name=name, command=command, args=args or [], **kw)


def _ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


def test_trifecta_is_high():
    servers = [
        _srv("files", args=["-y", "@modelcontextprotocol/server-filesystem", "/srv/project"]),
        _srv("web", args=["mcp-server-fetch"]),
    ]
    findings = [f for f in check_cross_server(servers) if f.rule_id == "XSV-001"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "untrusted" in findings[0].message


def test_private_plus_egress_without_untrusted_is_medium():
    servers = [_srv("db", args=["mcp-server-sqlite"]), _srv("notify", args=["server-smtp"])]
    findings = [f for f in check_cross_server(servers) if f.rule_id == "XSV-001"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_remote_server_counts_as_egress_but_localhost_does_not():
    remote = _srv("analytics", transport=Transport.HTTP, url="https://api.example.com/mcp")
    local = _srv("analytics", transport=Transport.HTTP, url="http://localhost:3000/mcp")
    db = _srv("db", args=["mcp-server-sqlite"])
    assert "XSV-001" in _ids(check_cross_server([db, remote]))
    assert "XSV-001" not in _ids(check_cross_server([db, local]))


def test_untrusted_content_next_to_exec():
    servers = [_srv("browser", args=["@playwright/mcp"]), _srv("term", args=["shell-server"])]
    findings = [f for f in check_cross_server(servers) if f.rule_id == "XSV-002"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_launcher_command_alone_is_not_exec():
    servers = [_srv("browser", args=["@playwright/mcp"]), _srv("notes", command="bash", args=["./notes.sh"])]
    assert "XSV-002" not in _ids(check_cross_server(servers))


def test_shared_secret_detected_and_value_never_reported():
    secret = "sk-live-0123456789abcdef"
    servers = [_srv("a", env={"API_KEY": secret}), _srv("b", env={"TOKEN": secret})]
    findings = [f for f in check_cross_server(servers) if f.rule_id == "XSV-003"]
    assert len(findings) == 1
    blob = " ".join([findings[0].message, findings[0].evidence, findings[0].remediation, findings[0].server_name])
    assert secret not in blob
    assert "a.API_KEY" in findings[0].evidence and "b.TOKEN" in findings[0].evidence


def test_env_references_and_short_values_are_not_shared_secrets():
    servers = [_srv("a", env={"K": "${API_KEY}"}), _srv("b", env={"K": "${API_KEY}"})]
    assert "XSV-003" not in _ids(check_cross_server(servers))
    servers = [_srv("a", env={"MODE": "prod"}), _srv("b", env={"MODE": "prod"})]
    assert "XSV-003" not in _ids(check_cross_server(servers))


def test_name_shadowing_detected():
    servers = [_srv("filesystem"), _srv("file-system"), _srv("filesytem")]
    findings = [f for f in check_cross_server(servers) if f.rule_id == "XSV-004"]
    assert len(findings) == 3


def test_unrelated_names_are_not_shadowing():
    assert "XSV-004" not in _ids(check_cross_server([_srv("github"), _srv("postgres")]))


def test_different_config_files_are_isolated():
    a = _srv("files", args=["server-filesystem"], source_file=Path("/tmp/a.json"))
    b = _srv("web", args=["mcp-server-fetch"], source_file=Path("/tmp/b.json"))
    assert check_cross_server([a, b]) == []


def test_single_server_never_triggers():
    assert check_cross_server([_srv("files", args=["server-filesystem"])]) == []


def test_engine_includes_cross_server_findings():
    servers = [_srv("files", args=["server-filesystem", "/srv/p"]), _srv("web", args=["mcp-server-fetch"])]
    assert "XSV-001" in _ids(scan(servers, analyze_source=False).findings)
