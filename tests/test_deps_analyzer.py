"""Tests for the dependency manifest analyzer — requirements.txt + package.json."""

from __future__ import annotations

from pathlib import Path

from canlix.analyzers import analyze_path
from canlix.analyzers.deps import analyze_package_json, analyze_requirements
from canlix.models import Severity

FIXTURES = Path(__file__).parent / "fixtures" / "deps"


# ── Helpers ────────────────────────────────────────────────────────────────


def _req(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text(content)
    return p


def _pkg(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "package.json"
    p.write_text(content)
    return p


# ── DEP-001: unpinned requirements.txt ─────────────────────────────────────


def test_DEP001_detects_bare_package_name(tmp_path):
    p = _req(tmp_path, "requests\n")
    findings = analyze_requirements(p)
    assert any(f.rule_id == "DEP-001" and f.severity == Severity.MEDIUM for f in findings)


def test_DEP001_detects_range_only(tmp_path):
    p = _req(tmp_path, "fastapi>=0.100.0\n")
    findings = analyze_requirements(p)
    assert any(f.rule_id == "DEP-001" for f in findings)


def test_DEP001_detects_package_with_extras_unpinned(tmp_path):
    p = _req(tmp_path, "requests[security]\n")
    findings = analyze_requirements(p)
    assert any(f.rule_id == "DEP-001" for f in findings)


def test_DEP001_passes_exact_pin(tmp_path):
    p = _req(tmp_path, "requests==2.31.0\n")
    findings = analyze_requirements(p)
    assert not any(f.rule_id == "DEP-001" for f in findings)


def test_DEP001_passes_exact_pin_with_extras(tmp_path):
    p = _req(tmp_path, "requests[security]==2.31.0\n")
    findings = analyze_requirements(p)
    assert not any(f.rule_id == "DEP-001" for f in findings)


def test_DEP001_skips_comments(tmp_path):
    p = _req(tmp_path, "# requests — no version needed\n")
    findings = analyze_requirements(p)
    assert not findings


def test_DEP001_skips_blank_lines(tmp_path):
    p = _req(tmp_path, "\n\n   \n")
    findings = analyze_requirements(p)
    assert not findings


def test_DEP001_skips_flag_lines(tmp_path):
    p = _req(tmp_path, "-r base.txt\n--index-url https://pypi.org/simple\n")
    findings = analyze_requirements(p)
    assert not findings


def test_DEP001_skips_vcs_urls(tmp_path):
    p = _req(tmp_path, "git+https://github.com/example/pkg.git@main\n")
    findings = analyze_requirements(p)
    assert not findings


def test_DEP001_line_number_accuracy(tmp_path):
    p = _req(tmp_path, "requests==2.31.0\nhttpx\nfastapi==0.111.0\n")
    findings = analyze_requirements(p)
    dep001 = [f for f in findings if f.rule_id == "DEP-001"]
    assert len(dep001) == 1
    assert dep001[0].line_number == 2
    assert "httpx" in dep001[0].code_snippet


# ── DEP-002: fully-unpinned package.json ───────────────────────────────────


def test_DEP002_detects_star_version(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"axios": "*"}}')
    findings = analyze_package_json(p)
    assert any(f.rule_id == "DEP-002" and f.severity == Severity.HIGH for f in findings)


def test_DEP002_detects_latest(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"express": "latest"}}')
    findings = analyze_package_json(p)
    assert any(f.rule_id == "DEP-002" and f.severity == Severity.HIGH for f in findings)


def test_DEP002_detects_empty_string(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"pkg": ""}}')
    findings = analyze_package_json(p)
    assert any(f.rule_id == "DEP-002" for f in findings)


# ── DEP-003: range-pinned package.json ─────────────────────────────────────


def test_DEP003_detects_caret_range(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"express": "^4.19.2"}}')
    findings = analyze_package_json(p)
    assert any(f.rule_id == "DEP-003" and f.severity == Severity.MEDIUM for f in findings)


def test_DEP003_detects_gte_range(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"typescript": ">=5.0.0"}}')
    findings = analyze_package_json(p)
    assert any(f.rule_id == "DEP-003" for f in findings)


def test_DEP003_detects_tilde_range(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"lodash": "~4.17.0"}}')
    findings = analyze_package_json(p)
    assert any(f.rule_id == "DEP-003" for f in findings)


def test_DEP003_passes_exact_semver(tmp_path):
    p = _pkg(tmp_path, '{"dependencies": {"axios": "1.7.2"}}')
    findings = analyze_package_json(p)
    assert not any(f.rule_id in ("DEP-002", "DEP-003") for f in findings)


def test_DEP003_passes_devDependencies_exact(tmp_path):
    p = _pkg(tmp_path, '{"devDependencies": {"jest": "29.7.0"}}')
    findings = analyze_package_json(p)
    assert not findings


def test_package_json_handles_malformed_json(tmp_path):
    p = _pkg(tmp_path, "not valid json {{{")
    findings = analyze_package_json(p)
    assert findings == []


# ── Integration: fixture files ──────────────────────────────────────────────


def test_requirements_pinned_fixture_no_findings():
    findings = analyze_requirements(FIXTURES / "requirements_pinned.txt")
    assert findings == []


def test_requirements_unpinned_fixture_has_findings():
    findings = analyze_requirements(FIXTURES / "requirements_unpinned.txt")
    rule_ids = {f.rule_id for f in findings}
    assert "DEP-001" in rule_ids
    # httpx and pydantic are unpinned; fastapi has only >=
    assert len(findings) == 3


def test_package_safe_fixture_no_findings():
    findings = analyze_package_json(FIXTURES / "package_safe.json")
    assert findings == []


def test_package_risky_fixture_has_findings():
    findings = analyze_package_json(FIXTURES / "package_risky.json")
    rule_ids = {f.rule_id for f in findings}
    assert "DEP-002" in rule_ids  # * and latest
    assert "DEP-003" in rule_ids  # ^ and >=


# ── analyze_path picks up manifest files ───────────────────────────────────


def test_analyze_path_picks_up_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx\nrequests==2.31.0\n")
    findings = analyze_path(tmp_path)
    assert any(f.rule_id == "DEP-001" for f in findings)


def test_analyze_path_picks_up_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"axios": "*"}}')
    findings = analyze_path(tmp_path)
    assert any(f.rule_id == "DEP-002" for f in findings)


def test_analyze_path_skips_node_modules_package_json(tmp_path):
    nm = tmp_path / "node_modules" / "axios"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"dependencies": {"lodash": "*"}}')
    findings = analyze_path(tmp_path)
    assert not any(f.rule_id in ("DEP-002", "DEP-003") for f in findings)
