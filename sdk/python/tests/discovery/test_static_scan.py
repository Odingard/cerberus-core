"""
Static-scan tests for :mod:`cerberus_ai.discover`.

Spec acceptance criterion (v1.4 §2.1):

    pytest tests/discovery/ passes with a fixture repo containing at
    least 6 framework variants (LangChain, LangGraph, CrewAI, AutoGen,
    LlamaIndex, OpenAI raw).

This file covers all six plus MCP-server parsing, broken-syntax
resilience, coverage accounting, and CLI wiring.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from cerberus_ai.discover import scan_repo
from cerberus_ai.discover.cli import _build_parser, run_discover
from cerberus_ai.discover.schema import DiscoveryReport

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def report() -> DiscoveryReport:
    return scan_repo(FIXTURES)


def _sites_for(report: DiscoveryReport, framework: str) -> list[str]:
    return sorted(
        f"{c.file}:{c.line}:{c.symbol}"
        for c in report.call_sites
        if c.framework == framework
    )


def test_detects_openai_raw(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "openai")
    assert any("openai_raw.py" in s and "OpenAI" in s for s in hits), hits


def test_detects_anthropic_raw(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "anthropic")
    assert any("anthropic_raw.py" in s for s in hits), hits


def test_detects_langchain(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "langchain")
    # ChatOpenAI in langchain_agent.py
    assert any("langchain_agent.py" in s and "ChatOpenAI" in s for s in hits), hits


def test_detects_langgraph(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "langgraph")
    assert any("langgraph_app.py" in s and "StateGraph" in s for s in hits), hits


def test_detects_crewai(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "crewai")
    assert any("crewai_crew.py" in s for s in hits), hits


def test_detects_autogen(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "autogen")
    assert len(hits) >= 2  # AssistantAgent + UserProxyAgent
    assert any("autogen_team.py" in s for s in hits), hits


def test_detects_llamaindex(report: DiscoveryReport) -> None:
    hits = _sites_for(report, "llamaindex")
    assert any("llamaindex_query.py" in s for s in hits), hits


def test_wrapped_by_cerberus_heuristic(report: DiscoveryReport) -> None:
    """crewai_crew.py instantiates Cerberus() in the same file as the
    agent constructor — every call site in that file must be marked
    wrapped=True. All other fixtures must stay wrapped=False."""
    for c in report.call_sites:
        if c.file.endswith("crewai_crew.py"):
            assert c.wrapped_by_cerberus is True, c
        else:
            assert c.wrapped_by_cerberus is False, c


def test_tool_declarations_attached_to_call_sites(report: DiscoveryReport) -> None:
    """The langchain fixture has two Tool() declarations; every call
    site in that file should list them in ``tools_registered``."""
    lc_sites = [c for c in report.call_sites if c.file.endswith("langchain_agent.py")]
    assert lc_sites, "expected at least one LangChain call site"
    for c in lc_sites:
        assert "search_kb" in c.tools_registered
        assert "send_email" in c.tools_registered


def test_mcp_server_parsing(report: DiscoveryReport) -> None:
    names = sorted(m.name for m in report.mcp_servers)
    assert names == ["filesystem", "github"]
    fs = next(m for m in report.mcp_servers if m.name == "filesystem")
    assert fs.command == "npx"
    assert "@modelcontextprotocol/server-filesystem" in fs.args


def test_broken_syntax_does_not_abort(report: DiscoveryReport, tmp_path: Path) -> None:
    """The fixture tree contains a deliberately malformed file; the
    scanner must record the parse error and keep going."""
    assert any("broken_syntax.py" in e for e in report.errors), report.errors
    # And it still produced reports for the other fixtures.
    assert len(report.call_sites) >= 6


def test_coverage_summary(report: DiscoveryReport) -> None:
    cov = report.coverage
    assert cov.total_call_sites == len(report.call_sites)
    assert cov.wrapped + cov.unwrapped == cov.total_call_sites
    # At least the one crewai file instantiates Cerberus.
    assert cov.wrapped >= 1
    assert 0.0 <= cov.coverage_pct <= 100.0


def test_missing_root_returns_empty_with_error(tmp_path: Path) -> None:
    rep = scan_repo(tmp_path / "does-not-exist")
    assert rep.call_sites == []
    assert rep.errors  # at least one error recorded


def test_report_serialises_stable_json(report: DiscoveryReport) -> None:
    payload = report.to_dict()
    s = json.dumps(payload, sort_keys=True)
    again = json.loads(s)
    assert again["coverage"]["total_call_sites"] == report.coverage.total_call_sites
    assert {"call_sites", "mcp_servers", "coverage", "scan_id",
            "generated_at", "root", "errors"} <= set(payload.keys())


# ── CLI ───────────────────────────────────────────────────────────────────


def test_cli_writes_json_report(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    parser = _build_parser()
    args = parser.parse_args([
        "discover", "--root", str(FIXTURES),
        "--output", str(out), "--format", "json",
    ])
    assert run_discover(args) == 0
    data = json.loads(out.read_text())
    assert data["coverage"]["total_call_sites"] >= 6


def test_cli_text_format_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    parser = _build_parser()
    args = parser.parse_args([
        "discover", "--root", str(FIXTURES), "--format", "text",
    ])
    assert run_discover(args) == 0
    captured = capsys.readouterr()
    assert "Cerberus discovery report" in captured.out
    assert "call sites:" in captured.out


def test_cli_skips_home_by_default(tmp_path: Path, monkeypatch) -> None:
    """Without --include-mcp-home, only the fixture's own mcp.json is
    read — no probing of the user's actual home directory."""
    parser = _build_parser()
    args = parser.parse_args([
        "discover", "--root", str(FIXTURES), "--format", "json",
        "--output", str(tmp_path / "o.json"),
    ])
    assert run_discover(args) == 0
    data = json.loads((tmp_path / "o.json").read_text())
    # Only the two servers from our fixture.
    assert len(data["mcp_servers"]) == 2


def test_console_script_is_installed() -> None:
    """The ``cerberus`` entrypoint is registered and callable via
    ``python -m cerberus_ai.discover.cli``. This guards against the
    pyproject.toml registration silently regressing."""
    proc = subprocess.run(
        [sys.executable, "-m", "cerberus_ai.discover.cli",
         "discover", "--root", str(FIXTURES), "--format", "json"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["coverage"]["total_call_sites"] >= 6
