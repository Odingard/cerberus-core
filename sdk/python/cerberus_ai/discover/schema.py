"""
Data model for :mod:`cerberus_ai.discover`.

The shapes here are load-bearing: the JSON serialisation is consumed by
dashboards, CI gates, and the forthcoming ``cerberus coverage`` sub-command.
Keep field names in sync with the v1.4 spec §2.1.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

Framework = Literal[
    "openai",
    "anthropic",
    "google",
    "langchain",
    "langgraph",
    "crewai",
    "llamaindex",
    "autogen",
    "mcp-client",
    "unknown",
]


@dataclass(frozen=True)
class CallSite:
    """A single location in the tree that invokes an LLM or instantiates
    an agent framework.

    ``wrapped_by_cerberus`` is ``True`` when the same file (or a file
    that imports it) instantiates ``cerberus_ai.Cerberus``. It is a
    best-effort static signal — not a runtime proof of coverage.
    """

    file: str
    line: int
    framework: Framework
    symbol: str
    model_family: str | None = None
    wrapped_by_cerberus: bool = False
    tools_registered: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "framework": self.framework,
            "symbol": self.symbol,
            "model_family": self.model_family,
            "wrapped_by_cerberus": self.wrapped_by_cerberus,
            "tools_registered": list(self.tools_registered),
        }


@dataclass(frozen=True)
class MCPServer:
    """An MCP server registration discovered in a client config.

    ``config_path`` is the file the registration lives in (e.g.
    ``~/.config/Claude/claude_desktop_config.json``,
    ``.cursor/mcp.json``). ``tool_count`` is populated only when the
    manifest itself lists tools; runtime tool-listing is out of scope
    for the static scanner.
    """

    name: str
    config_path: str
    command: str | None = None
    args: tuple[str, ...] = ()
    tool_count: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "config_path": self.config_path,
            "command": self.command,
            "args": list(self.args),
            "tool_count": self.tool_count,
        }


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate coverage over all discovered call sites."""

    total_call_sites: int
    wrapped: int
    unwrapped: int

    @property
    def coverage_pct(self) -> float:
        if self.total_call_sites == 0:
            return 0.0
        return round(100.0 * self.wrapped / self.total_call_sites, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_call_sites": self.total_call_sites,
            "wrapped": self.wrapped,
            "unwrapped": self.unwrapped,
            "coverage_pct": self.coverage_pct,
        }


@dataclass
class DiscoveryReport:
    """Top-level report emitted by :func:`scan_repo`.

    The schema is stable; unknown fields are ignored by downstream
    consumers so new detectors can be added without a version bump.
    """

    root: str
    scan_id: str
    generated_at: str
    call_sites: list[CallSite] = field(default_factory=list)
    mcp_servers: list[MCPServer] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> CoverageSummary:
        wrapped = sum(1 for c in self.call_sites if c.wrapped_by_cerberus)
        total = len(self.call_sites)
        return CoverageSummary(
            total_call_sites=total,
            wrapped=wrapped,
            unwrapped=total - wrapped,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "root": self.root,
            "call_sites": [c.to_dict() for c in self.call_sites],
            "mcp_servers": [m.to_dict() for m in self.mcp_servers],
            "coverage": self.coverage.to_dict(),
            "errors": list(self.errors),
        }

    @staticmethod
    def new(root: str) -> DiscoveryReport:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return DiscoveryReport(
            root=root,
            scan_id=f"disc-{now}",
            generated_at=now,
        )
