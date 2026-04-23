"""
cerberus_ai.discover
~~~~~~~~~~~~~~~~~~~~

Auto-discovery for Cerberus — v1.4 Delta #1.

The ``cerberus discover`` CLI statically scans a repository for every
LLM call site, tool registration, and MCP server manifest, then writes
a signed JSON report. Security teams use it to answer the question
Cerberus could not previously answer on its own:

    "Where are all my LLM call sites, and which ones are already
     protected by Cerberus?"

Primary entrypoints:

* :class:`~cerberus_ai.discover.schema.DiscoveryReport`
* :func:`~cerberus_ai.discover.static.scan_repo`
* :mod:`cerberus_ai.discover.cli` (the ``cerberus`` console script)
"""
from __future__ import annotations

from cerberus_ai.discover.schema import (
    CallSite,
    CoverageSummary,
    DiscoveryReport,
    MCPServer,
)
from cerberus_ai.discover.static import scan_repo

__all__ = [
    "CallSite",
    "CoverageSummary",
    "DiscoveryReport",
    "MCPServer",
    "scan_repo",
]
