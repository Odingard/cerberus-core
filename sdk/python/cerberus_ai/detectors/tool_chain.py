"""
cerberus_ai.detectors.tool_chain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Multi-Hop Tool Chain Detector -- Sub-classifier enhancing L3.

Detects exfiltration broken across multiple tool calls in a session,
where data flows through a chain: read(DB) -> transform(data) -> send(external).

Fires when a tool call sequence contains:
  1. A data-read tool (while L1 was active -- privilegedValues populated)
  2. Any transformation step
  3. An outbound tool

This catches staged exfiltration where no single tool call looks malicious
but the overall chain constitutes data theft.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal

# ── Tool name patterns indicating data reads ─────────────────────────────────

DATA_READ_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"read", re.I),
    re.compile(r"fetch", re.I),
    re.compile(r"get", re.I),
    re.compile(r"query", re.I),
    re.compile(r"lookup", re.I),
    re.compile(r"search", re.I),
    re.compile(r"find", re.I),
    re.compile(r"select", re.I),
    re.compile(r"load", re.I),
    re.compile(r"retrieve", re.I),
    re.compile(r"list", re.I),
]

# ── Tool name patterns indicating data transformation ─────────────────────────

TRANSFORM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"transform", re.I),
    re.compile(r"convert", re.I),
    re.compile(r"format", re.I),
    re.compile(r"parse", re.I),
    re.compile(r"encode", re.I),
    re.compile(r"compress", re.I),
    re.compile(r"summarize", re.I),
    re.compile(r"extract", re.I),
    re.compile(r"filter", re.I),
    re.compile(r"map", re.I),
    re.compile(r"process", re.I),
    re.compile(r"aggregate", re.I),
    re.compile(r"merge", re.I),
    re.compile(r"prepare", re.I),
]

# ── Tool name patterns indicating outbound/send actions ───────────────────────

OUTBOUND_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"send", re.I),
    re.compile(r"post", re.I),
    re.compile(r"upload", re.I),
    re.compile(r"email", re.I),
    re.compile(r"forward", re.I),
    re.compile(r"export", re.I),
    re.compile(r"push", re.I),
    re.compile(r"transmit", re.I),
    re.compile(r"deliver", re.I),
    re.compile(r"submit", re.I),
    re.compile(r"write.*external", re.I),
]

ToolRole = Literal["read", "transform", "outbound", "unknown"]


def classify_tool_role(
    tool_name: str,
    outbound_tools: Sequence[str],
) -> ToolRole:
    """Classify a tool name into a chain role."""
    # Explicit outbound tools take priority
    if tool_name in outbound_tools:
        return "outbound"

    for pattern in OUTBOUND_PATTERNS:
        if pattern.search(tool_name):
            return "outbound"

    # Transform checked before read -- prevents false classification
    # when tool names contain read-pattern substrings (e.g. "encodePayload" has "load")
    for pattern in TRANSFORM_PATTERNS:
        if pattern.search(tool_name):
            return "transform"

    for pattern in DATA_READ_PATTERNS:
        if pattern.search(tool_name):
            return "read"

    return "unknown"


class ToolChainEntry:
    """A single entry in the tool call history for chain detection."""

    __slots__ = ("tool_name", "turn_id")

    def __init__(self, tool_name: str, turn_id: str) -> None:
        self.tool_name = tool_name
        self.turn_id = turn_id


class MultiHopSignal:
    """Signal emitted when a multi-hop exfiltration chain is detected."""

    __slots__ = ("layer", "signal", "turn_id", "chain_tools", "chain_length", "timestamp")

    def __init__(
        self,
        turn_id: str,
        chain_tools: list[str],
        chain_length: int,
        timestamp: int,
    ) -> None:
        self.layer = "L3"
        self.signal = "MULTI_HOP_EXFILTRATION"
        self.turn_id = turn_id
        self.chain_tools = chain_tools
        self.chain_length = chain_length
        self.timestamp = timestamp


def detect_tool_chain_exfiltration(
    tool_name: str,
    turn_id: str,
    timestamp: int,
    tool_call_history: Sequence[ToolChainEntry],
    privileged_values_count: int,
    outbound_tools: Sequence[str],
) -> MultiHopSignal | None:
    """
    Detect multi-hop exfiltration chains in the session's tool call history.

    Scans the session tool call history for the pattern:
      read -> [transform]* -> outbound

    Only fires if L1 was active (privileged_values_count > 0) during the
    session, indicating sensitive data was accessed.

    Args:
        tool_name: Current tool being called.
        turn_id: Current turn identifier.
        timestamp: Current timestamp in milliseconds.
        tool_call_history: Prior tool calls in this session.
        privileged_values_count: Number of privileged values in session (L1 gate).
        outbound_tools: Explicit list of outbound tool names.

    Returns:
        MultiHopSignal if chain detected, None otherwise.
    """
    # Gate: only fire if current tool is outbound (chain completion point)
    current_role = classify_tool_role(tool_name, outbound_tools)
    if current_role != "outbound":
        return None

    # Gate: L1 must have been active (privileged data accessed this session)
    if privileged_values_count == 0:
        return None

    # Gate: need at least 2 prior tool calls to form a chain
    if len(tool_call_history) < 2:
        return None

    # Scan history for the read -> [transform] -> outbound pattern
    has_read = False
    has_transform = False
    chain_tools: list[str] = []

    for entry in tool_call_history:
        role = classify_tool_role(entry.tool_name, outbound_tools)
        if role == "read":
            has_read = True
            chain_tools.append(entry.tool_name)
        elif role == "transform" and has_read:
            has_transform = True
            chain_tools.append(entry.tool_name)

    # The current outbound call completes the chain -- require read + transform
    if not has_read or not has_transform:
        return None

    chain_tools.append(tool_name)

    return MultiHopSignal(
        turn_id=turn_id,
        chain_tools=chain_tools,
        chain_length=len(chain_tools),
        timestamp=timestamp,
    )
