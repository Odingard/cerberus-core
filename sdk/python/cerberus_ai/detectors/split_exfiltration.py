"""
cerberus_ai.detectors.split_exfiltration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Split Exfiltration Detector -- Sub-classifier enhancing L3.

Detects data exfiltration split across multiple outbound tool calls.
Attackers may chunk sensitive data into small pieces sent via separate
calls to avoid triggering single-call detection thresholds.

Fires when:
  1. Cumulative outbound volume exceeds a configurable threshold (default 10KB)
  2. At least 3 outbound calls have been made
  3. L1 was active (privileged data accessed this session)

Also detects repeated calls to the same outbound tool with sequential
data patterns (e.g., page=1, page=2, offset=0, offset=100).
"""
from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_SPLIT_EXFIL_THRESHOLD_BYTES = 10240
MIN_OUTBOUND_CALLS = 3

# ── Sequential arg key patterns ───────────────────────────────────────────────

SEQUENTIAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"page", re.I),
    re.compile(r"offset", re.I),
    re.compile(r"chunk", re.I),
    re.compile(r"part", re.I),
    re.compile(r"segment", re.I),
    re.compile(r"batch", re.I),
    re.compile(r"index", re.I),
    re.compile(r"seq", re.I),
    re.compile(r"sequence", re.I),
    re.compile(r"block", re.I),
]


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class OutboundCallRecord:
    """Metadata for a single outbound call in the session."""

    tool_name: str
    byte_size: int
    numeric_args: list[int | float] = field(default_factory=list)
    turn_id: str = ""


@dataclass
class SplitExfilSession:
    """
    Mutable session state for split exfiltration tracking.

    Maintained by the inspector across turns. Stores cumulative bytes
    and outbound call records.
    """

    outbound_records: list[OutboundCallRecord] = field(default_factory=list)
    cumulative_bytes: int = 0


class SplitExfiltrationSignal:
    """Signal emitted when split exfiltration pattern is detected."""

    __slots__ = (
        "layer",
        "signal",
        "turn_id",
        "outbound_call_count",
        "cumulative_bytes",
        "sequential_pattern",
        "timestamp",
    )

    def __init__(
        self,
        turn_id: str,
        outbound_call_count: int,
        cumulative_bytes: int,
        timestamp: int,
        sequential_pattern: bool = False,
    ) -> None:
        self.layer = "L3"
        self.signal = "SPLIT_EXFILTRATION"
        self.turn_id = turn_id
        self.outbound_call_count = outbound_call_count
        self.cumulative_bytes = cumulative_bytes
        self.sequential_pattern = sequential_pattern
        self.timestamp = timestamp


def _serialize_arguments(args: dict[str, Any]) -> str:
    """Serialize tool arguments to a single string."""
    try:
        return json.dumps(args, default=str)
    except (TypeError, ValueError):
        return str(args)


def _extract_sequential_indicators(args: dict[str, Any]) -> list[int | float]:
    """Extract numeric argument values that may indicate sequential data patterns."""
    numerics: list[int | float] = []

    for key, value in args.items():
        if not isinstance(value, (int, float)):
            continue
        for pattern in SEQUENTIAL_PATTERNS:
            if pattern.search(key):
                numerics.append(value)
                break

    return numerics


def _has_sequential_pattern(records: Sequence[OutboundCallRecord]) -> bool:
    """Check if numeric values across calls form a sequential pattern."""
    if len(records) < 2:
        return False

    # Group by tool name
    by_tool: dict[str, list[float]] = {}
    for rec in records:
        for num in rec.numeric_args:
            by_tool.setdefault(rec.tool_name, []).append(float(num))

    # Check for sequential patterns in any tool group
    for nums in by_tool.values():
        if len(nums) < 2:
            continue
        sorted_nums = sorted(nums)

        # Check for consistent increments
        increment = sorted_nums[1] - sorted_nums[0]
        if increment <= 0:
            continue

        is_sequential = True
        for i in range(2, len(sorted_nums)):
            if sorted_nums[i] - sorted_nums[i - 1] != increment:
                is_sequential = False
                break
        if is_sequential:
            return True

    return False


def detect_split_exfiltration(
    tool_name: str,
    tool_arguments: dict[str, Any],
    turn_id: str,
    timestamp: int,
    privileged_values_count: int,
    outbound_tools: Sequence[str],
    session: SplitExfilSession,
    threshold_bytes: int | None = None,
) -> SplitExfiltrationSignal | None:
    """
    Detect split exfiltration across multiple outbound tool calls.

    Tracks cumulative outbound volume and call frequency. Fires when
    the pattern suggests data is being chunked across multiple calls.

    Args:
        tool_name: Name of the tool being called.
        tool_arguments: Arguments passed to the tool.
        turn_id: Current turn identifier.
        timestamp: Current timestamp in milliseconds.
        privileged_values_count: Number of privileged values (L1 gate).
        outbound_tools: Explicit list of outbound tool names.
        session: Mutable session state for tracking outbound calls.
        threshold_bytes: Cumulative byte threshold (default 10KB).

    Returns:
        SplitExfiltrationSignal if split pattern detected, None otherwise.
    """
    # Gate: only runs for outbound tools
    if tool_name not in outbound_tools:
        return None

    # Gate: L1 must have been active (privileged data in session)
    if privileged_values_count == 0:
        return None

    effective_threshold = (
        threshold_bytes if threshold_bytes is not None
        else DEFAULT_SPLIT_EXFIL_THRESHOLD_BYTES
    )

    # Compute current call metrics
    current_arg_text = _serialize_arguments(tool_arguments)
    current_bytes = len(current_arg_text.encode("utf-8"))
    current_numerics = _extract_sequential_indicators(tool_arguments)

    # Update session state
    session.cumulative_bytes += current_bytes
    current_record = OutboundCallRecord(
        tool_name=tool_name,
        byte_size=current_bytes,
        numeric_args=current_numerics,
        turn_id=turn_id,
    )
    session.outbound_records.append(current_record)

    outbound_call_count = len(session.outbound_records)

    # Detection path 1: volume + frequency threshold
    volume_exceeded = (
        session.cumulative_bytes >= effective_threshold
        and outbound_call_count >= MIN_OUTBOUND_CALLS
    )

    # Detection path 2: sequential data patterns (lower threshold)
    sequential_detected = (
        outbound_call_count >= 2
        and _has_sequential_pattern(session.outbound_records)
    )

    if not volume_exceeded and not sequential_detected:
        return None

    return SplitExfiltrationSignal(
        turn_id=turn_id,
        outbound_call_count=outbound_call_count,
        cumulative_bytes=session.cumulative_bytes,
        sequential_pattern=sequential_detected,
        timestamp=timestamp,
    )
