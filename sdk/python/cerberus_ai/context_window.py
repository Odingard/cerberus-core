"""
cerberus_ai.context_window
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Context Window Manager -- Handles large RAG payloads.

When content exceeds the configured context window limit, segments are
scored by entropy, structural patterns, and position. High-priority
regions (system prompts, tool schemas, tool results) are always inspected.
Runs BEFORE the L1/L2/L3 detection pipeline in the interceptor.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Literal

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_CONTEXT_WINDOW_LIMIT = 32000
SEGMENT_SIZE = 512  # approximate tokens per segment

RegionType = Literal["system-prompt", "tool-schema", "tool-result", "general"]

# ── Structural patterns that increase a segment's priority score ──────────────

_STRUCTURAL_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r"https?://\S+"), 0.3),           # URLs
    (re.compile(r"\S+@\S+\.\S+"), 0.3),           # Email addresses
    (re.compile(r"<(?:SYSTEM|IMPORTANT|ADMIN|OVERRIDE)", re.I), 0.5),  # Authority tags
    (re.compile(r"ignore\s+(?:previous|all|prior)", re.I), 0.5),       # Injection
    (re.compile(r"(?:api[_\-]?key|password|secret|token)\s*[:=]", re.I), 0.4),  # Creds
    (re.compile(r"base64|atob|btoa|decode", re.I), 0.3),              # Encoding markers
    (re.compile(r"\b(?:ssn|social.security|credit.card)\b", re.I), 0.4),  # PII markers
]


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ContentSegment:
    """A scored segment of content."""

    text: str
    index: int
    score: float
    region: RegionType
    inspected: bool


@dataclass(frozen=True)
class ContextOverflowSignal:
    """Signal emitted when context window is exceeded."""

    layer: str = "L1"
    signal: str = "CONTEXT_OVERFLOW"
    turn_id: str = ""
    total_tokens: int = 0
    limit: int = 0
    segments_inspected: int = 0
    segments_dropped: int = 0
    overflow_action: str = "partial-scan"
    timestamp: int = 0


@dataclass
class AlwaysInspectRegions:
    """Configuration for which regions to always inspect."""

    system_prompts: bool = True
    tool_schemas: bool = True
    tool_results: bool = True


@dataclass
class ContextWindowResult:
    """Result of context window analysis."""

    overflow: bool
    total_tokens: int
    limit: int
    inspected_segments: list[ContentSegment] = field(default_factory=list)
    dropped_segments: list[ContentSegment] = field(default_factory=list)
    inspected_content: str = ""
    signal: ContextOverflowSignal | None = None
    blocked: bool = False


# ── Pure functions ────────────────────────────────────────────────────────────


def estimate_tokens(text: str) -> int:
    """
    Estimate token count from text.
    Uses a simple ~4 chars per token heuristic (GPT-style approximation).
    """
    if len(text) == 0:
        return 0
    return math.ceil(len(text) / 4)


def compute_entropy(text: str) -> float:
    """
    Compute Shannon entropy of a text segment.
    Higher entropy may indicate encoded/compressed/obfuscated content.
    """
    if len(text) == 0:
        return 0.0

    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def score_segment(text: str, index: int, total_segments: int) -> float:
    """
    Score a text segment by entropy, structural patterns, and position.

    Returns a score in [0, 1] where higher means more important to inspect.
    """
    # Entropy component (normalized to 0-1, typical text entropy is 3-5 bits)
    entropy = compute_entropy(text)
    entropy_score = min(entropy / 6, 1.0) * 0.3

    # Structural pattern component
    structural_score = 0.0
    for pattern, weight in _STRUCTURAL_PATTERNS:
        if pattern.search(text):
            structural_score += weight
    structural_score = min(structural_score, 1.0) * 0.4

    # Position component: first and last segments are higher priority
    position_score = 0.0
    if total_segments > 1:
        normalized_pos = index / (total_segments - 1)
        # U-shaped: high at start and end, lower in middle
        if 1 - 4 * (normalized_pos - 0.5) ** 2 > 0.5:
            position_score = 0.2
        else:
            position_score = 0.3 * (1 - min(normalized_pos, 1 - normalized_pos) * 2)
    else:
        position_score = 0.3

    return min(entropy_score + structural_score + position_score, 1.0)


def classify_region(text: str) -> RegionType:
    """Classify a text segment into a region based on content heuristics."""
    lower = text.lower()

    if any(
        marker in lower
        for marker in ("system:", "system prompt", "<system>", "you are a")
    ):
        return "system-prompt"

    if any(
        marker in lower
        for marker in (
            '"parameters"',
            '"type": "object"',
            '"properties"',
            "tool_schema",
            "function_definition",
        )
    ):
        return "tool-schema"

    if any(
        marker in lower
        for marker in ("tool_result", "tool result", "function_result", "observation:")
    ):
        return "tool-result"

    return "general"


def _should_always_inspect(
    region: RegionType,
    config: AlwaysInspectRegions,
) -> bool:
    """Determine whether a region should always be inspected."""
    if region == "system-prompt":
        return config.system_prompts
    if region == "tool-schema":
        return config.tool_schemas
    if region == "tool-result":
        return config.tool_results
    return False


def split_into_segments(text: str) -> list[str]:
    """Split text into segments of approximately SEGMENT_SIZE tokens each."""
    chars_per_segment = SEGMENT_SIZE * 4  # ~4 chars per token
    segments: list[str] = []

    for i in range(0, len(text), chars_per_segment):
        segments.append(text[i : i + chars_per_segment])

    if len(segments) == 0:
        segments.append("")

    return segments


def analyze_context_window(
    content: str,
    turn_id: str,
    context_window_limit: int | None = None,
    overflow_action: str = "partial-scan",
    always_inspect_regions: AlwaysInspectRegions | None = None,
) -> ContextWindowResult:
    """
    Analyze content against the context window limit.

    When content exceeds the limit:
    1. Split into ~512-token segments
    2. Score each segment by entropy + structural patterns + position
    3. Always-inspect regions are kept regardless of limit
    4. Remaining budget is filled by highest-scoring segments
    5. Emits CONTEXT_OVERFLOW signal with inspection metadata

    Args:
        content: The full content to analyze.
        turn_id: Current turn identifier.
        context_window_limit: Token limit (default 32000).
        overflow_action: Either "partial-scan" or "block".
        always_inspect_regions: Config for always-inspected regions.

    Returns:
        ContextWindowResult with inspected/dropped segments and overflow signal.
    """
    limit = (
        context_window_limit
        if context_window_limit is not None
        else DEFAULT_CONTEXT_WINDOW_LIMIT
    )
    inspect_config = always_inspect_regions or AlwaysInspectRegions()
    total_tokens = estimate_tokens(content)
    now_ms = int(time.time() * 1000)

    # No overflow -- inspect everything
    if total_tokens <= limit:
        raw_segments = split_into_segments(content)
        segments = [
            ContentSegment(
                text=text,
                index=i,
                score=score_segment(text, i, len(raw_segments)),
                region=classify_region(text),
                inspected=True,
            )
            for i, text in enumerate(raw_segments)
        ]

        return ContextWindowResult(
            overflow=False,
            total_tokens=total_tokens,
            limit=limit,
            inspected_segments=segments,
            dropped_segments=[],
            inspected_content=content,
            blocked=False,
        )

    # Overflow detected -- segment and prioritize
    raw_segments = split_into_segments(content)
    scored_segments = [
        ContentSegment(
            text=text,
            index=i,
            score=score_segment(text, i, len(raw_segments)),
            region=classify_region(text),
            inspected=False,
        )
        for i, text in enumerate(raw_segments)
    ]

    # Block mode -- emit signal and block detection
    if overflow_action == "block":
        signal = ContextOverflowSignal(
            turn_id=turn_id,
            total_tokens=total_tokens,
            limit=limit,
            segments_inspected=0,
            segments_dropped=len(scored_segments),
            overflow_action="block",
            timestamp=now_ms,
        )

        return ContextWindowResult(
            overflow=True,
            total_tokens=total_tokens,
            limit=limit,
            inspected_segments=[],
            dropped_segments=scored_segments,
            inspected_content="",
            signal=signal,
            blocked=True,
        )

    # Partial-scan mode -- prioritize segments
    always_inspect_indices: set[int] = set()
    always_inspect_tokens = 0

    for i, seg in enumerate(scored_segments):
        if _should_always_inspect(seg.region, inspect_config):
            always_inspect_indices.add(i)
            always_inspect_tokens += estimate_tokens(seg.text)

    # Remaining budget for general segments
    remaining_budget = max(0, limit - always_inspect_tokens)

    # Sort non-always-inspect segments by score descending
    general_entries = [
        (i, seg.score, estimate_tokens(seg.text))
        for i, seg in enumerate(scored_segments)
        if i not in always_inspect_indices
    ]
    general_entries.sort(key=lambda e: e[1], reverse=True)

    # Fill remaining budget with highest-scoring segments
    used_budget = 0
    selected_general_indices: set[int] = set()
    for idx, _score, tokens in general_entries:
        if used_budget + tokens <= remaining_budget:
            selected_general_indices.add(idx)
            used_budget += tokens

    # Build final segment lists
    inspected_segments: list[ContentSegment] = []
    dropped_segments: list[ContentSegment] = []

    for i, seg in enumerate(scored_segments):
        inspected = i in always_inspect_indices or i in selected_general_indices
        final_seg = ContentSegment(
            text=seg.text,
            index=seg.index,
            score=seg.score,
            region=seg.region,
            inspected=inspected,
        )
        if inspected:
            inspected_segments.append(final_seg)
        else:
            dropped_segments.append(final_seg)

    # Build inspected content (in original order)
    inspected_segments.sort(key=lambda s: s.index)
    inspected_content = "".join(s.text for s in inspected_segments)

    signal = ContextOverflowSignal(
        turn_id=turn_id,
        total_tokens=total_tokens,
        limit=limit,
        segments_inspected=len(inspected_segments),
        segments_dropped=len(dropped_segments),
        overflow_action="partial-scan",
        timestamp=now_ms,
    )

    return ContextWindowResult(
        overflow=True,
        total_tokens=total_tokens,
        limit=limit,
        inspected_segments=inspected_segments,
        dropped_segments=dropped_segments,
        inspected_content=inspected_content,
        signal=signal,
        blocked=False,
    )
