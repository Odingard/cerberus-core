"""
cerberus_ai.detectors.outbound_encoding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Outbound Encoding Detector -- Sub-classifier enhancing L3.

Detects encoded/obfuscated payloads in OUTBOUND tool call arguments.
The existing normalizer handles inbound/untrusted content (L2).
This sub-classifier covers the other direction: an agent encoding sensitive
data before exfiltrating it via an outbound tool call.

Fires when:
  1. The tool is an outbound tool
  2. Encoded content is detected in the tool arguments
  3. L1 was active (privileged data accessed this session)
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from cerberus_ai.detectors.normalizer import normalize


class EncodedExfiltrationSignal:
    """Signal emitted when encoded content is found in outbound arguments."""

    __slots__ = (
        "layer",
        "signal",
        "turn_id",
        "encoding_types",
        "decoded_snippet",
        "timestamp",
    )

    def __init__(
        self,
        turn_id: str,
        encoding_types: list[str],
        timestamp: int,
        decoded_snippet: str | None = None,
    ) -> None:
        self.layer = "L3"
        self.signal = "ENCODED_EXFILTRATION"
        self.turn_id = turn_id
        self.encoding_types = encoding_types
        self.decoded_snippet = decoded_snippet
        self.timestamp = timestamp


def _serialize_arguments(args: dict[str, Any]) -> str:
    """Serialize tool arguments to a single string for scanning."""
    try:
        return json.dumps(args, default=str)
    except (TypeError, ValueError):
        return str(args)


def detect_outbound_encoding(
    tool_name: str,
    tool_arguments: dict[str, Any],
    turn_id: str,
    timestamp: int,
    privileged_values_count: int,
    outbound_tools: Sequence[str],
) -> EncodedExfiltrationSignal | None:
    """
    Detect encoded payloads in outbound tool call arguments.

    Reuses the encoding detection patterns from the normalizer
    but applies them to outbound arguments rather than inbound content.

    Args:
        tool_name: Name of the tool being called.
        tool_arguments: Arguments passed to the tool.
        turn_id: Current turn identifier.
        timestamp: Current timestamp in milliseconds.
        privileged_values_count: Number of privileged values in session (L1 gate).
        outbound_tools: Explicit list of outbound tool names.

    Returns:
        EncodedExfiltrationSignal if encoding detected, None otherwise.
    """
    # Gate 1: only runs for outbound tools
    if tool_name not in outbound_tools:
        return None

    # Gate 2: L1 must have been active (sensitive data in session)
    if privileged_values_count == 0:
        return None

    # Serialize all outbound arguments to a single string for scanning
    outbound_text = _serialize_arguments(tool_arguments)
    if len(outbound_text) == 0:
        return None

    # Reuse encoding detection from normalizer
    result = normalize(outbound_text)
    if not result.was_encoded:
        return None

    # Extract a snippet of decoded content for evidence
    decoded_snippet: str | None = None
    if result.text != result.original and len(result.text) > 0:
        decoded_snippet = result.text[:200]

    return EncodedExfiltrationSignal(
        turn_id=turn_id,
        encoding_types=result.encodings_found,
        decoded_snippet=decoded_snippet,
        timestamp=timestamp,
    )
