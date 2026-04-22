"""
cerberus_ai.classifiers.mcp_scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
MCP Tool-Description Poisoning scanner — L2 sub-classifier.

Scans MCP (or generic) tool descriptions for hidden instructions,
cross-tool manipulation, data-routing commands, and zero-width
obfuscation. Based on Invariant Labs' tool-poisoning research.

Modes:
    ``scan_tool_descriptions(tools)`` — standalone registration-time scan.
    ``check_tool_call_poisoning(tool_name, tools)`` — runtime per-call lookup.

Parity port of ``src/classifiers/mcp-scanner.ts``. Same pattern set,
same category → severity mapping, same return shape.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from cerberus_ai.models import ToolSchema

_POISONING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Hidden instruction tags
    ("hidden_instruction", re.compile(r"<IMPORTANT>", re.I)),
    ("hidden_instruction", re.compile(r"<SYSTEM>", re.I)),
    ("hidden_instruction", re.compile(r"<ADMIN>", re.I)),
    ("hidden_instruction", re.compile(r"<!--[\s\S]*?-->", re.M)),

    # Sensitive file references
    ("sensitive_file_ref", re.compile(r"~\/\.ssh\b")),
    ("sensitive_file_ref", re.compile(r"~\/\.env\b")),
    ("sensitive_file_ref", re.compile(r"~\/\.aws\b")),
    ("sensitive_file_ref", re.compile(r"\/etc\/passwd\b")),
    ("sensitive_file_ref", re.compile(r"~\/\.gnupg\b")),
    (
        "sensitive_file_ref",
        re.compile(r"(?:credentials|secrets)\.(?:json|yaml|yml|toml|env)", re.I),
    ),

    # Cross-tool manipulation
    ("cross_tool_manipulation", re.compile(r"before\s+calling\b", re.I)),
    (
        "cross_tool_manipulation",
        re.compile(r"instead\s+of\s+(?:using|calling)\b", re.I),
    ),
    ("cross_tool_manipulation", re.compile(r"after\s+using\b", re.I)),
    ("cross_tool_manipulation", re.compile(r"when\s+.*\btool\b", re.I)),

    # Instruction injection
    ("instruction_injection", re.compile(r"\byou\s+must\b", re.I)),
    (
        "instruction_injection",
        re.compile(
            r"\balways\b.*\b(?:send|forward|include|attach)\b", re.I
        ),
    ),
    (
        "instruction_injection",
        re.compile(r"\bnever\b.*\b(?:tell|inform|reveal|show)\b", re.I),
    ),
    (
        "instruction_injection",
        re.compile(r"\bignore\b.*\b(?:instructions|rules|policies)\b", re.I),
    ),
    ("instruction_injection", re.compile(r"\boverride\b", re.I)),

    # Data routing
    ("data_routing", re.compile(r"\bsend\s+to\b", re.I)),
    ("data_routing", re.compile(r"\bforward\s+to\b", re.I)),
    ("data_routing", re.compile(r"\bcopy\s+to\b", re.I)),
    ("data_routing", re.compile(r"\bexfiltrate\b", re.I)),
    ("data_routing", re.compile(r"\bupload\s+(?:to|all)\b", re.I)),

    # Zero-width obfuscation
    ("obfuscation", re.compile(r"[\u200B\u200C\uFEFF\u00AD]")),
)

_HIGH_RISK = {"hidden_instruction", "data_routing", "obfuscation"}
_MEDIUM_RISK = {"sensitive_file_ref", "cross_tool_manipulation"}


@dataclass(frozen=True)
class ToolPoisoningResult:
    tool_name: str
    poisoned: bool
    patterns_found: tuple[str, ...]
    severity: str  # "low" | "medium" | "high"


def scan_description(text: str) -> list[str]:
    """Return the de-duplicated list of matched poisoning categories."""
    matched: set[str] = set()
    for category, pattern in _POISONING_PATTERNS:
        if pattern.search(text):
            matched.add(category)
    return sorted(matched)


def _determine_severity(patterns: Iterable[str]) -> str:
    patterns = list(patterns)
    if not patterns:
        return "low"
    if any(p in _HIGH_RISK for p in patterns):
        return "high"
    if any(p in _MEDIUM_RISK for p in patterns):
        return "medium"
    return "low"


def scan_tool_descriptions(
    tools: Iterable[ToolSchema],
) -> list[ToolPoisoningResult]:
    """Standalone scan — call at registration time for every declared tool."""
    results: list[ToolPoisoningResult] = []
    for tool in tools:
        description = tool.description or ""
        patterns = set(scan_description(description))
        if tool.parameters:
            patterns.update(scan_description(json.dumps(tool.parameters)))
        patterns_found = sorted(patterns)
        results.append(
            ToolPoisoningResult(
                tool_name=tool.name,
                poisoned=len(patterns_found) > 0,
                patterns_found=tuple(patterns_found),
                severity=_determine_severity(patterns_found),
            )
        )
    return results


def check_tool_call_poisoning(
    tool_name: str, tools: Iterable[ToolSchema]
) -> ToolPoisoningResult | None:
    """Runtime scan — return the poisoning verdict for the tool being called.

    ``None`` if the tool name isn't in the declared set (silent pass)."""
    for tool in tools:
        if tool.name != tool_name:
            continue
        description = tool.description or ""
        patterns = set(scan_description(description))
        if tool.parameters:
            patterns.update(scan_description(json.dumps(tool.parameters)))
        patterns_found = sorted(patterns)
        return ToolPoisoningResult(
            tool_name=tool_name,
            poisoned=len(patterns_found) > 0,
            patterns_found=tuple(patterns_found),
            severity=_determine_severity(patterns_found),
        )
    return None
