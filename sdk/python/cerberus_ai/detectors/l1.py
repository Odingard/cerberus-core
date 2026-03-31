"""
cerberus_ai.detectors.l1
~~~~~~~~~~~~~~~~~~~~~~~~~
L1 — Privileged Data Access Detector.

Detects when an agent is operating with access to sensitive data sources
(RAG pipelines, databases, confidential documents, PII stores).

Detection is deterministic and rule-based — no LLM classification.
"""
from __future__ import annotations

import re
from typing import Any

from cerberus_ai.models import DataSource, L1Detection, Message, ToolSchema

# ── Built-in classification patterns ──────────────────────────────────────────

# System prompt markers indicating privileged data access
_SYSTEM_PRIVILEGE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(rag|retrieval.augmented|vector.?store|knowledge.?base)\b", re.I),
    re.compile(r"\b(database|db|sql|mongo|postgres|mysql|redis|elasticsearch)\b", re.I),
    re.compile(r"\b(confidential|secret|proprietary|internal.?only|restricted)\b", re.I),
    re.compile(r"\b(customer.?data|user.?data|patient.?data|employee.?data)\b", re.I),
    re.compile(r"\b(pii|personal.?information|personally.?identifiable)\b", re.I),
    re.compile(r"\b(api.?key|access.?token|bearer.?token|credentials?|password)\b", re.I),
    re.compile(r"\b(ssn|social.?security|credit.?card|cvv|account.?number)\b", re.I),
    re.compile(r"\b(medical.?record|health.?data|hipaa|phi)\b", re.I),
    re.compile(r"\b(financial.?data|trading|portfolio|balance|transaction)\b", re.I),
    re.compile(r"\b(source.?code|repository|codebase|internal.?api)\b", re.I),
]

# Data-reading tool names (heuristic)
_DATA_READ_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(search|query|fetch|retrieve|get|read|load|lookup)\b", re.I),
    re.compile(r"\b(rag|vector|embed|similarity|semantic)\b", re.I),
    re.compile(r"\b(db|sql|database|mongo|elastic|redis)\b", re.I),
    re.compile(r"\b(file|document|storage|s3|blob|bucket)\b", re.I),
]

# Tool result content markers
_TOOL_RESULT_SENSITIVE: list[re.Pattern[str]] = [
    re.compile(r"\b(ssn|social.?security)\s*:?\s*\d{3}-?\d{2}-?\d{4}", re.I),
    re.compile(r"\b(email)\s*:?\s*[\w.+-]+@[\w-]+\.\w+", re.I),
    re.compile(r"\b(phone|tel|mobile)\s*:?\s*[\d\s\(\)\-\+]{7,}", re.I),
    re.compile(r"\b(dob|date.?of.?birth|birthday)\s*:?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}", re.I),
    re.compile(r"\b(credit.?card|cc.?num)\s*:?\s*\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}", re.I),
    re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}", re.I),            # AWS access keys
    re.compile(r"sk-[A-Za-z0-9]{20,}", re.I),               # OpenAI-style keys
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT tokens
]


class L1Detector:
    """
    Detects L1 — Privileged Data Access.

    Checks:
      1. Registered data sources from CerberusConfig
      2. System prompt content for privilege indicators
      3. Tool schemas for data-reading capabilities
      4. Tool results for sensitive data patterns
    """

    def __init__(self, data_sources: list[DataSource], declared_tools: list[ToolSchema]) -> None:
        self._sources = data_sources
        self._declared_tools = declared_tools
        # Pre-compile source name patterns
        self._source_patterns = [
            (src, re.compile(re.escape(src.name), re.I))
            for src in data_sources
        ]

    def detect(self, messages: list[Message], tool_calls: list[Any] | None = None) -> L1Detection:
        matched_sources: list[str] = []
        evidence: list[str] = []
        confidence = 0.0

        # Check 1 — Registered data sources mentioned in messages
        full_text = " ".join(
            m.content if isinstance(m.content, str) else str(m.content or "")
            for m in messages
        )
        for src, pattern in self._source_patterns:
            if pattern.search(full_text):
                matched_sources.append(src.name)
                evidence.append(
                    f"Registered source '{src.name}'"
                    f" ({src.classification})"
                    " referenced in context"
                )
                confidence = max(confidence, 0.90)

        # Check 2 — System prompt privilege patterns
        for msg in messages:
            if msg.role == "system":
                content = msg.content if isinstance(msg.content, str) else str(msg.content or "")
                for pattern in _SYSTEM_PRIVILEGE_PATTERNS:
                    m = pattern.search(content)
                    if m:
                        evidence.append(f"System prompt privilege indicator: '{m.group(0)}'")
                        confidence = max(confidence, 0.75)
                        break

        # Check 3 — Declared tools with data-read capability
        for tool in self._declared_tools:
            if tool.is_data_read:
                matched_sources.append(f"tool:{tool.name}")
                evidence.append(f"Data-reading tool declared in session: '{tool.name}'")
                confidence = max(confidence, 0.70)

        # Check 4 — Tool schemas by name heuristic
        for tool in self._declared_tools:
            for pattern in _DATA_READ_TOOL_PATTERNS:
                if pattern.search(tool.name) or pattern.search(tool.description):
                    if f"tool:{tool.name}" not in matched_sources:
                        matched_sources.append(f"tool:{tool.name}")
                        evidence.append(f"Tool '{tool.name}' matches data-read heuristic")
                        confidence = max(confidence, 0.60)
                    break

        # Check 5 — Tool results contain sensitive data patterns
        for msg in messages:
            if msg.role == "tool":
                content = msg.content if isinstance(msg.content, str) else str(msg.content or "")
                for pattern in _TOOL_RESULT_SENSITIVE:
                    m = pattern.search(content)
                    if m:
                        evidence.append(
                            "Tool result contains sensitive"
                            f" data pattern: {pattern.pattern[:40]}"
                        )
                        confidence = max(confidence, 0.95)
                        if "tool_result_pii" not in matched_sources:
                            matched_sources.append("tool_result_pii")

        return L1Detection(
            matched_sources=matched_sources,
            evidence=evidence,
            confidence=confidence,
        )
