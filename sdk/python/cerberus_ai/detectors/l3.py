"""
cerberus_ai.detectors.l3
~~~~~~~~~~~~~~~~~~~~~~~~~
L3 — Outbound Exfiltration Path Detector.

Detects when an agent has an active mechanism to send data to an external
destination: tool calls, HTTP requests, email, file writes, DNS, webhooks.

Includes:
  - Static tool capability analysis
  - Cross-turn data flow tracking
  - Tool argument semantic analysis (encoding, volume anomalies, sensitive fields)
  - Split exfiltration detection (cumulative volume)
  - Behavioral intent scoring (deterministic, no LLM)
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any

from cerberus_ai.detectors.normalizer import normalize
from cerberus_ai.models import L3Detection, Message, ToolCall, ToolSchema

# ── Network-capable tool heuristics ───────────────────────────────────────────

_NETWORK_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(http|https|webhook|request|fetch|curl|post|get)\b", re.I),
    re.compile(r"\b(email|smtp|sendgrid|mailgun|ses|send.?mail)\b", re.I),
    re.compile(r"\b(slack|discord|teams|telegram|twilio|sms|notify|message)\b", re.I),
    re.compile(r"\b(s3|gcs|blob|upload|storage|bucket|put.?object)\b", re.I),
    re.compile(r"\b(dns|resolve|lookup|nslookup)\b", re.I),
    re.compile(r"\b(ftp|sftp|scp|rsync|transfer)\b", re.I),
    re.compile(r"\b(database|db|insert|write|update|upsert)\b", re.I),
    re.compile(r"\b(log|audit|track|report|export)\b", re.I),
]

# URL patterns in tool arguments
_URL_PATTERN = re.compile(r"https?://[^\s\"']+", re.I)
_EXTERNAL_URL_PATTERN = re.compile(
    r"https?://(?!localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)[\w\-\.]+",
    re.I
)

# Sensitive field names in tool arguments
_SENSITIVE_ARG_KEYS = re.compile(
    r"\b(email|phone|ssn|dob|password|passwd|secret|token|key|api_key|auth|"
    r"credit_card|cc_num|cvv|account|balance|salary|medical|diagnosis|"
    r"address|zip|postal|birth|gender|race|ethnicity)\b",
    re.I
)


# ── Behavioral intent scoring weights ─────────────────────────────────────────

_INTENT_WEIGHTS = {
    "network_capable_tool":       0.30,
    "l1_active_session":          0.25,
    "l2_detected_recently":       0.20,
    "argument_volume_anomaly":    0.15,
    "argument_encoding_anomaly":  0.10,
}

_INTENT_THRESHOLD = 0.60   # configurable via CerberusConfig


# ── Cross-turn data flow tracking ─────────────────────────────────────────────

@dataclass
class DataFlowToken:
    token_id: str
    created_at_turn: int
    data_classification: str
    data_fingerprint: str
    expires_at_turn: int


@dataclass
class SplitExfilTracker:
    session_id: str
    cumulative_volume_bytes: int = 0
    outbound_calls: list[dict[str, Any]] = field(default_factory=list)
    pattern_score: float = 0.0
    volume_threshold: int = 10_240   # 10KB default


class SessionL3State:
    """Per-session state for cross-turn L3 tracking."""

    def __init__(self, session_id: str, retention_turns: int = 10) -> None:
        self.session_id = session_id
        self.retention_turns = retention_turns
        self.data_flow_tokens: list[DataFlowToken] = []
        self.split_tracker = SplitExfilTracker(session_id=session_id)
        self.current_turn = 0
        self.l2_recent_turns: list[int] = []

    def record_l1_data_access(self, classification: str, content_fingerprint: str) -> DataFlowToken:
        token = DataFlowToken(
            token_id=hashlib.sha256(f"{self.session_id}:{self.current_turn}:{time.time()}".encode()).hexdigest()[:16],
            created_at_turn=self.current_turn,
            data_classification=classification,
            data_fingerprint=content_fingerprint,
            expires_at_turn=self.current_turn + self.retention_turns,
        )
        self.data_flow_tokens.append(token)
        return token

    def record_l2_detected(self) -> None:
        self.l2_recent_turns.append(self.current_turn)

    def has_active_data_flow_token(self) -> bool:
        return any(t.expires_at_turn >= self.current_turn for t in self.data_flow_tokens)

    def l2_detected_recently(self, window: int = 3) -> bool:
        return any(t >= self.current_turn - window for t in self.l2_recent_turns)

    def advance_turn(self) -> None:
        self.current_turn += 1
        # Expire old tokens
        self.data_flow_tokens = [
            t for t in self.data_flow_tokens
            if t.expires_at_turn >= self.current_turn
        ]

    def record_outbound_call(self, tool_name: str, args_bytes: int) -> None:
        self.split_tracker.cumulative_volume_bytes += args_bytes
        self.split_tracker.outbound_calls.append({
            "turn": self.current_turn,
            "tool": tool_name,
            "bytes": args_bytes,
        })


class L3Detector:
    """
    Detects L3 — Outbound Exfiltration Path.

    Detection methods:
      - Static: tool schema has outbound capability
      - Cross-turn: data flow token active + outbound tool call
      - Behavioral: intent scoring on tool call arguments
      - Split: cumulative outbound volume threshold exceeded with L1 active
    """

    def __init__(
        self,
        declared_tools: list[ToolSchema],
        intent_threshold: float = _INTENT_THRESHOLD,
    ) -> None:
        self._declared_tools = {t.name: t for t in declared_tools}
        self._intent_threshold = intent_threshold

    def detect(
        self,
        messages: list[Message],
        tool_calls: list[ToolCall],
        session_state: SessionL3State,
        l1_active: bool = False,
        l2_active: bool = False,
    ) -> L3Detection:
        exfiltration_tools: list[str] = []
        evidence: list[str] = []
        confidence = 0.0
        detection_method: str | None = None

        if not tool_calls:
            # No tool calls — check if any declared tool has outbound capability
            for tool in self._declared_tools.values():
                if tool.is_network_capable:
                    exfiltration_tools.append(tool.name)
                    evidence.append(f"Network-capable tool declared in session: '{tool.name}'")
                    confidence = max(confidence, 0.55)
                    detection_method = "STATIC_DECLARED"
            return L3Detection(
                exfiltration_tools=exfiltration_tools,
                evidence=evidence,
                confidence=confidence,
                detection_method=detection_method,
            )

        for tc in tool_calls:
            tool_schema = self._declared_tools.get(tc.name)
            args_str = str(tc.arguments)
            args_bytes = len(args_str.encode())

            # ── Static detection ──────────────────────────────────────────────
            is_network_capable = False
            if tool_schema and tool_schema.is_network_capable:
                is_network_capable = True
            elif any(p.search(tc.name) for p in _NETWORK_TOOL_PATTERNS):
                is_network_capable = True
            elif _EXTERNAL_URL_PATTERN.search(args_str):
                is_network_capable = True

            if is_network_capable:
                exfiltration_tools.append(tc.name)
                evidence.append(f"Network-capable tool invoked: '{tc.name}'")
                confidence = max(confidence, 0.70)
                detection_method = "STATIC"

            # ── Cross-turn detection ──────────────────────────────────────────
            if session_state.has_active_data_flow_token() and is_network_capable:
                evidence.append(
                    f"Cross-turn exfiltration: data flow token active from earlier turn; "
                    f"outbound tool '{tc.name}' invoked now"
                )
                confidence = max(confidence, 0.90)
                detection_method = "CROSS_TURN"

            # ── Record outbound call for split detection ───────────────────────
            if is_network_capable:
                session_state.record_outbound_call(tc.name, args_bytes)

            # ── Split exfiltration detection ──────────────────────────────────
            st = session_state.split_tracker
            if (
                st.cumulative_volume_bytes > st.volume_threshold
                and l1_active
                and len(st.outbound_calls) >= 2
            ):
                evidence.append(
                    f"Split exfiltration: {st.cumulative_volume_bytes} bytes transmitted "
                    f"across {len(st.outbound_calls)} outbound calls with L1 active"
                )
                confidence = max(confidence, 0.85)
                detection_method = "SPLIT"
                if tc.name not in exfiltration_tools:
                    exfiltration_tools.append(tc.name)

            # ── Behavioral intent scoring ─────────────────────────────────────
            intent_score = 0.0
            if is_network_capable:
                intent_score += _INTENT_WEIGHTS["network_capable_tool"]
            if l1_active:
                intent_score += _INTENT_WEIGHTS["l1_active_session"]
            if l2_active or session_state.l2_detected_recently():
                intent_score += _INTENT_WEIGHTS["l2_detected_recently"]

            # Argument volume anomaly
            if args_bytes > 4096:   # >4KB args is anomalous
                intent_score += _INTENT_WEIGHTS["argument_volume_anomaly"]
                evidence.append(f"Tool '{tc.name}' argument volume anomaly: {args_bytes} bytes")

            # Argument encoding anomaly
            norm = normalize(args_str)
            if norm.was_encoded:
                intent_score += _INTENT_WEIGHTS["argument_encoding_anomaly"]
                evidence.append(
                    f"Tool '{tc.name}' arguments"
                    f" contain encoding: {norm.encodings_found}"
                )

            # Sensitive field names in arguments
            if _SENSITIVE_ARG_KEYS.search(args_str):
                evidence.append(f"Tool '{tc.name}' arguments contain sensitive field names")
                intent_score = min(intent_score + 0.10, 1.0)

            # Log intent score regardless (audit trail)
            evidence.append(f"Tool '{tc.name}' behavioral intent score: {intent_score:.2f}")

            if intent_score >= self._intent_threshold:
                if tc.name not in exfiltration_tools:
                    exfiltration_tools.append(tc.name)
                confidence = max(confidence, min(intent_score, 1.0))
                if not detection_method:
                    detection_method = "BEHAVIORAL"

        return L3Detection(
            exfiltration_tools=list(set(exfiltration_tools)),
            evidence=evidence,
            confidence=confidence,
            detection_method=detection_method,
        )
