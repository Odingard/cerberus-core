"""
cerberus_ai.models
~~~~~~~~~~~~~~~~~~
All data models for the Cerberus runtime security platform.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ── Enums ──────────────────────────────────────────────────────────────────────


class StreamingMode(str, Enum):
    """Controls how Cerberus handles streaming LLM responses."""
    BUFFER_ALL = "BUFFER_ALL"          # Maximum detection fidelity (default)
    PARTIAL_SCAN = "PARTIAL_SCAN"      # Inspect buffered portion on overflow
    PASSTHROUGH = "PASSTHROUGH"        # Legacy compatibility only — reduced coverage


class Severity(str, Enum):
    INFO = "INFO"
    ADVISORY = "ADVISORY"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionTier(str, Enum):
    L1 = "L1"   # Privileged data access
    L2 = "L2"   # Untrusted content injection
    L3 = "L3"   # Outbound exfiltration path


class EventType(str, Enum):
    # Trifecta events
    LETHAL_TRIFECTA = "LETHAL_TRIFECTA"
    PARTIAL_L1 = "PARTIAL_L1_DETECTED"
    PARTIAL_L2 = "PARTIAL_L2_DETECTED"
    PARTIAL_L3 = "PARTIAL_L3_DETECTED"
    PARTIAL_TRIFECTA_RISK = "PARTIAL_TRIFECTA_RISK"
    # EGI events
    EGI_VIOLATION = "EGI_GRAPH_VIOLATION"
    EGI_TOOL_UNAUTHORIZED = "EGI_UNAUTHORIZED_TOOL_USE"
    EGI_TOOL_LATE_REGISTERED = "EGI_LATE_TOOL_REGISTERED"
    EGI_INJECTION_ASSISTED_REGISTRATION = "EGI_INJECTION_ASSISTED_REGISTRATION"
    EGI_SCHEMA_MISMATCH = "EGI_SCHEMA_MISMATCH"
    # Context window
    CONTEXT_OVERFLOW = "CONTEXT_WINDOW_OVERFLOW"
    # Config
    PASSTHROUGH_MODE_ACTIVE = "SECURITY_CONFIG_ADVISORY_PASSTHROUGH"
    # Cross-turn L3
    CROSS_TURN_EXFILTRATION = "CROSS_TURN_EXFILTRATION_PATH"
    SPLIT_EXFILTRATION = "SPLIT_EXFILTRATION_PATTERN"
    # Self-security
    RUNTIME_INTEGRITY_FAILURE = "RUNTIME_INTEGRITY_FAILURE"
    CONFIG_TAMPER = "CONFIG_TAMPER_DETECTED"
    TELEMETRY_GAP = "TELEMETRY_SUPPRESSION_DETECTED"


class OverflowAction(str, Enum):
    BLOCK = "BLOCK"
    PARTIAL_SCAN = "PARTIAL_SCAN"


# ── Message / Tool models ──────────────────────────────────────────────────────


class Message(BaseModel):
    """A single message in an LLM conversation."""
    role: str                                          # system | user | assistant | tool
    content: str | list[dict[str, Any]] | None = None
    tool_call_id: str | None = None
    name: str | None = None


class ToolSchema(BaseModel):
    """Declared tool schema — used for EGI graph initialization."""
    name: str
    description: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    # Cerberus classification
    is_network_capable: bool = False    # HTTP, webhook, email, DNS
    is_data_read: bool = False          # reads from data stores
    is_data_write: bool = False         # writes to data stores or files
    declared_scope: str | None = None   # human-readable scope declaration


class ToolCall(BaseModel):
    """A tool call made by the LLM in a turn."""
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    raw_arguments: str = ""             # pre-parse arguments string


class DataSource(BaseModel):
    """A registered data source — used for L1 classification."""
    name: str
    classification: str                 # PII | CONFIDENTIAL | SECRET | INTERNAL
    description: str = ""


# ── Detection results ──────────────────────────────────────────────────────────


class TrifectaConditions(BaseModel):
    """State of each Lethal Trifecta condition for a turn."""
    l1_privileged_data: bool = False
    l2_injection: bool = False
    l3_exfiltration_path: bool = False

    @property
    def trifecta_active(self) -> bool:
        return self.l1_privileged_data and self.l2_injection and self.l3_exfiltration_path

    @property
    def active_count(self) -> int:
        return sum([self.l1_privileged_data, self.l2_injection, self.l3_exfiltration_path])

    @property
    def severity(self) -> Severity:
        count = self.active_count
        if self.trifecta_active:
            return Severity.CRITICAL
        if self.l1_privileged_data and self.l2_injection:
            return Severity.HIGH        # highest pre-Trifecta state
        if count == 2:
            return Severity.HIGH
        if count == 1:
            return Severity.ADVISORY
        return Severity.INFO


class L1Detection(BaseModel):
    matched_sources: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class L2Detection(BaseModel):
    injection_patterns: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    encoding_detected: str | None = None    # base64 | unicode | url | html


class L3Detection(BaseModel):
    exfiltration_tools: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    detection_method: str | None = None     # STATIC | CROSS_TURN | BEHAVIORAL | SPLIT


class EGIViolation(BaseModel):
    violation_type: str
    expected_node: str | None = None
    actual_node: str | None = None
    tool_name: str | None = None
    description: str = ""


class SecurityEvent(BaseModel):
    """A security event emitted to Observe."""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    severity: Severity
    turn_id: str
    session_id: str
    timestamp_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    sequence_number: int = 0
    conditions: TrifectaConditions | None = None
    l1_detail: L1Detection | None = None
    l2_detail: L2Detection | None = None
    l3_detail: L3Detection | None = None
    egi_violation: EGIViolation | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    blocked: bool = False


class InspectionResult(BaseModel):
    """The result of a Cerberus inspection — returned to the caller."""
    turn_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    blocked: bool = False
    conditions: TrifectaConditions = Field(default_factory=TrifectaConditions)
    severity: Severity = Severity.INFO
    events: list[SecurityEvent] = Field(default_factory=list)
    egi_violations: list[EGIViolation] = Field(default_factory=list)
    inspection_latency_us: int = 0      # microseconds
    context_overflow: bool = False

    @property
    def trifecta_detected(self) -> bool:
        return self.conditions.trifecta_active

    @property
    def any_detection(self) -> bool:
        return self.conditions.active_count > 0 or bool(self.egi_violations)


# ── Configuration ──────────────────────────────────────────────────────────────


class ObserveConfig(BaseModel):
    """Telemetry configuration."""
    enabled: bool = True
    # LOCAL_ONLY | LOCAL_PLUS_SIEM | LOCAL_PLUS_SYSLOG
    mode: str = "LOCAL_ONLY"
    siem_endpoint: str | None = None
    log_path: str = "/var/log/cerberus/events"
    emit_partial_signals: bool = True


class CerberusConfig(BaseModel):
    """Full Cerberus runtime configuration."""
    # Streaming
    streaming_mode: StreamingMode = StreamingMode.BUFFER_ALL
    max_buffer_bytes: int = 2 * 1024 * 1024        # 2MB
    overflow_action: OverflowAction = OverflowAction.BLOCK

    # Context window
    context_window_limit: int = 32_000             # tokens
    context_scoring_mode: str = "PRIORITY_ANCHOR"
    always_inspect_regions: list[str] = Field(
        default_factory=lambda: ["system_prompt", "tool_schemas", "tool_results"]
    )

    # Detection thresholds
    l3_behavioral_intent_threshold: float = 0.60
    cross_turn_data_flow_enabled: bool = True
    cross_turn_retention_turns: int = 10            # how many turns to track data flow tokens

    # Timing side-channel hardening
    min_response_ms: int = 0                        # 0 = disabled; set >0 for constant-time
    timing_jitter_ms: int = 0

    # Telemetry
    observe: ObserveConfig = Field(default_factory=ObserveConfig)

    # Data sources registered for L1 detection
    data_sources: list[DataSource] = Field(default_factory=list)

    # Declared tools registered for EGI
    declared_tools: list[ToolSchema] = Field(default_factory=list)

    # Split exfiltration threshold (bytes)
    split_exfil_threshold_bytes: int = 10_240  # 10KB default
