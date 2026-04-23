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
    # Manifest gate (per-turn cryptographic authorization gate)
    MANIFEST_SIGNATURE_INVALID = "MANIFEST_SIGNATURE_INVALID"
    # Context window
    CONTEXT_OVERFLOW = "CONTEXT_WINDOW_OVERFLOW"
    # Config / streaming
    PASSTHROUGH_MODE_ACTIVE = "SECURITY_CONFIG_ADVISORY_PASSTHROUGH"
    PARTIAL_SCAN_MODE_ACTIVE = "SECURITY_CONFIG_ADVISORY_PARTIAL_SCAN"
    # Cross-turn L3
    CROSS_TURN_EXFILTRATION = "CROSS_TURN_EXFILTRATION_PATH"
    SPLIT_EXFILTRATION = "SPLIT_EXFILTRATION_PATTERN"
    # L4 memory contamination
    CONTAMINATED_MEMORY_ACTIVE = "CONTAMINATED_MEMORY_ACTIVE"
    # MCP tool poisoning (sub-classifier of L2)
    MCP_TOOL_POISONED = "MCP_TOOL_POISONED"
    # Multi-agent delegation / cross-agent
    CROSS_AGENT_TRIFECTA = "CROSS_AGENT_TRIFECTA"
    CONTEXT_CONTAMINATION_PROPAGATION = "CONTEXT_CONTAMINATION_PROPAGATION"
    UNAUTHORIZED_AGENT_SPAWN = "UNAUTHORIZED_AGENT_SPAWN"
    # Self-security / runtime
    RUNTIME_INTEGRITY_FAILURE = "RUNTIME_INTEGRITY_FAILURE"
    CONFIG_TAMPER = "CONFIG_TAMPER_DETECTED"
    TELEMETRY_GAP = "TELEMETRY_SUPPRESSION_DETECTED"
    INSPECTION_TIMEOUT = "INSPECTION_TIMEOUT_EXCEEDED"
    TURN_SIZE_EXCEEDED = "TURN_SIZE_LIMIT_EXCEEDED"
    # Synthetic terminal event: emitted exactly once at the end of every
    # inspection, blocked or not. Carries the canonical per-inspection
    # metrics (risk_score, inspection_duration_ms, tool_name, action,
    # blocked) so the Prometheus exporter can count one tool-call per
    # inspection — without it, the exporter would either over-count
    # (multiple PARTIAL_* events fire per blocked turn) or miss clean
    # turns entirely (no detection events fire). Severity is INFO; this
    # event is bookkeeping, not a security signal.
    INSPECTION_COMPLETE = "INSPECTION_COMPLETE"


class OverflowAction(str, Enum):
    BLOCK = "BLOCK"
    PARTIAL_SCAN = "PARTIAL_SCAN"


class TrustLevel(str, Enum):
    """Trust classification for inbound content / memory writes."""
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class AgentType(str, Enum):
    """Role of an agent in a multi-agent delegation graph."""
    ORCHESTRATOR = "orchestrator"
    SUBAGENT = "subagent"
    TOOL_AGENT = "tool_agent"


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


class MemoryToolConfig(BaseModel):
    """
    L4 memory contamination configuration for a single tool.

    Declare which of an agent's tools read from or write to persistent
    memory so Cerberus can track taint propagation across sessions.

    ``node_id_field`` and ``content_field`` are the argument names Cerberus
    consults to derive the memory node identifier and the content hash. If
    either is missing at runtime, Cerberus falls back to a small set of
    common field names (``key`` / ``id`` / ``nodeId`` / ``memoryKey`` for the
    node id; ``value`` / ``content`` / ``data`` for content).
    """
    tool_name: str
    operation: str                      # "read" | "write"
    node_id_field: str | None = None    # e.g. "key"
    content_field: str | None = None    # e.g. "value"


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
    """Telemetry configuration.

    Cerberus Observe is the tamper-evident telemetry path. Events are signed
    with an HMAC-SHA256 key and written as NDJSON. Guard (or any verifier)
    re-computes the signature to detect log tampering and monitors sequence
    numbers to detect suppression.

    Key material:
      * ``signing_key_path`` — if set, Observe loads the signing key from the
        given path (32 bytes). The file must be readable only by the running
        user. This is the production mode.
      * ``signing_key_env`` — if set and ``signing_key_path`` is unset,
        Observe reads a hex- or base64-encoded key from the environment.
      * If neither is set, Observe generates an ephemeral key in memory and
        emits a ``TELEMETRY_GAP``-level warning: signatures will be
        *unverifiable by any external party*. This is development-only.

    Air-gap mode:
      * ``airgap_mode = True`` switches off every network emitter (SIEM forward,
        HTTP forwarders, etc.) regardless of other config, encrypts every
        NDJSON record with AES-256-GCM using ``encryption_key_path``, and
        enforces daily rotation + ``retention_days`` deletion of older logs.
        This is the mode federal/classified deployments use.
    """
    enabled: bool = True
    # LOCAL_ONLY | LOCAL_PLUS_SIEM | LOCAL_PLUS_SYSLOG | DISABLED
    mode: str = "LOCAL_ONLY"
    siem_endpoint: str | None = None
    log_path: str = "/var/log/cerberus/events"
    emit_partial_signals: bool = True

    # Tamper-evident signing key custody
    signing_key_path: str | None = None
    signing_key_env: str | None = None
    # If True, allow the ephemeral-key fallback and only log a warning.
    # If False (default), Cerberus will raise at startup when no key material
    # is provided AND the user set ``enabled=True``. This preserves the
    # "tamper-evident" property advertised in the spec.
    allow_ephemeral_signing_key: bool = True

    # Air-gapped / offline mode (Sprint 5)
    airgap_mode: bool = False
    encryption_key_path: str | None = None
    encryption_key_env: str | None = None
    retention_days: int = 365
    rotation_interval_s: int = 86_400              # 24 hours
    verify_sequence_continuity: bool = True


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

    # Self-hardening (Sprint 7): bound inspection latency and input size.
    # Fail-secure: exceeding either limit returns a BLOCKED result with a
    # dedicated event. These are the "detectors cannot hang forever" and
    # "caller cannot DoS the inspector with a 1GB turn" guarantees.
    inspection_timeout_ms: int = 500               # 0 = disabled
    max_turn_bytes: int = 10 * 1024 * 1024         # 10MB hard cap; 0 = disabled

    # Prometheus exporter (v1.4 Delta #4). When enabled, the SDK starts a
    # background HTTP server exposing /metrics in the Prometheus text
    # format. Metric names match the shipped Grafana dashboard at
    # ``monitoring/grafana/dashboards/cerberus.json``. Requires the
    # ``prometheus`` extras: ``pip install 'cerberus-ai[prometheus]'``.
    prometheus_enabled: bool = False
    prometheus_port: int = 9464
    prometheus_host: str = "0.0.0.0"  # noqa: S104 — metrics endpoint, intentionally public

    # Manifest gate (v1.3.0 TS parity): if True, every turn verifies the
    # signed EGI manifest before any detector runs. Any signature failure
    # short-circuits to BLOCKED with MANIFEST_SIGNATURE_INVALID.
    manifest_gate_enabled: bool = True

    # L4 memory contamination (Sprint 2): declare the tools that read/write
    # agent memory so Cerberus can track taint across sessions.
    memory_tools: list[MemoryToolConfig] = Field(default_factory=list)
    # Persistent provenance ledger path. If None, an in-memory ledger is used
    # and cross-process / cross-restart taint detection is disabled.
    provenance_ledger_path: str | None = None

    # MCP tool poisoning scanner (Sprint 6 L2 sub-classifier)
    mcp_scanner_enabled: bool = True

    # v1.4 Delta #2 — ML-backed L2 classifier.
    # Off by default; enable with a model file downloaded separately
    # (no weights ship in the OSS repo). When enabled the classifier
    # scores every untrusted-role message and fuses into the regex
    # L2 score via max(). Fail-open at inference (any exception →
    # 0.0, regex still runs); fail-closed at startup (a missing
    # model path raises before the first turn).
    ml_injection_enabled: bool = False
    ml_injection_model_path: str | None = None
    ml_injection_tokenizer_path: str | None = None
    ml_injection_threshold: float = 0.75
    ml_injection_max_latency_ms: int = 30

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
