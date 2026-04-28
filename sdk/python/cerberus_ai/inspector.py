"""
cerberus_ai.inspector
~~~~~~~~~~~~~~~~~~~~~
Core Cerberus inspection engine.

Orchestrates L1, L2, L3, L4 detectors, EGI, the manifest gate, the
MCP tool-poisoning sub-classifier, and cross-agent correlation into
a single synchronous-or-async inspection API. Emits signed events
to Observe.

Pre-flight checks (fail-secure BLOCK):
    * ``max_turn_bytes`` size limit
    * ``manifest_gate_enabled`` per-turn manifest signature verification

Detection runs with an optional ``inspection_timeout_ms`` budget; on
expiry the call returns a BLOCKED result with ``INSPECTION_TIMEOUT``.
"""
from __future__ import annotations

import concurrent.futures
import logging
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

from cerberus_ai.async_inspect import InspectionHandle
from cerberus_ai.classifiers.mcp_scanner import (
    check_tool_call_poisoning,
    scan_tool_descriptions,
)
from cerberus_ai.context_window import (
    AlwaysInspectRegions,
    analyze_context_window,
)
from cerberus_ai.cross_agent import (
    detect_context_contamination,
    detect_cross_agent_trifecta,
    detect_unauthorized_agent_spawn,
)
from cerberus_ai.detectors.l1 import L1Detector
from cerberus_ai.detectors.l2 import L2Detector
from cerberus_ai.detectors.l3 import L3Detector, SessionL3State
from cerberus_ai.detectors.l4_memory import L4Detector, MemoryContaminationSignal
from cerberus_ai.detectors.outbound_encoding import detect_outbound_encoding
from cerberus_ai.detectors.split_exfiltration import (
    SplitExfilSession,
    detect_split_exfiltration,
)
from cerberus_ai.detectors.tool_chain import (
    ToolChainEntry,
    detect_tool_chain_exfiltration,
)
from cerberus_ai.egi.engine import EGIEngine
from cerberus_ai.egi.signer import Verifier
from cerberus_ai.graph.contamination import create_contamination_graph
from cerberus_ai.graph.delegation import DelegationGraph, RiskState, update_risk_state
from cerberus_ai.graph.ledger import ProvenanceLedger
from cerberus_ai.manifest_gate import verify_manifest_before_turn
from cerberus_ai.models import (
    CerberusConfig,
    EventType,
    InspectionResult,
    Message,
    SecurityEvent,
    Severity,
    ToolCall,
    TrifectaConditions,
    TrustLevel,
)
from cerberus_ai.telemetry.observe import ObserveEmitter

logger = logging.getLogger("cerberus.inspector")


def _completed_future(result: InspectionResult) -> concurrent.futures.Future[InspectionResult]:
    """Return a Future already resolved with ``result``.

    Used by ``inspect_async_nonblocking`` when a pre-flight check (size
    limit, manifest gate) blocks the turn before any worker submission.
    """
    fut: concurrent.futures.Future[InspectionResult] = concurrent.futures.Future()
    fut.set_result(result)
    return fut


class CerberusInspector:
    """
    Core inspection engine for a single Cerberus session.

    One inspector per agent session. Maintains session state (L3 cross-turn
    tracking, EGI graph, turn counter).
    """

    def __init__(
        self,
        session_id: str,
        config: CerberusConfig,
        observe: ObserveEmitter,
        agent_id: str | None = None,
    ) -> None:
        self._session_id = session_id
        self._config = config
        self._observe = observe
        self._agent_id = agent_id or str(uuid.uuid4())
        self._turn_counter = 0
        self._sequence_number = 0

        # Initialize detectors
        self._l1 = L1Detector(
            data_sources=config.data_sources,
            declared_tools=config.declared_tools,
        )
        self._l2 = L2Detector()
        self._l3 = L3Detector(
            declared_tools=config.declared_tools,
            intent_threshold=config.l3_behavioral_intent_threshold,
        )

        # Session state for cross-turn L3 tracking
        self._l3_state = SessionL3State(
            session_id=session_id,
            retention_turns=config.cross_turn_data_flow_retention_turns
            if hasattr(config, "cross_turn_data_flow_retention_turns")
            else 10,
        )

        # Sprint 3/6 sub-classifier session state
        self._tool_chain_history: list[ToolChainEntry] = []
        self._privileged_values_count: int = 0
        self._split_exfil_session = SplitExfilSession()
        self._outbound_tools: list[str] = [
            t.name for t in config.declared_tools if t.is_network_capable
        ]

        # EGI engine
        self._egi = EGIEngine(
            session_id=session_id,
            agent_id=self._agent_id,
            declared_tools=config.declared_tools,
        )

        # L4 memory contamination detector + ledger (optional)
        self._ledger: ProvenanceLedger | None = (
            ProvenanceLedger(config.provenance_ledger_path)
            if config.provenance_ledger_path
            else ProvenanceLedger()
            if config.memory_tools
            else None
        )
        self._l4 = L4Detector(
            memory_tools=list(config.memory_tools),
            graph=create_contamination_graph(),
            ledger=self._ledger,
        )

        # Multi-agent delegation state (bound lazily via bind_delegation_graph)
        self._delegation_graph: DelegationGraph | None = None
        self._manifest_verifier: Verifier | None = None
        self._current_risk_state = RiskState()

        # Per-inspector executor used to enforce ``inspection_timeout_ms``
        # and to back the non-blocking async handle. Bounded to one worker;
        # we don't want two turns for the same session racing.
        self._exec = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix=f"cerberus-{self._agent_id[:8]}"
        )
        self._lock = threading.Lock()

        # One-shot registration-time MCP poisoning scan. Any hit is emitted
        # as a HIGH event so Guard sees that the agent was booted with a
        # tool whose description is trying to manipulate the model.
        if config.mcp_scanner_enabled and config.declared_tools:
            for result in scan_tool_descriptions(config.declared_tools):
                if not result.poisoned:
                    continue
                severity = (
                    Severity.CRITICAL
                    if result.severity == "high"
                    else Severity.HIGH
                    if result.severity == "medium"
                    else Severity.ADVISORY
                )
                self._emit(
                    SecurityEvent(
                        event_type=EventType.MCP_TOOL_POISONED,
                        severity=severity,
                        turn_id="registration",
                        session_id=self._session_id,
                        payload={
                            "tool_name": result.tool_name,
                            "patterns": list(result.patterns_found),
                            "phase": "registration",
                        },
                    )
                )

        # Emit a startup warning if Observe fell back to an ephemeral key.
        warning = self._observe.emit_ephemeral_key_warning()
        if warning is not None:
            self._emit(warning)

    def _parse_tool_calls(self, raw_tool_calls: list[dict[str, Any]] | None) -> list[ToolCall]:
        """Parse raw tool call dicts into ToolCall models."""
        if not raw_tool_calls:
            return []
        result = []
        for tc in raw_tool_calls:
            try:
                import json
                args = tc.get("arguments", tc.get("function", {}).get("arguments", {}))
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except Exception:
                        args = {"raw": args}
                result.append(ToolCall(
                    id=tc.get("id", str(uuid.uuid4())),
                    name=tc.get("name", tc.get("function", {}).get("name", "unknown")),
                    arguments=args if isinstance(args, dict) else {},
                    raw_arguments=str(args),
                ))
            except Exception:
                logging.debug("Failed to parse tool call: %s", tc, exc_info=True)
        return result

    def _emit(self, event: SecurityEvent) -> None:
        self._sequence_number += 1
        event.sequence_number = self._sequence_number
        self._observe.emit(event)

    # ── Multi-agent binding ───────────────────────────────────────────────

    def bind_delegation_graph(
        self,
        graph: DelegationGraph,
        verifier: Verifier | None = None,
    ) -> None:
        """Bind a signed delegation graph to this inspector.

        Every subsequent ``inspect()`` call will verify the graph signature
        before any detector runs (the *manifest gate*) and, after detection,
        correlate the per-turn risk state across the delegation chain for
        CROSS_AGENT_TRIFECTA / CONTEXT_CONTAMINATION_PROPAGATION /
        UNAUTHORIZED_AGENT_SPAWN.
        """
        with self._lock:
            self._delegation_graph = graph
            self._manifest_verifier = verifier

    # ── Inspect ───────────────────────────────────────────────────────────

    def inspect(
        self,
        messages: list[Message] | list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None = None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> InspectionResult:
        """
        Synchronous inspection of a complete LLM turn.

        Runs pre-flight checks (size limit, manifest gate) before the
        detection pipeline. If ``inspection_timeout_ms`` is set and exceeded,
        returns a fail-secure BLOCKED result with ``INSPECTION_TIMEOUT``.

        Args:
            messages: Conversation messages (Message objects or dicts)
            tool_calls: Tool calls made in this turn (optional)
            partial_signal_callback: Called for each partial detection signal

        Returns:
            InspectionResult — check .blocked and .trifecta_detected
        """
        start_us = time.perf_counter_ns() // 1000
        turn_id = str(uuid.uuid4())

        # ── Pre-flight: per-turn size limit (Sprint 7, fail-secure) ─────────
        size_block = self._check_size_limit(messages, tool_calls, turn_id, start_us)
        if size_block is not None:
            return size_block

        # ── Pre-flight: per-turn manifest gate (v1.3.0 TS parity) ───────────
        manifest_block = self._check_manifest_gate(turn_id, start_us)
        if manifest_block is not None:
            return manifest_block

        # ── Detection with optional hard timeout ────────────────────────────
        timeout_ms = self._config.inspection_timeout_ms
        if timeout_ms and timeout_ms > 0:
            try:
                future = self._exec.submit(
                    self._inspect_core,
                    messages,
                    tool_calls,
                    partial_signal_callback,
                    turn_id,
                    start_us,
                )
                return future.result(timeout=timeout_ms / 1000.0)
            except concurrent.futures.TimeoutError:
                end_us = time.perf_counter_ns() // 1000
                event = SecurityEvent(
                    event_type=EventType.INSPECTION_TIMEOUT,
                    severity=Severity.CRITICAL,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={"timeout_ms": timeout_ms},
                    blocked=True,
                )
                self._emit(event)
                return InspectionResult(
                    turn_id=turn_id,
                    session_id=self._session_id,
                    blocked=True,
                    severity=Severity.CRITICAL,
                    events=[event],
                    inspection_latency_us=end_us - start_us,
                )

        return self._inspect_core(
            messages, tool_calls, partial_signal_callback, turn_id, start_us
        )

    # ── Pre-flight helpers ────────────────────────────────────────────────

    def _check_size_limit(
        self,
        messages: list[Message] | list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None,
        turn_id: str,
        start_us: int,
    ) -> InspectionResult | None:
        limit = self._config.max_turn_bytes
        if not limit or limit <= 0:
            return None
        total = 0
        for m in messages:
            if isinstance(m, Message):
                total += len(m.model_dump_json())
            else:
                total += len(str(m))
            if total > limit:
                break
        if total <= limit and tool_calls:
            for tc in tool_calls:
                total += len(str(tc))
                if total > limit:
                    break
        if total <= limit:
            return None
        end_us = time.perf_counter_ns() // 1000
        event = SecurityEvent(
            event_type=EventType.TURN_SIZE_EXCEEDED,
            severity=Severity.CRITICAL,
            turn_id=turn_id,
            session_id=self._session_id,
            payload={"turn_bytes": total, "limit_bytes": limit},
            blocked=True,
        )
        self._emit(event)
        return InspectionResult(
            turn_id=turn_id,
            session_id=self._session_id,
            blocked=True,
            severity=Severity.CRITICAL,
            events=[event],
            inspection_latency_us=end_us - start_us,
        )

    def _check_manifest_gate(
        self, turn_id: str, start_us: int
    ) -> InspectionResult | None:
        if not self._config.manifest_gate_enabled:
            return None
        graph = self._delegation_graph
        if graph is None:
            return None
        signal = verify_manifest_before_turn(
            graph, self._session_id, turn_id, self._manifest_verifier
        )
        if signal is None:
            return None
        end_us = time.perf_counter_ns() // 1000
        event = SecurityEvent(
            event_type=EventType.MANIFEST_SIGNATURE_INVALID,
            severity=Severity.CRITICAL,
            turn_id=turn_id,
            session_id=self._session_id,
            payload={
                "algorithm": signal.algorithm,
                "key_id": signal.key_id,
                "reason": signal.reason,
            },
            blocked=True,
        )
        self._emit(event)
        return InspectionResult(
            turn_id=turn_id,
            session_id=self._session_id,
            blocked=True,
            severity=Severity.CRITICAL,
            events=[event],
            inspection_latency_us=end_us - start_us,
        )

    # ── Core pipeline ─────────────────────────────────────────────────────

    def _inspect_core(
        self,
        messages: list[Message] | list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None,
        turn_id: str,
        start_us: int,
    ) -> InspectionResult:
        self._turn_counter += 1
        self._l3_state.advance_turn()

        events: list[SecurityEvent] = []

        # Normalize message dicts to Message objects
        normalized_messages: list[Message] = []
        for m in messages:
            if isinstance(m, dict):
                fields = {
                    k: v for k, v in m.items()
                    if k in Message.model_fields
                }
                # Coerce non-standard content types to string
                content = fields.get("content")
                if content is not None and not isinstance(
                    content, (str, list)
                ):
                    fields["content"] = str(content)
                normalized_messages.append(Message(**fields))
            else:
                normalized_messages.append(m)

        parsed_tool_calls = self._parse_tool_calls(tool_calls)

        # ── Context Window Check (runs before L1/L2/L3) ──────────────────────
        full_content = " ".join(
            m.content if isinstance(m.content, str) else str(m.content or "")
            for m in normalized_messages
        )
        region_names = self._config.always_inspect_regions
        cw_regions = AlwaysInspectRegions(
            system_prompts="system_prompt" in region_names,
            tool_schemas="tool_schemas" in region_names,
            tool_results="tool_results" in region_names,
        )
        cw_result = analyze_context_window(
            content=full_content,
            turn_id=turn_id,
            context_window_limit=self._config.context_window_limit,
            overflow_action=self._config.overflow_action.value.lower().replace(
                "_", "-"
            ),
            always_inspect_regions=cw_regions,
        )

        context_overflow = cw_result.overflow
        if cw_result.signal:
            event = SecurityEvent(
                event_type=EventType.CONTEXT_OVERFLOW,
                severity=Severity.ADVISORY,
                turn_id=turn_id,
                session_id=self._session_id,
                payload={
                    "total_tokens": cw_result.total_tokens,
                    "limit": cw_result.limit,
                    "segments_inspected": len(cw_result.inspected_segments),
                    "segments_dropped": len(cw_result.dropped_segments),
                },
            )
            events.append(event)
            self._emit(event)

        if cw_result.blocked:
            end_us = time.perf_counter_ns() // 1000
            return InspectionResult(
                turn_id=turn_id,
                session_id=self._session_id,
                blocked=True,
                severity=Severity.CRITICAL,
                events=events,
                inspection_latency_us=end_us - start_us,
                context_overflow=True,
            )

        # ── L1 Detection ──────────────────────────────────────────────────────
        l1_result = self._l1.detect(normalized_messages, parsed_tool_calls)
        l1_active = l1_result.confidence >= 0.60

        if l1_active:
            self._privileged_values_count += 1

            # Record data flow token for cross-turn tracking
            content_text = " ".join(
                m.content if isinstance(m.content, str) else str(m.content or "")
                for m in normalized_messages if m.role == "tool"
            )
            fingerprint = __import__("hashlib").sha256(content_text.encode()).hexdigest()[:16]
            self._l3_state.record_l1_data_access("DETECTED", fingerprint)

            event = SecurityEvent(
                event_type=EventType.PARTIAL_L1,
                severity=Severity.ADVISORY,
                turn_id=turn_id,
                session_id=self._session_id,
                l1_detail=l1_result,
                conditions=TrifectaConditions(l1_privileged_data=True),
            )
            events.append(event)
            self._emit(event)
            if partial_signal_callback:
                partial_signal_callback(event)

        # ── L2 Detection ──────────────────────────────────────────────────────
        l2_result = self._l2.detect(normalized_messages)
        l2_active = l2_result.confidence >= 0.60

        if l2_active:
            self._l3_state.record_l2_detected()
            event = SecurityEvent(
                event_type=EventType.PARTIAL_L2,
                severity=Severity.HIGH if l1_active else Severity.ADVISORY,
                turn_id=turn_id,
                session_id=self._session_id,
                l2_detail=l2_result,
                conditions=TrifectaConditions(l1_privileged_data=l1_active, l2_injection=True),
            )
            events.append(event)
            self._emit(event)
            if partial_signal_callback:
                partial_signal_callback(event)

        # ── L3 Detection ──────────────────────────────────────────────────────
        l3_result = self._l3.detect(
            messages=normalized_messages,
            tool_calls=parsed_tool_calls,
            session_state=self._l3_state,
            l1_active=l1_active,
            l2_active=l2_active,
        )
        l3_active = l3_result.confidence >= 0.55

        if l3_active:
            event = SecurityEvent(
                event_type=EventType.PARTIAL_L3,
                severity=Severity.ADVISORY,
                turn_id=turn_id,
                session_id=self._session_id,
                l3_detail=l3_result,
                conditions=TrifectaConditions(
                    l1_privileged_data=l1_active,
                    l2_injection=l2_active,
                    l3_exfiltration_path=True,
                ),
            )
            events.append(event)
            self._emit(event)
            if partial_signal_callback:
                partial_signal_callback(event)

        # ── Sprint 3/6: Tool Chain, Outbound Encoding, Split Exfiltration ────
        now_ms = int(time.time() * 1000)

        for tc in parsed_tool_calls:
            # Tool chain detection
            chain_signal = detect_tool_chain_exfiltration(
                tool_name=tc.name,
                turn_id=turn_id,
                timestamp=now_ms,
                tool_call_history=self._tool_chain_history,
                privileged_values_count=self._privileged_values_count,
                outbound_tools=self._outbound_tools,
            )
            if chain_signal:
                event = SecurityEvent(
                    event_type=EventType.CROSS_TURN_EXFILTRATION,
                    severity=Severity.HIGH,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={
                        "signal": chain_signal.signal,
                        "chain_tools": chain_signal.chain_tools,
                        "chain_length": chain_signal.chain_length,
                    },
                )
                events.append(event)
                self._emit(event)
                if not l3_active:
                    l3_active = True

            # Outbound encoding detection
            enc_signal = detect_outbound_encoding(
                tool_name=tc.name,
                tool_arguments=tc.arguments,
                turn_id=turn_id,
                timestamp=now_ms,
                privileged_values_count=self._privileged_values_count,
                outbound_tools=self._outbound_tools,
            )
            if enc_signal:
                event = SecurityEvent(
                    event_type=EventType.PARTIAL_L3,
                    severity=Severity.HIGH,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={
                        "signal": enc_signal.signal,
                        "encoding_types": enc_signal.encoding_types,
                        "decoded_snippet": enc_signal.decoded_snippet,
                    },
                )
                events.append(event)
                self._emit(event)
                if not l3_active:
                    l3_active = True

            # Split exfiltration detection
            split_signal = detect_split_exfiltration(
                tool_name=tc.name,
                tool_arguments=tc.arguments,
                turn_id=turn_id,
                timestamp=now_ms,
                privileged_values_count=self._privileged_values_count,
                outbound_tools=self._outbound_tools,
                session=self._split_exfil_session,
                threshold_bytes=self._config.split_exfil_threshold_bytes,
            )
            if split_signal:
                event = SecurityEvent(
                    event_type=EventType.SPLIT_EXFILTRATION,
                    severity=Severity.HIGH,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={
                        "signal": split_signal.signal,
                        "outbound_call_count": split_signal.outbound_call_count,
                        "cumulative_bytes": split_signal.cumulative_bytes,
                        "sequential_pattern": split_signal.sequential_pattern,
                    },
                )
                events.append(event)
                self._emit(event)
                if not l3_active:
                    l3_active = True

            # ── MCP Tool Poisoning (per-call) ─────────────────────────────
            if self._config.mcp_scanner_enabled:
                mcp_result = check_tool_call_poisoning(
                    tool_name=tc.name, tools=self._config.declared_tools
                )
                if mcp_result is not None and mcp_result.poisoned:
                    severity = (
                        Severity.CRITICAL
                        if mcp_result.severity == "high"
                        else Severity.HIGH
                        if mcp_result.severity == "medium"
                        else Severity.ADVISORY
                    )
                    event = SecurityEvent(
                        event_type=EventType.MCP_TOOL_POISONED,
                        severity=severity,
                        turn_id=turn_id,
                        session_id=self._session_id,
                        payload={
                            "tool_name": mcp_result.tool_name,
                            "patterns": list(mcp_result.patterns_found),
                            "phase": "invocation",
                        },
                    )
                    events.append(event)
                    self._emit(event)
                    if not l2_active:
                        l2_active = True

            # Record tool call in chain history for future turns
            self._tool_chain_history.append(
                ToolChainEntry(tool_name=tc.name, turn_id=turn_id)
            )

        # ── EGI Check ─────────────────────────────────────────────────────────
        egi_violations = self._egi.check_turn(
            tool_calls=parsed_tool_calls,
            current_turn=self._turn_counter,
            l2_active=l2_active,
        )
        for v in egi_violations:
            event = SecurityEvent(
                event_type=EventType.EGI_VIOLATION,
                severity=Severity.CRITICAL,
                turn_id=turn_id,
                session_id=self._session_id,
                egi_violation=v,
                blocked=True,
            )
            events.append(event)
            self._emit(event)

        # ── Trifecta Correlation ──────────────────────────────────────────────
        conditions = TrifectaConditions(
            l1_privileged_data=l1_active,
            l2_injection=l2_active,
            l3_exfiltration_path=l3_active,
        )
        blocked = conditions.trifecta_active or bool(egi_violations)

        if conditions.trifecta_active:
            trifecta_event = SecurityEvent(
                event_type=EventType.LETHAL_TRIFECTA,
                severity=Severity.CRITICAL,
                turn_id=turn_id,
                session_id=self._session_id,
                conditions=conditions,
                l1_detail=l1_result,
                l2_detail=l2_result,
                l3_detail=l3_result,
                blocked=True,
                payload={
                    "l1_evidence": l1_result.evidence,
                    "l2_evidence": l2_result.evidence,
                    "l3_evidence": l3_result.evidence,
                    "l1_confidence": l1_result.confidence,
                    "l2_confidence": l2_result.confidence,
                    "l3_confidence": l3_result.confidence,
                },
            )
            events.append(trifecta_event)
            self._emit(trifecta_event)

        # ── Cross-agent correlation (multi-agent deployments) ────────────────
        if self._delegation_graph is not None:
            self._current_risk_state = RiskState(
                l1=self._current_risk_state.l1 or l1_active,
                l2=self._current_risk_state.l2 or l2_active,
                l3=self._current_risk_state.l3 or l3_active,
            )
            update_risk_state(
                self._delegation_graph, self._agent_id, self._current_risk_state
            )
            spawn_signal = detect_unauthorized_agent_spawn(
                self._delegation_graph, self._agent_id, turn_id
            )
            if spawn_signal is not None:
                event = SecurityEvent(
                    event_type=EventType.UNAUTHORIZED_AGENT_SPAWN,
                    severity=Severity.CRITICAL,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={"agent_id": spawn_signal.agent_id},
                    blocked=True,
                )
                events.append(event)
                self._emit(event)
                blocked = True

            cross_signal = detect_cross_agent_trifecta(
                self._delegation_graph,
                self._agent_id,
                self._current_risk_state,
                turn_id,
            )
            if cross_signal is not None:
                event = SecurityEvent(
                    event_type=EventType.CROSS_AGENT_TRIFECTA,
                    severity=Severity.CRITICAL,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={
                        "contributing_agents": list(cross_signal.contributing_agents),
                    },
                    blocked=True,
                )
                events.append(event)
                self._emit(event)
                blocked = True

            cc_signal = detect_context_contamination(
                self._delegation_graph, self._agent_id, turn_id
            )
            if cc_signal is not None:
                event = SecurityEvent(
                    event_type=EventType.CONTEXT_CONTAMINATION_PROPAGATION,
                    severity=Severity.HIGH,
                    turn_id=turn_id,
                    session_id=self._session_id,
                    payload={
                        "source_agent_id": cc_signal.source_agent_id,
                        "contaminated_agent_id": cc_signal.contaminated_agent_id,
                        "contamination_chain": list(cc_signal.contamination_chain),
                    },
                )
                events.append(event)
                self._emit(event)

        end_us = time.perf_counter_ns() // 1000
        latency_us = end_us - start_us

        return InspectionResult(
            turn_id=turn_id,
            session_id=self._session_id,
            blocked=blocked,
            conditions=conditions,
            severity=conditions.severity,
            events=events,
            egi_violations=egi_violations,
            inspection_latency_us=latency_us,
            context_overflow=context_overflow,
        )

    async def inspect_async(
        self,
        messages: list[Message] | list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None = None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> InspectionResult:
        """
        Async wrapper for inspect(). Runs inspection in asyncio executor
        to avoid blocking the event loop.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.inspect(messages, tool_calls, partial_signal_callback),
        )

    def inspect_async_nonblocking(
        self,
        messages: list[Message] | list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None = None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> InspectionHandle:
        """Schedule an inspection without blocking the caller.

        Returns an :class:`InspectionHandle` the caller can poll,
        ``await`` via ``handle.result()``, or attach callbacks to with
        ``handle.on_complete()`` / ``handle.on_block()``. Use this
        variant when the agent wants to keep generating tokens while
        inspection runs on a worker thread — the verdict is still
        required before any outbound tool call is dispatched.

        Pre-flight checks (size limit + manifest gate) run synchronously
        on the caller; only ``_inspect_core`` is submitted to the worker
        executor. This avoids self-deadlock on the single-worker pool
        that backs ``inspection_timeout_ms``.
        """
        start_us = time.perf_counter_ns() // 1000
        turn_id = str(uuid.uuid4())

        size_block = self._check_size_limit(messages, tool_calls, turn_id, start_us)
        if size_block is not None:
            return InspectionHandle(_completed_future(size_block))

        manifest_block = self._check_manifest_gate(turn_id, start_us)
        if manifest_block is not None:
            return InspectionHandle(_completed_future(manifest_block))

        future = self._exec.submit(
            self._inspect_core,
            messages,
            tool_calls,
            partial_signal_callback,
            turn_id,
            start_us,
        )
        return InspectionHandle(future)

    def inspect_memory_tool_result(
        self,
        *,
        tool_name: str,
        tool_arguments: dict[str, Any],
        tool_result: str,
        trust_level: TrustLevel | str = TrustLevel.UNKNOWN,
    ) -> MemoryContaminationSignal | None:
        """Feed a completed memory-tool call through the L4 detector.

        Callers invoke this after a declared memory tool
        (``MemoryToolConfig``) returns, so the contamination graph and
        provenance ledger can record the taint of the stored / read
        node. If a read surfaces a node whose lineage contains an
        ``untrusted`` ancestor from a different session, a
        ``CONTAMINATED_MEMORY_ACTIVE`` event is emitted and the signal
        returned.
        """
        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)

        signal = self._l4.on_tool_call(
            session_id=self._session_id,
            turn_id=str(uuid.uuid4()),
            tool_name=tool_name,
            tool_arguments=tool_arguments,
            tool_result=tool_result,
            trust_level=trust_level,
        )
        if signal is not None:
            event = SecurityEvent(
                event_type=EventType.CONTAMINATED_MEMORY_ACTIVE,
                severity=Severity.HIGH,
                turn_id=signal.turn_id,
                session_id=self._session_id,
                payload={
                    "tool_name": signal.tool_name,
                    "node_id": signal.node_id,
                    "contamination_source": signal.contamination_source,
                },
            )
            self._emit(event)
        return signal

    def close(self) -> None:
        """Shut down the per-inspector worker thread + flush Observe + close ledger."""
        try:
            self._exec.shutdown(wait=False, cancel_futures=True)
        except Exception as e:  # noqa: BLE001
            logger.debug("Inspector executor shutdown failed: %s", e)
        if self._ledger is not None:
            try:
                self._ledger.close()
            except Exception as e:  # noqa: BLE001
                logger.debug("Inspector ledger close failed: %s", e)
        try:
            self._observe.close()
        except Exception as e:  # noqa: BLE001
            logger.debug("Inspector observe close failed: %s", e)

    def register_tool_late(
        self,
        tool: Any,
        reason: str,
        authorized_by: str,
    ) -> tuple[bool, str]:
        """Register a tool after initialization via the controlled late-binding hook."""
        from cerberus_ai.models import ToolSchema
        if not isinstance(tool, ToolSchema):
            # Allow dict-style registration
            tool = ToolSchema(**tool) if isinstance(tool, dict) else tool

        l2_active = self._l3_state.l2_detected_recently(window=1)
        success, message = self._egi.register_tool_late(
            tool=tool,
            reason=reason,
            authorized_by=authorized_by,
            current_turn=self._turn_counter,
            l2_active=l2_active,
        )

        if not success:
            event = SecurityEvent(
                event_type=EventType.EGI_INJECTION_ASSISTED_REGISTRATION,
                severity=Severity.CRITICAL,
                turn_id=str(uuid.uuid4()),
                session_id=self._session_id,
                payload={"tool_name": tool.name, "reason": reason, "message": message},
                blocked=True,
            )
            self._emit(event)

        return success, message
