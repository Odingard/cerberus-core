"""
cerberus_ai
~~~~~~~~~~~
Cerberus — Python SDK for Cerberus Core runtime inspection.

Cerberus is runtime security middleware for LLM agents. One ``Cerberus``
instance per agent session inspects every LLM turn for the **Lethal
Trifecta** (L1 privileged data access + L2 untrusted content injection
+ L3 outbound exfiltration intent), **Execution Graph Integrity** (EGI)
violations, **L4 cross-session memory contamination**, and **MCP tool
poisoning**. If the trifecta co-occurs in a single turn, the turn is
blocked before the tool call goes out.

Usage (sync)::

    from cerberus_ai import Cerberus, CerberusConfig
    from cerberus_ai.models import DataSource, ToolSchema

    cerberus = Cerberus(CerberusConfig(
        data_sources=[DataSource(
            name="customer_db", classification="PII",
            description="Customer records",
        )],
        declared_tools=[ToolSchema(
            name="send_email", description="Send email",
            is_network_capable=True,
        )],
    ))

    result = cerberus.inspect(messages=messages, tool_calls=tool_calls)
    if result.blocked:
        raise Exception(f"Security block: {result.events}")

Usage (async, non-blocking)::

    handle = cerberus.inspect_async_nonblocking(messages, tool_calls)
    handle.on_block(lambda r: siem.alert(r))
    result = handle.result(timeout=0.25)  # fail-secure at 250 ms

Usage (streaming)::

    async for chunk in cerberus.stream(messages=messages):
        print(chunk["delta"], end="", flush=True)

Usage (multi-agent, signed manifest)::

    from cerberus_ai.graph.delegation import create_delegation_graph
    graph = create_delegation_graph("session-1", "orchestrator",
                                    "orchestrator", ["tool_a", "tool_b"])
    cerberus.bind_delegation_graph(graph)
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Callable
from typing import Any

__version__ = "1.3.0"

from cerberus_ai.async_inspect import InspectionHandle, InspectionStillRunning
from cerberus_ai.inspector import CerberusInspector
from cerberus_ai.models import (
    AgentType,
    CerberusConfig,
    EventType,
    InspectionResult,
    MemoryToolConfig,
    SecurityEvent,
    Severity,
    StreamingMode,
    TrustLevel,
)
from cerberus_ai.telemetry.observe import ObserveEmitter, ObserveVerifier


class SecurityError(Exception):
    """Raised when Cerberus blocks a turn."""

    def __init__(self, result: InspectionResult) -> None:
        self.result = result
        super().__init__(
            f"Cerberus blocked turn {result.turn_id}: "
            f"{result.severity} — {[e.event_type for e in result.events]}"
        )


class Cerberus:
    """
    Cerberus runtime inspection SDK — session-scoped instance.

    One Cerberus instance manages one agent session. For multi-agent
    deployments, create one instance per agent and bind the same signed
    delegation graph to each via :meth:`bind_delegation_graph`.
    """

    def __init__(
        self,
        config: CerberusConfig | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> None:
        self._config = config or CerberusConfig()
        self._session_id = session_id or str(uuid.uuid4())
        self._observe = ObserveEmitter(self._config.observe)
        self._prometheus: Any = None
        if self._config.prometheus_enabled:
            # Lazy-import so prometheus_client is only required when the
            # exporter is actually turned on. Raises a clear ImportError
            # if the 'prometheus' extras aren't installed.
            from cerberus_ai.telemetry.prometheus import PrometheusExporter
            self._prometheus = PrometheusExporter(
                observe=self._observe,
                port=self._config.prometheus_port,
                host=self._config.prometheus_host,
            )
            self._prometheus.increment_active_sessions(1)
        self._inspector = CerberusInspector(
            session_id=self._session_id,
            config=self._config,
            observe=self._observe,
            agent_id=agent_id,
        )

        # Streaming-mode advisory events (BUFFER_ALL is the safe default)
        mode = self._config.streaming_mode
        if mode == StreamingMode.PASSTHROUGH:
            self._observe.emit(SecurityEvent(
                event_type=EventType.PASSTHROUGH_MODE_ACTIVE,
                severity=Severity.HIGH,
                turn_id="config",
                session_id=self._session_id,
                payload={
                    "warning": (
                        "PASSTHROUGH mode active — full pre-tool-call"
                        " inspection is bypassed for streamed chunks;"
                        " only post-turn detection runs. Do not enable"
                        " in production for privileged-data agents."
                    ),
                },
            ))
        elif mode == StreamingMode.PARTIAL_SCAN:
            self._observe.emit(SecurityEvent(
                event_type=EventType.PARTIAL_SCAN_MODE_ACTIVE,
                severity=Severity.ADVISORY,
                turn_id="config",
                session_id=self._session_id,
                payload={
                    "warning": (
                        "PARTIAL_SCAN mode active — chunks beyond the"
                        " buffer limit are inspected incrementally;"
                        " detection coverage is slightly reduced"
                        " compared with BUFFER_ALL."
                    ),
                },
            ))

    # ── Core inspection API ────────────────────────────────────────────────────

    def inspect(
        self,
        messages: list[dict[str, Any]] | list[Any],
        tool_calls: list[dict[str, Any]] | None = None,
        raise_on_block: bool = False,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> InspectionResult:
        """
        Inspect a complete LLM turn synchronously.
        """
        result = self._inspector.inspect(
            messages=messages,
            tool_calls=tool_calls,
            partial_signal_callback=partial_signal_callback,
        )
        if raise_on_block and result.blocked:
            raise SecurityError(result)
        return result

    async def inspect_async(
        self,
        messages: list[dict[str, Any]] | list[Any],
        tool_calls: list[dict[str, Any]] | None = None,
        raise_on_block: bool = False,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> InspectionResult:
        """Async version of inspect(). Non-blocking — runs in executor."""
        result = await self._inspector.inspect_async(
            messages=messages,
            tool_calls=tool_calls,
            partial_signal_callback=partial_signal_callback,
        )
        if raise_on_block and result.blocked:
            raise SecurityError(result)
        return result

    def inspect_async_nonblocking(
        self,
        messages: list[dict[str, Any]] | list[Any],
        tool_calls: list[dict[str, Any]] | None = None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> InspectionHandle:
        """Schedule an inspection on a worker thread and return a handle.

        Use when the agent wants to keep generating while inspection
        runs in the background. Before dispatching any outbound tool
        call, the caller MUST block on ``handle.result(timeout=...)``.
        """
        return self._inspector.inspect_async_nonblocking(
            messages=messages,
            tool_calls=tool_calls,
            partial_signal_callback=partial_signal_callback,
        )

    def inspect_memory_tool_result(
        self,
        *,
        tool_name: str,
        tool_arguments: dict[str, Any],
        tool_result: str,
        trust_level: TrustLevel | str = TrustLevel.UNKNOWN,
    ) -> Any:
        """Feed a completed memory-tool result through the L4 detector."""
        return self._inspector.inspect_memory_tool_result(
            tool_name=tool_name,
            tool_arguments=tool_arguments,
            tool_result=tool_result,
            trust_level=trust_level,
        )

    async def stream(
        self,
        messages: list[dict[str, Any]] | list[Any],
        tool_calls: list[dict[str, Any]] | None = None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """
        Streaming inspection — yields chunks only after full-turn inspection passes.

        The behaviour is controlled by ``config.streaming_mode``:

        * ``BUFFER_ALL`` (default) — buffer all chunks, inspect the complete
          turn, then emit a synthetic ``inspection_pass`` chunk if safe.
        * ``PARTIAL_SCAN`` — same as ``BUFFER_ALL`` but emits a
          ``PARTIAL_SCAN_MODE_ACTIVE`` advisory at init time.
        * ``PASSTHROUGH`` — yield chunks immediately with reduced
          pre-tool-call detection (legacy compatibility).
        """
        mode = self._config.streaming_mode
        if mode == StreamingMode.PASSTHROUGH:
            # Kick off inspection in the background; still yield a
            # terminal signal when it completes so callers can tear
            # down cleanly if the verdict is BLOCKED.
            handle = self.inspect_async_nonblocking(
                messages=messages,
                tool_calls=tool_calls,
                partial_signal_callback=partial_signal_callback,
            )
            yield {
                "type": "passthrough",
                "turn_id": "passthrough",
            }
            result = handle.result()
            if result.blocked:
                return
            yield {
                "type": "inspection_pass",
                "turn_id": result.turn_id,
                "severity": result.severity.value,
                "conditions": {
                    "l1": result.conditions.l1_privileged_data,
                    "l2": result.conditions.l2_injection,
                    "l3": result.conditions.l3_exfiltration_path,
                },
            }
            return

        result = await self.inspect_async(
            messages=messages,
            tool_calls=tool_calls,
            partial_signal_callback=partial_signal_callback,
        )
        if result.blocked:
            return
        yield {
            "type": "inspection_pass",
            "turn_id": result.turn_id,
            "severity": result.severity.value,
            "conditions": {
                "l1": result.conditions.l1_privileged_data,
                "l2": result.conditions.l2_injection,
                "l3": result.conditions.l3_exfiltration_path,
            },
        }

    # ── Tool registration API ──────────────────────────────────────────────────

    def register_tool_late(
        self,
        tool: Any,
        reason: str,
        authorized_by: str,
    ) -> tuple[bool, str]:
        """Register a tool after session initialization (late-binding hook)."""
        return self._inspector.register_tool_late(
            tool=tool,
            reason=reason,
            authorized_by=authorized_by,
        )

    # ── Multi-agent binding ────────────────────────────────────────────────────

    def bind_delegation_graph(self, graph: Any, verifier: Any | None = None) -> None:
        """Bind a signed delegation graph (enables manifest gate + cross-agent)."""
        self._inspector.bind_delegation_graph(graph, verifier)

    # ── Context manager support ────────────────────────────────────────────────

    async def __aenter__(self) -> Cerberus:
        return self

    async def __aexit__(self, *args: Any) -> None:
        self.close()

    def __enter__(self) -> Cerberus:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def close(self) -> None:
        self._inspector.close()
        if self._prometheus is not None:
            try:
                self._prometheus.increment_active_sessions(-1)
            finally:
                self._prometheus.close()
                self._prometheus = None

    @property
    def prometheus_exporter(self) -> Any:
        """The :class:`PrometheusExporter` bound to this instance, or None."""
        return self._prometheus

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def config(self) -> CerberusConfig:
        return self._config


__all__ = [
    "AgentType",
    "Cerberus",
    "CerberusConfig",
    "EventType",
    "InspectionHandle",
    "InspectionResult",
    "InspectionStillRunning",
    "MemoryToolConfig",
    "ObserveEmitter",
    "ObserveVerifier",
    "SecurityError",
    "SecurityEvent",
    "Severity",
    "StreamingMode",
    "TrustLevel",
    "__version__",
]
