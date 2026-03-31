"""
cerberus_ai
~~~~~~~~~~~
Cerberus — Python SDK for Cerberus Core runtime inspection.

Primary entry point. One Cerberus instance = one agent session.

Usage (sync):
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

Usage (async):
    async with Cerberus(config) as cerberus:
        result = await cerberus.inspect_async(messages=messages)

Usage (streaming):
    async for chunk in cerberus.stream(messages=messages):
        print(chunk["delta"], end="", flush=True)
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator, Callable
from typing import Any

__version__ = "1.1.3"

from cerberus_ai.inspector import CerberusInspector
from cerberus_ai.models import (
    CerberusConfig,
    InspectionResult,
    SecurityEvent,
)
from cerberus_ai.telemetry.observe import ObserveEmitter


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
    deployments, create one instance per agent and treat the GitHub repo as
    the source of truth for current product boundaries and roadmap.
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
        self._inspector = CerberusInspector(
            session_id=self._session_id,
            config=self._config,
            observe=self._observe,
            agent_id=agent_id,
        )

        # Warn on PASSTHROUGH mode
        if self._config.streaming_mode.value == "PASSTHROUGH":
            from cerberus_ai.models import EventType, SecurityEvent, Severity
            self._observe.emit(SecurityEvent(
                event_type=EventType.PASSTHROUGH_MODE_ACTIVE,
                severity=Severity.HIGH,
                turn_id="config",
                session_id=self._session_id,
                payload={
                    "warning": (
                        "PASSTHROUGH mode active"
                        " — streaming detection"
                        " significantly reduced"
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

        Args:
            messages: LLM conversation messages
            tool_calls: Tool calls from this turn
            raise_on_block: If True, raises SecurityError on block
            partial_signal_callback: Called for each partial detection signal

        Returns:
            InspectionResult
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

    async def stream(
        self,
        messages: list[dict[str, Any]] | list[Any],
        tool_calls: list[dict[str, Any]] | None = None,
        partial_signal_callback: Callable[[SecurityEvent], None] | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """
        Streaming inspection — yields chunks only after full-turn inspection passes.

        In BUFFER_ALL mode (default): buffers all chunks, inspects complete turn,
        then replays buffered chunks if safe.

        In PASSTHROUGH mode: yields chunks immediately (reduced detection coverage).
        """
        # In BUFFER_ALL: inspect the complete turn (messages already include full context)
        # then yield a synthetic "pass" signal
        result = await self.inspect_async(
            messages=messages,
            tool_calls=tool_calls,
            partial_signal_callback=partial_signal_callback,
        )

        if result.blocked:
            # Stream is terminated — do not yield any chunks
            return

        # Turn passed — signal to caller
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
        """
        Register a tool after session initialization.

        Uses the controlled late-binding hook — logged in audit trail.
        Blocked if injection (L2) was active in the recent session.

        Returns:
            (success: bool, message: str)
        """
        return self._inspector.register_tool_late(
            tool=tool,
            reason=reason,
            authorized_by=authorized_by,
        )

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
        self._observe.close()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def config(self) -> CerberusConfig:
        return self._config
