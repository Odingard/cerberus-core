"""
cerberus_ai.integrations.llamaindex
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LlamaIndex integration for Cerberus.

Two integration patterns:

* :class:`CerberusCallbackHandler` — a minimal LlamaIndex
  :class:`~llama_index.core.callbacks.base_handler.BaseCallbackHandler`
  that inspects every LLM turn and, separately, every tool invocation.
* :func:`wrap_engine` — convenience wrapper that attaches the handler
  to a chat engine or query engine's ``callback_manager``.

The handler intentionally works without importing any LlamaIndex
symbols at module load so ``cerberus-ai`` remains an optional
dependency: duck typing is used for ``CBEventType`` / ``EventPayload``
access.

Install::

    pip install cerberus-ai[llamaindex]
"""
from __future__ import annotations

import logging
from typing import Any

from cerberus_ai import Cerberus, SecurityError
from cerberus_ai.models import CerberusConfig, InspectionResult

logger = logging.getLogger(__name__)


class CerberusCallbackHandler:
    """LlamaIndex callback handler that runs Cerberus inspection.

    Attach to a ``CallbackManager`` on a LlamaIndex chat / query engine::

        from llama_index.core.callbacks import CallbackManager
        from cerberus_ai import Cerberus
        from cerberus_ai.integrations.llamaindex import CerberusCallbackHandler

        cerberus = Cerberus(config)
        handler = CerberusCallbackHandler(cerberus, raise_on_block=True)
        cb_mgr = CallbackManager([handler])
        engine = index.as_chat_engine(callback_manager=cb_mgr)
    """

    event_starts_to_ignore: list[str] = []
    event_ends_to_ignore: list[str] = []

    def __init__(
        self,
        cerberus: Cerberus,
        raise_on_block: bool = True,
    ) -> None:
        self._cerberus = cerberus
        self._raise_on_block = raise_on_block
        self._last_result: InspectionResult | None = None

    # LlamaIndex callback API — minimal surface implemented.
    def on_event_start(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: dict[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        if payload is None:
            return
        name = getattr(event_type, "value", str(event_type)).lower()
        if "llm" in name:
            self._inspect_llm(payload)
        elif "function_call" in name or "tool" in name:
            self._inspect_tool(payload)

    def start_trace(self, trace_id: str | None = None) -> None: ...

    def end_trace(
        self,
        trace_id: str | None = None,
        trace_map: dict[str, list[str]] | None = None,
    ) -> None: ...

    # ── Inspection helpers ────────────────────────────────────────────

    def _inspect_llm(self, payload: dict[str, Any]) -> None:
        messages: list[dict[str, Any]] = []
        tool_calls: list[dict[str, Any]] = []

        response = payload.get("response") or payload.get("completion")
        if response is not None:
            content = getattr(response, "message", None) or response
            role = getattr(content, "role", "assistant")
            text = getattr(content, "content", str(content))
            messages.append({"role": str(role), "content": str(text)})
            raw = getattr(response, "additional_kwargs", None) or {}
            if isinstance(raw, dict):
                raw_calls = raw.get("tool_calls") or []
                if isinstance(raw_calls, list):
                    tool_calls.extend(raw_calls)

        prompt_messages = payload.get("messages")
        if isinstance(prompt_messages, list):
            for m in prompt_messages:
                messages.append(
                    {
                        "role": str(getattr(m, "role", "user")),
                        "content": str(getattr(m, "content", m)),
                    }
                )

        if not messages:
            return
        self._run(messages, tool_calls or None)

    def _inspect_tool(self, payload: dict[str, Any]) -> None:
        output = payload.get("function_call_response") or payload.get("response")
        if output is None:
            return
        self._run(
            messages=[{"role": "tool", "content": str(output)}],
            tool_calls=None,
        )

    def _run(
        self,
        messages: list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None,
    ) -> None:
        try:
            result = self._cerberus.inspect(messages=messages, tool_calls=tool_calls)
            self._last_result = result
            if result.blocked and self._raise_on_block:
                raise SecurityError(result)
        except SecurityError:
            raise
        except Exception:
            logger.debug("Cerberus inspection error in LlamaIndex handler", exc_info=True)

    @property
    def last_result(self) -> InspectionResult | None:
        return self._last_result


def wrap_engine(
    engine: Any, config: CerberusConfig | None = None, **kwargs: Any
) -> Any:
    """Attach a :class:`CerberusCallbackHandler` to a LlamaIndex engine.

    Works with any object that exposes a ``callback_manager`` attribute
    with an ``add_handler`` method (chat engines, query engines, agent
    runners). Returns the same ``engine`` for chaining.
    """
    cerberus = Cerberus(config or CerberusConfig())
    handler = CerberusCallbackHandler(cerberus, **kwargs)
    cb_mgr = getattr(engine, "callback_manager", None)
    if cb_mgr is None:
        raise AttributeError(
            "wrap_engine expected engine to expose `callback_manager`; "
            "attach CerberusCallbackHandler manually instead."
        )
    cb_mgr.add_handler(handler)
    return engine
