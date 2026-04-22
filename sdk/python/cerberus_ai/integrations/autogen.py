"""
cerberus_ai.integrations.autogen
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
AutoGen (Microsoft) integration for Cerberus.

The integration works against the ``autogen`` / ``pyautogen`` agent
surface. An :class:`CerberusAutoGenHook` wraps an existing
``ConversableAgent`` by intercepting the ``a_receive`` /
``generate_reply`` hooks to run Cerberus inspection on every inbound
message and every generated reply; generated replies containing
blocked content raise :class:`SecurityError`.

No AutoGen symbols are imported at load time so the SDK stays
optional. AutoGen is only required if you actually call
:func:`wrap_agent`.

Install::

    pip install cerberus-ai[autogen]
"""
from __future__ import annotations

import logging
from typing import Any

from cerberus_ai import Cerberus, SecurityError
from cerberus_ai.models import CerberusConfig, InspectionResult

logger = logging.getLogger(__name__)


class CerberusAutoGenHook:
    """AutoGen hook that runs Cerberus inspection on a ConversableAgent.

    Usage::

        from autogen import ConversableAgent
        from cerberus_ai import Cerberus
        from cerberus_ai.integrations.autogen import wrap_agent

        agent = ConversableAgent(name="assistant", llm_config={...})
        hook = wrap_agent(agent, config=CerberusConfig(...))
    """

    def __init__(
        self,
        cerberus: Cerberus,
        raise_on_block: bool = True,
    ) -> None:
        self._cerberus = cerberus
        self._raise_on_block = raise_on_block
        self._last_result: InspectionResult | None = None

    def inspect_message(
        self,
        message: Any,
        sender: Any = None,
        **_: Any,
    ) -> InspectionResult:
        """Inspect an inbound message from another agent."""
        content = message if isinstance(message, str) else getattr(message, "content", message)
        tool_calls = None
        if isinstance(message, dict):
            content = message.get("content", "")
            raw = message.get("tool_calls")
            if isinstance(raw, list):
                tool_calls = raw
        return self._run(
            [{"role": "assistant", "content": str(content)}], tool_calls
        )

    def inspect_reply(
        self,
        recipient: Any,
        messages: list[dict[str, Any]] | None = None,
        sender: Any = None,
        config: Any = None,
    ) -> tuple[bool, Any]:
        """Hook signature compatible with ``register_reply``.

        Returns ``(False, None)`` to let AutoGen continue (pass-through),
        or raises :class:`SecurityError` when the reply is blocked.
        """
        msgs = messages or []
        normalized: list[dict[str, Any]] = []
        tool_calls: list[dict[str, Any]] = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            normalized.append(
                {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
            )
            raw_calls = m.get("tool_calls")
            if isinstance(raw_calls, list):
                tool_calls.extend(raw_calls)
        if not normalized:
            return False, None
        self._run(normalized, tool_calls or None)
        return False, None

    def _run(
        self,
        messages: list[dict[str, Any]],
        tool_calls: list[dict[str, Any]] | None,
    ) -> InspectionResult:
        result = self._cerberus.inspect(messages=messages, tool_calls=tool_calls)
        self._last_result = result
        if result.blocked and self._raise_on_block:
            raise SecurityError(result)
        return result

    @property
    def last_result(self) -> InspectionResult | None:
        return self._last_result


def wrap_agent(
    agent: Any, config: CerberusConfig | None = None, **kwargs: Any
) -> CerberusAutoGenHook:
    """Attach Cerberus inspection to an AutoGen ``ConversableAgent``.

    Registers the hook via ``register_reply`` if available so every
    reply the agent produces is inspected. Returns the hook so callers
    can introspect ``last_result``.
    """
    cerberus = Cerberus(config or CerberusConfig())
    hook = CerberusAutoGenHook(cerberus, **kwargs)
    register_reply = getattr(agent, "register_reply", None)
    if callable(register_reply):
        try:
            register_reply(trigger=[object], reply_func=hook.inspect_reply)
        except Exception:  # noqa: BLE001 — AutoGen API varies by version
            register_reply(trigger=None, reply_func=hook.inspect_reply)
    else:
        logger.warning(
            "AutoGen agent %r has no register_reply; use hook.inspect_message manually",
            agent,
        )
    return hook
