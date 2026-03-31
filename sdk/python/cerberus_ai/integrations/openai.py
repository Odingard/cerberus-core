"""
cerberus_ai.integrations.openai
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
OpenAI SDK integration helpers for Cerberus inspection.

Install: pip install cerberus-ai[openai]

Usage:
    from cerberus_ai.integrations.openai import CerberusOpenAI
    from cerberus_ai.models import CerberusConfig, DataSource, ToolSchema

    client = CerberusOpenAI(
        config=CerberusConfig(
            data_sources=[DataSource(
                name="customer_db",
                classification="PII",
                description="CRM data",
            )],
            declared_tools=[ToolSchema(
                name="send_email",
                description="Send email",
                is_network_capable=True,
            )],
        )
    )

    # Convenience wrapper around openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Help me"}],
    )
"""
from __future__ import annotations

from typing import Any

from cerberus_ai import Cerberus, SecurityError
from cerberus_ai.models import CerberusConfig


class _SecuredCompletions:
    def __init__(self, completions: Any, cerberus: Cerberus, raise_on_block: bool) -> None:
        self._completions = completions
        self._cerberus = cerberus
        self._raise_on_block = raise_on_block

    def create(self, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        response = self._completions.create(messages=messages, **kwargs)

        # Build inspection messages (input + response)
        response_messages = list(messages)
        choices = getattr(response, "choices", [])
        tool_calls_raw = []
        for choice in choices:
            msg = getattr(choice, "message", None)
            if msg:
                response_messages.append({
                    "role": getattr(msg, "role", "assistant"),
                    "content": getattr(msg, "content", "") or "",
                })
                tcs = getattr(msg, "tool_calls", None) or []
                for tc in tcs:
                    fn = getattr(tc, "function", None)
                    if fn:
                        tool_calls_raw.append({
                            "id": getattr(tc, "id", ""),
                            "name": getattr(fn, "name", ""),
                            "arguments": getattr(fn, "arguments", "{}"),
                        })

        result = self._cerberus.inspect(
            messages=response_messages,
            tool_calls=tool_calls_raw or None,
        )
        if result.blocked and self._raise_on_block:
            raise SecurityError(result)

        return response


class _SecuredChat:
    def __init__(self, chat: Any, cerberus: Cerberus, raise_on_block: bool) -> None:
        self.completions = _SecuredCompletions(chat.completions, cerberus, raise_on_block)


class CerberusOpenAI:
    """
    Convenience wrapper around openai.OpenAI() with Cerberus inspection.

    All chat.completions.create() calls are inspected before the response
    is returned to the caller.
    """

    def __init__(
        self,
        config: CerberusConfig | None = None,
        raise_on_block: bool = True,
        **openai_kwargs: Any,
    ) -> None:
        try:
            import openai
        except ImportError as e:
            raise ImportError("pip install cerberus-ai[openai]") from e

        self._cerberus = Cerberus(config or CerberusConfig())
        self._client = openai.OpenAI(**openai_kwargs)
        self.chat = _SecuredChat(self._client.chat, self._cerberus, raise_on_block)
        self.models = self._client.models
        self.embeddings = self._client.embeddings


class CerberusAnthropic:
    """
    Convenience wrapper around anthropic.Anthropic() with Cerberus inspection.

    Install: pip install cerberus-ai[anthropic]
    """

    def __init__(
        self,
        config: CerberusConfig | None = None,
        raise_on_block: bool = True,
        **anthropic_kwargs: Any,
    ) -> None:
        try:
            import anthropic
        except ImportError as e:
            raise ImportError("pip install cerberus-ai[anthropic]") from e

        self._cerberus = Cerberus(config or CerberusConfig())
        self._client = anthropic.Anthropic(**anthropic_kwargs)
        self._raise_on_block = raise_on_block

    def inspect_and_return(self, request_messages: list[Any], response: Any) -> Any:
        """Inspect a response and return it if safe, raise SecurityError if blocked."""
        messages = list(request_messages)
        content = getattr(response, "content", [])
        for block in content:
            block_type = getattr(block, "type", "")
            if block_type == "text":
                messages.append({"role": "assistant", "content": getattr(block, "text", "")})
            elif block_type == "tool_use":
                messages.append({"role": "assistant", "content": str(block)})

        result = self._cerberus.inspect(messages=messages)
        if result.blocked and self._raise_on_block:
            raise SecurityError(result)
        return response

    @property
    def messages(self) -> Any:
        return _SecuredAnthropicMessages(self._client.messages, self)


class _SecuredAnthropicMessages:
    def __init__(self, messages: Any, parent: CerberusAnthropic) -> None:
        self._messages = messages
        self._parent = parent

    def create(self, messages: list[Any], **kwargs: Any) -> Any:
        response = self._messages.create(messages=messages, **kwargs)
        return self._parent.inspect_and_return(messages, response)
