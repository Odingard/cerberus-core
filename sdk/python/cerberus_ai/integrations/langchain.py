"""
cerberus_ai.integrations.langchain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LangChain integration for Cerberus.

Two integration patterns:
  1. CerberusCallbackHandler — attach to any LangChain chain/agent
  2. wrap_chain() / wrap_agent() — convenience wrappers

Install: pip install cerberus-ai[langchain]
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from cerberus_ai import Cerberus, SecurityError
from cerberus_ai.models import CerberusConfig, InspectionResult

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class CerberusCallbackHandler:
    """
    LangChain callback handler that runs Cerberus inspection on every LLM turn.

    Usage:
        from cerberus_ai.integrations.langchain import CerberusCallbackHandler
        from langchain_openai import ChatOpenAI

        cerberus = Cerberus(config)
        handler = CerberusCallbackHandler(cerberus, raise_on_block=True)
        llm = ChatOpenAI(callbacks=[handler])
    """

    def __init__(
        self,
        cerberus: Cerberus,
        raise_on_block: bool = True,
    ) -> None:
        self._cerberus = cerberus
        self._raise_on_block = raise_on_block
        self._last_result: InspectionResult | None = None

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called after LLM generates a response — inspect the full turn."""
        try:
            generations = getattr(response, "generations", [[]])
            messages = []
            tool_calls = []

            for gen_list in generations:
                for gen in gen_list:
                    msg = getattr(gen, "message", None)
                    if msg:
                        messages.append({
                            "role": getattr(msg, "type", "assistant"),
                            "content": getattr(msg, "content", ""),
                        })
                        # Extract tool calls if present
                        additional_kwargs = getattr(msg, "additional_kwargs", {})
                        if "tool_calls" in additional_kwargs:
                            tool_calls.extend(additional_kwargs["tool_calls"])

            if messages:
                result = self._cerberus.inspect(
                    messages=messages,
                    tool_calls=tool_calls or None,
                )
                self._last_result = result
                if result.blocked and self._raise_on_block:
                    raise SecurityError(result)

        except SecurityError:
            raise
        except Exception:
            logging.debug("Cerberus inspection error in on_llm_end", exc_info=True)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called after a tool executes — inspect tool result for injection."""
        try:
            result = self._cerberus.inspect(
                messages=[{"role": "tool", "content": str(output)}],
            )
            self._last_result = result
            if result.blocked and self._raise_on_block:
                raise SecurityError(result)
        except SecurityError:
            raise
        except Exception:
            logging.debug("Cerberus inspection error in on_tool_end", exc_info=True)

    @property
    def last_result(self) -> InspectionResult | None:
        return self._last_result


def wrap_chain(chain: Any, config: CerberusConfig | None = None, **kwargs: Any) -> Any:
    """
    Wrap a LangChain chain with Cerberus inspection.

    Returns the chain with a CerberusCallbackHandler attached.

    Usage:
        from langchain_openai import ChatOpenAI
        from langchain.schema.runnable import RunnableLambda
        from cerberus_ai.integrations.langchain import wrap_chain

        chain = ChatOpenAI() | RunnableLambda(lambda x: x)
        secured_chain = wrap_chain(chain)
        result = secured_chain.invoke({"input": "Hello"})
    """
    cerberus = Cerberus(config or CerberusConfig())
    handler = CerberusCallbackHandler(cerberus, **kwargs)

    # Attach callback via config
    existing_config = getattr(chain, "config", {}) or {}
    callbacks = existing_config.get("callbacks", [])
    callbacks.append(handler)

    return chain.with_config({"callbacks": callbacks})


def wrap_agent(agent: Any, config: CerberusConfig | None = None, **kwargs: Any) -> Any:
    """
    Wrap a LangChain agent executor with Cerberus inspection.

    Usage:
        from cerberus_ai.integrations.langchain import wrap_agent
        secured_agent = wrap_agent(agent_executor, config=my_config)
        result = secured_agent.invoke({"input": "Do something"})
    """
    cerberus = Cerberus(config or CerberusConfig())
    handler = CerberusCallbackHandler(cerberus, **kwargs)

    existing_callbacks = getattr(agent, "callbacks", []) or []
    agent.callbacks = existing_callbacks + [handler]
    return agent
