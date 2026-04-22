"""
cerberus_ai.integrations.langgraph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
LangGraph integration for Cerberus.

LangGraph builds agent graphs where each node is a callable receiving
a state dict and returning an updated state dict. The
:func:`wrap_node` decorator runs Cerberus inspection on the node's
input messages and (optionally) its output messages, blocking any
reply that would satisfy the Lethal Trifecta or propagate a
cross-session contamination.

For *multi-agent* graphs, bind a signed delegation graph to the
inspector via :meth:`cerberus_ai.Cerberus.bind_delegation_graph` at
graph-build time so cross-agent correlation fires when the trifecta
is satisfied across nodes.

Install::

    pip install cerberus-ai[langgraph]
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from typing import Any

from cerberus_ai import Cerberus, SecurityError
from cerberus_ai.models import CerberusConfig, InspectionResult

logger = logging.getLogger(__name__)

NodeFn = Callable[[dict[str, Any]], dict[str, Any]]


def _collect_messages(state: dict[str, Any]) -> list[dict[str, Any]]:
    raw = state.get("messages") if isinstance(state, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for m in raw:
        if isinstance(m, dict):
            out.append(
                {
                    "role": str(m.get("role") or m.get("type") or "user"),
                    "content": str(m.get("content", "")),
                }
            )
        else:
            out.append(
                {
                    "role": str(getattr(m, "type", "user")),
                    "content": str(getattr(m, "content", m)),
                }
            )
    return out


def _collect_tool_calls(state: dict[str, Any]) -> list[dict[str, Any]]:
    raw = state.get("messages") if isinstance(state, dict) else None
    if not isinstance(raw, list):
        return []
    calls: list[dict[str, Any]] = []
    for m in raw:
        extra = (
            m.get("additional_kwargs")
            if isinstance(m, dict)
            else getattr(m, "additional_kwargs", None)
        )
        if isinstance(extra, dict):
            tc = extra.get("tool_calls")
            if isinstance(tc, list):
                calls.extend(tc)
        if isinstance(m, dict):
            tc = m.get("tool_calls")
            if isinstance(tc, list):
                calls.extend(tc)
    return calls


def wrap_node(
    node_fn: NodeFn | None = None,
    *,
    cerberus: Cerberus | None = None,
    config: CerberusConfig | None = None,
    raise_on_block: bool = True,
) -> Callable[..., Any]:
    """Decorate a LangGraph node with Cerberus inspection.

    Can be used as ``wrap_node(fn)`` or ``wrap_node(cerberus=c)(fn)``.
    A blocked result raises :class:`SecurityError` by default; set
    ``raise_on_block=False`` to return an error-terminating state
    instead (``{"messages": [...], "blocked": True}``).
    """

    def decorator(fn: NodeFn) -> NodeFn:
        inspector = cerberus or Cerberus(config or CerberusConfig())

        @functools.wraps(fn)
        def wrapper(state: dict[str, Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
            inbound = _collect_messages(state)
            inbound_calls = _collect_tool_calls(state)
            if inbound:
                pre: InspectionResult = inspector.inspect(
                    messages=inbound, tool_calls=inbound_calls or None
                )
                if pre.blocked:
                    if raise_on_block:
                        raise SecurityError(pre)
                    return {"messages": inbound, "blocked": True, "turn_id": pre.turn_id}

            new_state = fn(state, *args, **kwargs)

            outbound = _collect_messages(new_state) if isinstance(new_state, dict) else []
            outbound_calls = (
                _collect_tool_calls(new_state) if isinstance(new_state, dict) else []
            )
            if outbound:
                post: InspectionResult = inspector.inspect(
                    messages=outbound, tool_calls=outbound_calls or None
                )
                if post.blocked:
                    if raise_on_block:
                        raise SecurityError(post)
                    return {"messages": outbound, "blocked": True, "turn_id": post.turn_id}
            return new_state

        wrapper.cerberus = inspector  # type: ignore[attr-defined]
        return wrapper

    if node_fn is not None and callable(node_fn):
        return decorator(node_fn)
    return decorator


def wrap_graph(
    compiled_graph: Any,
    config: CerberusConfig | None = None,
    **kwargs: Any,
) -> Any:
    """Attach inspection to *every* node in a compiled LangGraph.

    Only works on LangGraph's ``CompiledStateGraph`` / similar objects
    that expose a writable ``nodes`` mapping. Returns the same graph.
    """
    cerberus = Cerberus(config or CerberusConfig())
    nodes = getattr(compiled_graph, "nodes", None)
    if not isinstance(nodes, dict):
        raise AttributeError(
            "wrap_graph expected compiled_graph.nodes to be a dict-like mapping"
        )
    for name, spec in list(nodes.items()):
        fn = getattr(spec, "runnable", None) or spec
        if not callable(fn):
            continue
        wrapped = wrap_node(fn, cerberus=cerberus, **kwargs)
        if hasattr(spec, "runnable"):
            spec.runnable = wrapped
        else:
            nodes[name] = wrapped
    return compiled_graph
