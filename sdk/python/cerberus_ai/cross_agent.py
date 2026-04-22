"""
cerberus_ai.cross_agent
~~~~~~~~~~~~~~~~~~~~~~~
Cross-agent correlation — detects the Lethal Trifecta across agent
boundaries in a multi-agent delegation graph.

Three pure detectors, each ``(graph, ctx) -> Signal | None``:

* :func:`detect_cross_agent_trifecta` — L1+L2+L3 satisfied across two or
  more connected agents in the delegation chain.
* :func:`detect_context_contamination` — L2 (injection) propagates through
  a delegation edge from an upstream agent to ``current_agent_id``.
* :func:`detect_unauthorized_agent_spawn` — an agent appears at runtime
  without a delegation edge from a node in the signed graph.

Parity port of ``src/engine/cross-agent-correlation.ts``. Signals use
the existing layer tag ``CROSS_AGENT`` and no new layers are added.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from cerberus_ai.graph.delegation import (
    DelegationGraph,
    RiskState,
    get_agent_chain,
    is_authorized_agent,
)


@dataclass(frozen=True)
class CrossAgentTrifectaSignal:
    turn_id: str
    contributing_agents: tuple[str, ...]
    risk_state: RiskState
    timestamp: int


@dataclass(frozen=True)
class ContextContaminationSignal:
    turn_id: str
    source_agent_id: str
    contaminated_agent_id: str
    contamination_chain: tuple[str, ...]
    timestamp: int


@dataclass(frozen=True)
class UnauthorizedAgentSpawnSignal:
    turn_id: str
    agent_id: str
    timestamp: int


def detect_cross_agent_trifecta(
    graph: DelegationGraph,
    current_agent_id: str,
    current_risk_state: RiskState,
    turn_id: str,
) -> CrossAgentTrifectaSignal | None:
    """Fire when L1 ∧ L2 ∧ L3 is satisfied across ≥2 agents in the chain."""
    chain = get_agent_chain(graph, current_agent_id)
    if not chain:
        return None

    l1 = l2 = l3 = False
    contributing: list[str] = []

    def _push(agent_id: str) -> None:
        if agent_id not in contributing:
            contributing.append(agent_id)

    for node in chain:
        state = current_risk_state if node.agent_id == current_agent_id else node.risk_state
        if state.l1:
            l1 = True
            _push(node.agent_id)
        if state.l2:
            l2 = True
            _push(node.agent_id)
        if state.l3:
            l3 = True
            _push(node.agent_id)

    if l1 and l2 and l3 and len(contributing) > 1:
        return CrossAgentTrifectaSignal(
            turn_id=turn_id,
            contributing_agents=tuple(contributing),
            risk_state=RiskState(l1=l1, l2=l2, l3=l3),
            timestamp=int(time.time() * 1000),
        )
    return None


def detect_context_contamination(
    graph: DelegationGraph, current_agent_id: str, turn_id: str
) -> ContextContaminationSignal | None:
    """Fire when an upstream agent's L2 contamination reached this agent."""
    chain = get_agent_chain(graph, current_agent_id)
    if len(chain) < 2:
        return None
    if current_agent_id not in graph.nodes:
        return None

    sources: list[str] = []
    for node in chain:
        if node.agent_id == current_agent_id:
            continue
        if node.risk_state.l2 and node.agent_id not in sources:
            sources.append(node.agent_id)

    for edge in graph.edges:
        if edge.to_agent_id != current_agent_id:
            continue
        if edge.risk_state_at_handoff.l2 and edge.from_agent_id not in sources:
            sources.append(edge.from_agent_id)

    if not sources:
        return None

    return ContextContaminationSignal(
        turn_id=turn_id,
        source_agent_id=sources[0],
        contaminated_agent_id=current_agent_id,
        contamination_chain=tuple(sources),
        timestamp=int(time.time() * 1000),
    )


def detect_unauthorized_agent_spawn(
    graph: DelegationGraph, agent_id: str, turn_id: str
) -> UnauthorizedAgentSpawnSignal | None:
    """Fire when ``agent_id`` is not in the signed delegation graph."""
    if is_authorized_agent(graph, agent_id):
        return None
    return UnauthorizedAgentSpawnSignal(
        turn_id=turn_id,
        agent_id=agent_id,
        timestamp=int(time.time() * 1000),
    )
