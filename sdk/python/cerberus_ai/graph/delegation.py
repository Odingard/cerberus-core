"""
cerberus_ai.graph.delegation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Delegation graph — multi-agent execution graph integrity (Sprint 4).

Each agent is a node; each handoff is an edge carrying the context
fingerprint and the risk state at handoff time. The graph is
cryptographically signed at creation; the per-turn manifest gate
re-verifies the signature before every detection pass.

Parity port of ``src/graph/delegation.ts``. The canonical signing
payload matches the TS version byte-for-byte so a Python-signed graph
can be verified by the TS SDK and vice versa.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

from cerberus_ai.egi.signer import Ed25519Signer, Signer, Verifier

AgentType = Literal["orchestrator", "subagent", "tool_agent"]


@dataclass(frozen=True)
class RiskState:
    l1: bool = False
    l2: bool = False
    l3: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {"l1": self.l1, "l2": self.l2, "l3": self.l3}


@dataclass(frozen=True)
class AgentNode:
    agent_id: str
    agent_type: AgentType
    declared_tools: tuple[str, ...]
    risk_state: RiskState
    parent_agent_id: str | None = None


@dataclass(frozen=True)
class DelegationEdge:
    from_agent_id: str
    to_agent_id: str
    context_fingerprint: str
    risk_state_at_handoff: RiskState
    timestamp: int


@dataclass
class DelegationGraph:
    session_id: str
    root_agent_id: str
    nodes: dict[str, AgentNode] = field(default_factory=dict)
    edges: list[DelegationEdge] = field(default_factory=list)
    # Cryptographic authorization metadata:
    signature: str = ""
    algorithm: str = ""
    key_id: str = ""

    # Package-private; populated by create_delegation_graph for in-process verify.
    _verifier: Verifier | None = None

    def signing_payload(self) -> str:
        """Canonical JSON payload used for signature verification."""
        root = self.nodes.get(self.root_agent_id)
        declared = list(root.declared_tools) if root is not None else []
        return _canonical_payload(
            self.session_id,
            self.root_agent_id,
            declared,
            self.algorithm,
            self.key_id,
        )


def _canonical_payload(
    session_id: str,
    root_agent_id: str,
    root_declared_tools: list[str],
    algorithm: str,
    key_id: str,
) -> str:
    payload = {
        "v": 1,
        "sessionId": session_id,
        "rootAgentId": root_agent_id,
        "rootDeclaredTools": sorted(root_declared_tools),
        "algorithm": algorithm,
        "keyId": key_id,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def compute_context_fingerprint(context: str) -> str:
    """SHA-256 hex of a handoff context string."""
    return hashlib.sha256(context.encode()).hexdigest()


def create_delegation_graph(
    session_id: str,
    root_agent_id: str,
    root_agent_type: AgentType,
    root_declared_tools: list[str],
    signer: Signer | None = None,
) -> DelegationGraph:
    """
    Build and sign a new delegation graph with ``root_agent_id`` as orchestrator.
    Defaults to an Ed25519 signer when ``signer`` is None.
    """
    effective_signer = signer or Ed25519Signer()

    algorithm = effective_signer.algorithm
    key_id = effective_signer.key_id
    payload = _canonical_payload(
        session_id, root_agent_id, root_declared_tools, algorithm, key_id
    )
    signature = effective_signer.sign(payload)

    graph = DelegationGraph(
        session_id=session_id,
        root_agent_id=root_agent_id,
        signature=signature,
        algorithm=algorithm,
        key_id=key_id,
    )
    graph.nodes[root_agent_id] = AgentNode(
        agent_id=root_agent_id,
        agent_type=root_agent_type,
        declared_tools=tuple(root_declared_tools),
        risk_state=RiskState(),
    )
    # Signers that also implement Verifier can re-verify in-process.
    if hasattr(effective_signer, "verify"):
        graph._verifier = effective_signer  # type: ignore[assignment]
    return graph


def verify_graph_integrity(
    graph: DelegationGraph, verifier: Verifier | None = None
) -> bool:
    """Verify ``graph`` has not been tampered with since creation."""
    v = verifier or graph._verifier
    if v is None:
        return False
    if v.algorithm != graph.algorithm or v.key_id != graph.key_id:
        return False
    return v.verify(graph.signing_payload(), graph.signature)


# ── Graph construction / queries ────────────────────────────────────


def add_delegation(
    graph: DelegationGraph,
    from_agent_id: str,
    to_agent: AgentNode,
    context: str,
    risk_state_at_handoff: RiskState,
    timestamp: int,
) -> None:
    """Add an agent node and the delegation edge from ``from_agent_id``."""
    if from_agent_id not in graph.nodes:
        raise ValueError(f"from_agent_id {from_agent_id!r} is not in the graph")
    graph.nodes[to_agent.agent_id] = AgentNode(
        agent_id=to_agent.agent_id,
        agent_type=to_agent.agent_type,
        declared_tools=to_agent.declared_tools,
        risk_state=to_agent.risk_state,
        parent_agent_id=from_agent_id,
    )
    graph.edges.append(
        DelegationEdge(
            from_agent_id=from_agent_id,
            to_agent_id=to_agent.agent_id,
            context_fingerprint=compute_context_fingerprint(context),
            risk_state_at_handoff=risk_state_at_handoff,
            timestamp=timestamp,
        )
    )


def get_agent_chain(graph: DelegationGraph, agent_id: str) -> list[AgentNode]:
    """Return the ancestor chain from root to ``agent_id`` inclusive."""
    chain: list[AgentNode] = []
    current = graph.nodes.get(agent_id)
    while current is not None:
        chain.insert(0, current)
        if current.parent_agent_id is None:
            break
        current = graph.nodes.get(current.parent_agent_id)
    return chain


def is_authorized_agent(graph: DelegationGraph, agent_id: str) -> bool:
    """True if ``agent_id`` is present in the signed graph."""
    return agent_id in graph.nodes


def update_risk_state(
    graph: DelegationGraph, agent_id: str, risk_state: RiskState
) -> None:
    """Update the cumulative risk state for a node. No-op if node missing."""
    node = graph.nodes.get(agent_id)
    if node is None:
        return
    graph.nodes[agent_id] = AgentNode(
        agent_id=node.agent_id,
        agent_type=node.agent_type,
        declared_tools=node.declared_tools,
        risk_state=risk_state,
        parent_agent_id=node.parent_agent_id,
    )
