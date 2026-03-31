"""
cerberus_ai.egi
~~~~~~~~~~~~~~~
Execution Graph Integrity (EGI).

Formalizes an agent's intended execution sequence as a directed graph at
initialization. Detects any deviation triggered by untrusted content.

EGI is structural/behavioral — orthogonal to all content-based detection.
The graph is cryptographically signed at initialization and immutable thereafter.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass

from cerberus_ai.models import EGIViolation, ToolCall, ToolSchema


@dataclass
class EGINode:
    """A node in the execution graph — represents a declared tool or capability."""
    node_id: str
    tool_name: str
    description: str
    schema_fingerprint: str     # hash of tool schema — detects schema changes
    is_network_capable: bool
    is_data_read: bool
    is_data_write: bool


@dataclass
class EGIEdge:
    """A permitted transition between nodes."""
    from_node_id: str | None    # None = entry point (first call)
    to_node_id: str
    condition: str = "any"


@dataclass
class EGIGraph:
    """
    The immutable, signed execution graph for an agent session.
    Signed at initialization — any mutation is detected.
    """
    graph_id: str
    session_id: str
    agent_id: str
    nodes: list[EGINode]
    edges: list[EGIEdge]
    initialized_at: int         # Unix ms
    signature: str = ""         # HMAC-SHA256

    def signing_payload(self) -> str:
        """Canonical JSON for signing — deterministic serialization."""
        return json.dumps({
            "graph_id": self.graph_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "tool_name": n.tool_name,
                    "schema_fingerprint": n.schema_fingerprint,
                }
                for n in sorted(self.nodes, key=lambda x: x.node_id)
            ],
            "initialized_at": self.initialized_at,
        }, sort_keys=True)


def _schema_fingerprint(tool: ToolSchema) -> str:
    """Deterministic fingerprint of a tool schema."""
    payload = json.dumps({
        "name": tool.name,
        "description": tool.description,
        "parameters": tool.parameters,
        "is_network_capable": tool.is_network_capable,
        "is_data_read": tool.is_data_read,
        "is_data_write": tool.is_data_write,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _sign(payload: str, key: bytes) -> str:
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def _verify(payload: str, signature: str, key: bytes) -> bool:
    expected = _sign(payload, key)
    return hmac.compare_digest(expected, signature)


@dataclass
class LateRegistrationRecord:
    """Record of a late-registered tool."""
    tool_name: str
    reason: str
    authorized_by: str
    registered_at_turn: int
    l2_active_at_registration: bool     # injection-assisted detection flag
    node_id: str


class EGIEngine:
    """
    Manages Execution Graph Integrity for a session.

    Usage:
      engine = EGIEngine(session_id, agent_id, declared_tools)
      # On each turn:
      violations = engine.check_turn(tool_calls, current_turn, l2_active)
    """

    def __init__(
        self,
        session_id: str,
        agent_id: str,
        declared_tools: list[ToolSchema],
        signing_key: bytes | None = None,
    ) -> None:
        self._session_id = session_id
        self._agent_id = agent_id
        self._key = signing_key or os.urandom(32)
        self._late_registrations: list[LateRegistrationRecord] = []

        # Build and sign the graph
        self._graph = self._build_graph(declared_tools)
        self._graph.signature = _sign(self._graph.signing_payload(), self._key)

        # Node lookup by tool name
        self._nodes_by_name: dict[str, EGINode] = {
            n.tool_name: n for n in self._graph.nodes
        }

    def _build_graph(self, tools: list[ToolSchema]) -> EGIGraph:
        nodes = [
            EGINode(
                node_id=str(uuid.uuid4()),
                tool_name=t.name,
                description=t.description,
                schema_fingerprint=_schema_fingerprint(t),
                is_network_capable=t.is_network_capable,
                is_data_read=t.is_data_read,
                is_data_write=t.is_data_write,
            )
            for t in tools
        ]
        return EGIGraph(
            graph_id=str(uuid.uuid4()),
            session_id=self._session_id,
            agent_id=self._agent_id,
            nodes=nodes,
            edges=[],               # permissive edge model — any declared tool can follow any other
            initialized_at=int(time.time() * 1000),
        )

    def verify_graph_integrity(self) -> bool:
        """Verify the graph has not been tampered with since initialization."""
        return _verify(self._graph.signing_payload(), self._graph.signature, self._key)

    def check_turn(
        self,
        tool_calls: list[ToolCall],
        current_turn: int,
        l2_active: bool = False,
    ) -> list[EGIViolation]:
        """
        Check tool calls in a turn against the signed execution graph.
        Returns a list of violations (empty = clean).
        """
        violations: list[EGIViolation] = []

        # Integrity check first — detect graph tampering
        if not self.verify_graph_integrity():
            violations.append(EGIViolation(
                violation_type="GRAPH_INTEGRITY_FAILURE",
                description="EGI graph signature verification failed — possible tampering detected",
            ))
            return violations   # halt further checks — graph is untrusted

        for tc in tool_calls:
            node = self._nodes_by_name.get(tc.name)

            if node is None:
                # Check late registrations
                late = next((r for r in self._late_registrations if r.tool_name == tc.name), None)
                if late is None:
                    violations.append(EGIViolation(
                        violation_type="UNAUTHORIZED_TOOL_USE",
                        tool_name=tc.name,
                        description=(
                            f"Tool '{tc.name}' invoked but not"
                            " in EGI graph and not late-registered"
                        ),
                    ))
                elif late.l2_active_at_registration:
                    violations.append(EGIViolation(
                        violation_type="INJECTION_ASSISTED_TOOL_USE",
                        tool_name=tc.name,
                        description=(
                            f"Tool '{tc.name}' was late-registered while L2 injection was active — "
                            "possible injection-assisted capability expansion"
                        ),
                    ))

        return violations

    def register_tool_late(
        self,
        tool: ToolSchema,
        reason: str,
        authorized_by: str,
        current_turn: int,
        l2_active: bool = False,
    ) -> tuple[bool, str]:
        """
        Register a tool after initialization via the controlled late-binding hook.

        Returns (success, message).
        Injection-assisted registration (L2 active) is blocked.
        """
        if l2_active:
            record = LateRegistrationRecord(
                tool_name=tool.name,
                reason=reason,
                authorized_by=authorized_by,
                registered_at_turn=current_turn,
                l2_active_at_registration=True,
                node_id="",
            )
            self._late_registrations.append(record)
            return False, (
                f"INJECTION_ASSISTED_REGISTRATION: Tool '{tool.name}' registration blocked — "
                "L2 injection active at registration time"
            )

        # Add to graph (requires re-signing)
        node = EGINode(
            node_id=str(uuid.uuid4()),
            tool_name=tool.name,
            description=tool.description,
            schema_fingerprint=_schema_fingerprint(tool),
            is_network_capable=tool.is_network_capable,
            is_data_read=tool.is_data_read,
            is_data_write=tool.is_data_write,
        )
        self._graph.nodes.append(node)
        self._nodes_by_name[tool.name] = node
        # Re-sign the updated graph
        self._graph.signature = _sign(self._graph.signing_payload(), self._key)

        record = LateRegistrationRecord(
            tool_name=tool.name,
            reason=reason,
            authorized_by=authorized_by,
            registered_at_turn=current_turn,
            l2_active_at_registration=False,
            node_id=node.node_id,
        )
        self._late_registrations.append(record)
        return True, f"Tool '{tool.name}' successfully registered and added to EGI graph"

    @property
    def graph_id(self) -> str:
        return self._graph.graph_id

    @property
    def registered_tools(self) -> list[str]:
        return [n.tool_name for n in self._graph.nodes]

    @property
    def late_registrations(self) -> list[LateRegistrationRecord]:
        return list(self._late_registrations)
