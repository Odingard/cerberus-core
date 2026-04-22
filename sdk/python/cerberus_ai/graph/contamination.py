"""
cerberus_ai.graph.contamination
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Contamination graph — directed taint propagation across memory nodes.

Used by L4 Memory Contamination. Parity port of
``src/graph/contamination.ts``.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Literal

TrustLevel = Literal["trusted", "untrusted", "unknown"]


@dataclass(frozen=True)
class GraphNode:
    node_id: str
    trust_level: TrustLevel
    source_session_id: str
    source: str
    content_hash: str
    timestamp: int


@dataclass(frozen=True)
class GraphEdge:
    source_node_id: str
    target_node_id: str
    session_id: str
    timestamp: int


@dataclass
class ContaminationGraph:
    """In-memory taint graph with BFS ancestor traversal."""

    _nodes: dict[str, GraphNode] = field(default_factory=dict)
    _edges: list[GraphEdge] = field(default_factory=list)
    # target -> set of source node ids
    _reverse_adj: dict[str, set[str]] = field(default_factory=dict)

    def write_node(self, node: GraphNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self._edges.append(edge)
        sources = self._reverse_adj.setdefault(edge.target_node_id, set())
        sources.add(edge.source_node_id)

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_nodes(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def get_edges(self) -> list[GraphEdge]:
        return list(self._edges)

    def get_ancestors(self, node_id: str) -> list[GraphNode]:
        """BFS up the reverse adjacency; returns all ancestor nodes."""
        visited: set[str] = set()
        queue: deque[str] = deque()
        ancestors: list[GraphNode] = []

        direct = self._reverse_adj.get(node_id)
        if direct:
            for parent in direct:
                if parent not in visited:
                    visited.add(parent)
                    queue.append(parent)

        while queue:
            current = queue.popleft()
            node = self._nodes.get(current)
            if node is not None:
                ancestors.append(node)
            parents = self._reverse_adj.get(current)
            if parents:
                for parent in parents:
                    if parent not in visited:
                        visited.add(parent)
                        queue.append(parent)

        return ancestors

    def is_tainted(self, node_id: str) -> bool:
        node = self._nodes.get(node_id)
        if node is None:
            return False
        if node.trust_level == "untrusted":
            return True
        return any(a.trust_level == "untrusted" for a in self.get_ancestors(node_id))

    def has_cross_session_taint(self, node_id: str, current_session_id: str) -> bool:
        node = self._nodes.get(node_id)
        if node is None:
            return False
        if node.trust_level == "untrusted" and node.source_session_id != current_session_id:
            return True
        for ancestor in self.get_ancestors(node_id):
            if (
                ancestor.trust_level == "untrusted"
                and ancestor.source_session_id != current_session_id
            ):
                return True
        return False

    def find_contamination_source(self, node_id: str) -> str | None:
        node = self._nodes.get(node_id)
        if node is None:
            return None
        if node.trust_level == "untrusted":
            return node.source
        for ancestor in self.get_ancestors(node_id):
            if ancestor.trust_level == "untrusted":
                return ancestor.source
        return None

    def size(self) -> int:
        return len(self._nodes)

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
        self._reverse_adj.clear()


def create_contamination_graph() -> ContaminationGraph:
    """Factory — kept for parity with the TS API (`createContaminationGraph`)."""
    return ContaminationGraph()
