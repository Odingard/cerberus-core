"""
cerberus_ai.detectors.l4_memory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
L4 — Memory Contamination detector.

Tracks taint through persistent agent memory across sessions. The
novel detection this layer delivers: a tool that reads from a memory
node which was written, in a *different session*, by an untrusted
source, fires a CRITICAL ``CONTAMINATED_MEMORY_ACTIVE`` signal before
the read result re-enters the LLM context.

Parity port of ``src/layers/l4-memory.ts``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from cerberus_ai.graph.contamination import (
    ContaminationGraph,
    GraphNode,
    create_contamination_graph,
)
from cerberus_ai.graph.ledger import (
    ProvenanceLedger,
    ProvenanceRecord,
    hash_content,
)
from cerberus_ai.models import MemoryToolConfig, TrustLevel

_NODE_ID_FIELDS = ("key", "id", "nodeId", "node_id", "memoryKey", "memory_key")
_CONTENT_FIELDS = ("value", "content", "data")


@dataclass(frozen=True)
class MemoryContaminationSignal:
    """Emitted when a read resolves to a cross-session-tainted node."""

    turn_id: str
    session_id: str
    node_id: str
    contamination_source: str
    timestamp: int
    # Useful for Observe / Guard.
    tool_name: str = ""


def _extract_node_id(
    args: dict[str, Any], config: MemoryToolConfig
) -> str | None:
    if config.node_id_field:
        v = args.get(config.node_id_field)
        if isinstance(v, str) and v:
            return v
        return None
    for field_name in _NODE_ID_FIELDS:
        v = args.get(field_name)
        if isinstance(v, str) and v:
            return v
    return None


def _extract_content(
    args: dict[str, Any], result: str, config: MemoryToolConfig
) -> str:
    if config.content_field:
        v = args.get(config.content_field)
        if isinstance(v, str):
            return v
    for field_name in _CONTENT_FIELDS:
        v = args.get(field_name)
        if isinstance(v, str):
            return v
    return result


@dataclass
class L4Detector:
    """Memory-contamination detector bound to a per-session graph + ledger."""

    memory_tools: list[MemoryToolConfig] = field(default_factory=list)
    graph: ContaminationGraph = field(default_factory=create_contamination_graph)
    ledger: ProvenanceLedger | None = None

    def _config_for(self, tool_name: str) -> MemoryToolConfig | None:
        for cfg in self.memory_tools:
            if cfg.tool_name == tool_name:
                return cfg
        return None

    def on_tool_call(
        self,
        *,
        session_id: str,
        turn_id: str,
        tool_name: str,
        tool_arguments: dict[str, Any],
        tool_result: str,
        trust_level: TrustLevel,
        timestamp: int | None = None,
    ) -> MemoryContaminationSignal | None:
        cfg = self._config_for(tool_name)
        if cfg is None:
            return None
        node_id = _extract_node_id(tool_arguments, cfg)
        if node_id is None:
            return None

        now = timestamp if timestamp is not None else int(time.time() * 1000)
        content = _extract_content(tool_arguments, tool_result, cfg)
        content_hash = hash_content(content)

        if cfg.operation == "write":
            self.graph.write_node(
                GraphNode(
                    node_id=node_id,
                    trust_level=trust_level.value,
                    source_session_id=session_id,
                    source=tool_name,
                    content_hash=content_hash,
                    timestamp=now,
                )
            )
            if self.ledger is not None:
                self.ledger.record_write(
                    ProvenanceRecord(
                        node_id=node_id,
                        session_id=session_id,
                        trust_level=trust_level.value,
                        source=tool_name,
                        content_hash=content_hash,
                        timestamp=now,
                    )
                )
            return None

        # Read path
        if not self._has_cross_session_taint(node_id, session_id):
            return None
        source = self._find_contamination_source(node_id) or "unknown"
        return MemoryContaminationSignal(
            turn_id=turn_id,
            session_id=session_id,
            node_id=node_id,
            contamination_source=source,
            timestamp=now,
            tool_name=tool_name,
        )

    def _has_cross_session_taint(self, node_id: str, session_id: str) -> bool:
        if self.graph.has_cross_session_taint(node_id, session_id):
            return True
        if self.ledger is not None:
            return self.ledger.is_cross_session_tainted(node_id, session_id)
        return False

    def _find_contamination_source(self, node_id: str) -> str | None:
        source = self.graph.find_contamination_source(node_id)
        if source is not None:
            return source
        if self.ledger is None:
            return None
        for record in self.ledger.get_node_history(node_id):
            if record.trust_level == "untrusted":
                return record.source
        return None
