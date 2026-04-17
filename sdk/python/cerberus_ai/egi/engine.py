"""
cerberus_ai.egi
~~~~~~~~~~~~~~~
Execution Graph Integrity (EGI).

Formalizes an agent's intended execution sequence as a directed graph at
initialization. Detects any deviation triggered by untrusted content.

EGI is structural/behavioral — orthogonal to all content-based detection.
The graph is cryptographically signed at initialization. Signing is
pluggable via the ``Signer`` / ``Verifier`` protocol in
``cerberus_ai.egi.signer``; by default a process-ephemeral Ed25519 key
is used. Enterprise deployments should inject a KMS/HSM-backed signer
at startup.

Manifest coverage: the signed payload binds the full declared-tool
surface (names, descriptions, capability flags, schema fingerprints),
the edge set, the late-registration ledger, and manifest metadata.
Any mutation to any of these fields after initialization will fail
signature verification.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field

from cerberus_ai.models import EGIViolation, ToolCall, ToolSchema

from .signer import (
    HmacSigner,
    Signer,
    Verifier,
    get_default_signer,
)

#: Bumped whenever the signed-payload schema changes in a way verifiers
#: need to know about.
MANIFEST_VERSION: int = 2


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
class LateRegistrationRecord:
    """Record of a late-registered tool."""
    tool_name: str
    reason: str
    authorized_by: str
    registered_at_turn: int
    l2_active_at_registration: bool     # injection-assisted detection flag
    node_id: str


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
    manifest_version: int = MANIFEST_VERSION
    algorithm: str = ""
    key_id: str = ""
    signature: str = ""
    late_registrations: list[LateRegistrationRecord] = field(default_factory=list)

    def signing_payload(self) -> str:
        """
        Canonical JSON for signing — deterministic serialization covering
        the full manifest: every node field, the edge set, the
        late-registration ledger, and the algorithm / key identifier.
        """
        return json.dumps({
            "manifest_version": self.manifest_version,
            "graph_id": self.graph_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "initialized_at": self.initialized_at,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "tool_name": n.tool_name,
                    "description": n.description,
                    "schema_fingerprint": n.schema_fingerprint,
                    "is_network_capable": n.is_network_capable,
                    "is_data_read": n.is_data_read,
                    "is_data_write": n.is_data_write,
                }
                for n in sorted(self.nodes, key=lambda x: x.node_id)
            ],
            "edges": [
                {
                    "from_node_id": e.from_node_id,
                    "to_node_id": e.to_node_id,
                    "condition": e.condition,
                }
                for e in sorted(
                    self.edges,
                    key=lambda x: (x.from_node_id or "", x.to_node_id, x.condition),
                )
            ],
            "late_registrations": [
                {
                    "tool_name": r.tool_name,
                    "reason": r.reason,
                    "authorized_by": r.authorized_by,
                    "registered_at_turn": r.registered_at_turn,
                    "l2_active_at_registration": r.l2_active_at_registration,
                    "node_id": r.node_id,
                }
                for r in sorted(self.late_registrations, key=lambda x: x.node_id)
            ],
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


class EGIEngine:
    """
    Manages Execution Graph Integrity for a session.

    Usage::

        engine = EGIEngine(session_id, agent_id, declared_tools)
        # On each turn:
        violations = engine.check_turn(tool_calls, current_turn, l2_active)

    The signing key material can be supplied in three ways (checked in order):

    1. ``signer=`` — a ``Signer`` implementation (recommended; used for
       KMS/HSM adapters).
    2. ``verifier=`` — an optional explicit verifier. Defaults to the
       signer itself when it also implements ``verify()``.
    3. ``signing_key=`` — legacy bytes HMAC key path. When supplied,
       wraps the bytes in an ``HmacSigner``. New code should pass a
       ``Signer`` directly.

    If none of the above are supplied, the process-wide default signer
    (ephemeral Ed25519) is used.
    """

    def __init__(
        self,
        session_id: str,
        agent_id: str,
        declared_tools: list[ToolSchema],
        signing_key: bytes | None = None,
        *,
        signer: Signer | None = None,
        verifier: Verifier | None = None,
        strict_amendment: bool = False,
    ) -> None:
        self._session_id = session_id
        self._agent_id = agent_id
        # Strict mode: the runtime is NOT allowed to self-re-sign a late
        # amendment. Callers must supply a signature produced out-of-band
        # (typically by an enterprise gateway / KMS-backed authority) via
        # ``register_tool_late(..., amendment_signature=...)``. This is the
        # "runtime cannot silently expand its own authority" rule.
        self._strict_amendment = strict_amendment

        if signer is not None:
            self._signer: Signer = signer
        elif signing_key is not None:
            self._signer = HmacSigner(key=signing_key)
        else:
            self._signer = get_default_signer()

        # The same object is typically both a Signer and a Verifier
        # (HmacSigner, Ed25519Signer). If an explicit verifier was given
        # or the signer doesn't expose verify(), use the override.
        if verifier is not None:
            self._verifier: Verifier = verifier
        elif isinstance(self._signer, Verifier):  # runtime_checkable Protocol
            self._verifier = self._signer
        else:
            raise ValueError(
                "Signer does not implement Verifier; pass `verifier=` explicitly"
            )

        # Build and sign the graph
        self._graph = self._build_graph(declared_tools)
        self._graph.algorithm = self._signer.algorithm
        self._graph.key_id = self._signer.key_id
        self._graph.signature = self._signer.sign(self._graph.signing_payload())

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
            manifest_version=MANIFEST_VERSION,
        )

    def verify_graph_integrity(self) -> bool:
        """Verify the graph has not been tampered with since initialization.

        Binds algorithm and key_id to the verifier — any mismatch is a
        verification failure, not a silent pass."""
        if (
            self._graph.algorithm != self._verifier.algorithm
            or self._graph.key_id != self._verifier.key_id
        ):
            return False
        return self._verifier.verify(
            self._graph.signing_payload(), self._graph.signature
        )

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
                late = next(
                    (r for r in self._graph.late_registrations if r.tool_name == tc.name),
                    None,
                )
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

    def _derive_amendment_node_id(self, tool_name: str, current_turn: int) -> str:
        """Derive a deterministic node_id for a late amendment.

        Both :meth:`preview_amendment_payload` and :meth:`register_tool_late`
        must produce the *same* canonical payload for the same amendment —
        otherwise the out-of-band signature would verify against the preview
        but not against the payload the engine actually constructs. Using a
        uuid5 derivation keeps the id stable for a given
        ``(graph_id, tool_name, current_turn)``.
        """
        ns = uuid.uuid5(uuid.NAMESPACE_URL, f"cerberus-egi:{self._graph.graph_id}")
        return str(uuid.uuid5(ns, f"{tool_name}:{current_turn}"))

    def preview_amendment_payload(
        self,
        tool: ToolSchema,
        reason: str,
        authorized_by: str,
        current_turn: int,
        l2_active: bool = False,
    ) -> str:
        """
        Return the exact canonical payload an authority must sign to
        register ``tool`` late.

        Used by strict deployments (``strict_amendment=True``): the runtime
        calls this, ships the payload to an out-of-band signer (gateway /
        KMS), and then passes the resulting signature into
        :meth:`register_tool_late` as ``amendment_signature``. The runtime
        itself never signs.

        Does not mutate engine state — purely derives what the post-amend
        manifest would look like.
        """
        preview_node = EGINode(
            node_id=self._derive_amendment_node_id(tool.name, current_turn),
            tool_name=tool.name,
            description=tool.description,
            schema_fingerprint=_schema_fingerprint(tool),
            is_network_capable=tool.is_network_capable,
            is_data_read=tool.is_data_read,
            is_data_write=tool.is_data_write,
        )
        preview_record = LateRegistrationRecord(
            tool_name=tool.name,
            reason=reason,
            authorized_by=authorized_by,
            registered_at_turn=current_turn,
            l2_active_at_registration=l2_active,
            node_id="" if l2_active else preview_node.node_id,
        )
        preview_nodes = list(self._graph.nodes)
        if not l2_active:
            preview_nodes.append(preview_node)
        preview_graph = EGIGraph(
            graph_id=self._graph.graph_id,
            session_id=self._graph.session_id,
            agent_id=self._graph.agent_id,
            nodes=preview_nodes,
            edges=list(self._graph.edges),
            initialized_at=self._graph.initialized_at,
            manifest_version=self._graph.manifest_version,
            algorithm=self._graph.algorithm,
            key_id=self._graph.key_id,
            late_registrations=[*self._graph.late_registrations, preview_record],
        )
        return preview_graph.signing_payload()

    def register_tool_late(
        self,
        tool: ToolSchema,
        reason: str,
        authorized_by: str,
        current_turn: int,
        l2_active: bool = False,
        *,
        amendment_signature: str | None = None,
    ) -> tuple[bool, str]:
        """
        Register a tool after initialization via the controlled late-binding hook.

        Returns ``(success, message)``.

        Two modes:

        * **Permissive** (default, ``strict_amendment=False``): the engine
          re-signs the graph in-process with ``self._signer``. Convenient
          for OSS / dev, but the runtime itself is capable of expanding
          its own authority.
        * **Strict** (``strict_amendment=True``): the runtime refuses to
          self-sign. The caller must first call
          :meth:`preview_amendment_payload`, sign it out-of-band with an
          authorized signer (gateway / KMS), and pass the hex signature
          here via ``amendment_signature``. The signature is verified
          against ``self._verifier`` before mutation — any mismatch is a
          hard refusal.

        Injection-assisted registration (``l2_active=True``) is always
        blocked; the rejection is still added to the signed ledger as
        evidence, but in strict mode that ledger update itself also
        requires an authorized ``amendment_signature``.
        """
        def _apply_new_signature(payload: str) -> tuple[bool, str]:
            if self._strict_amendment:
                if amendment_signature is None:
                    return False, (
                        "STRICT_AMENDMENT_REQUIRED: signed amendment missing. "
                        "Obtain a signature over preview_amendment_payload(...) "
                        "from an authorized signer and pass it as "
                        "amendment_signature=."
                    )
                if not self._verifier.verify(payload, amendment_signature):
                    return False, (
                        "STRICT_AMENDMENT_INVALID: supplied amendment_signature "
                        "did not verify against the configured authority key."
                    )
                self._graph.signature = amendment_signature
                return True, ""
            self._graph.signature = self._signer.sign(payload)
            return True, ""

        if l2_active:
            record = LateRegistrationRecord(
                tool_name=tool.name,
                reason=reason,
                authorized_by=authorized_by,
                registered_at_turn=current_turn,
                l2_active_at_registration=True,
                node_id="",
            )
            self._graph.late_registrations.append(record)
            ok, err = _apply_new_signature(self._graph.signing_payload())
            if not ok:
                self._graph.late_registrations.pop()
                return False, err
            return False, (
                f"INJECTION_ASSISTED_REGISTRATION: Tool '{tool.name}' registration blocked — "
                "L2 injection active at registration time"
            )

        node = EGINode(
            node_id=self._derive_amendment_node_id(tool.name, current_turn),
            tool_name=tool.name,
            description=tool.description,
            schema_fingerprint=_schema_fingerprint(tool),
            is_network_capable=tool.is_network_capable,
            is_data_read=tool.is_data_read,
            is_data_write=tool.is_data_write,
        )
        record = LateRegistrationRecord(
            tool_name=tool.name,
            reason=reason,
            authorized_by=authorized_by,
            registered_at_turn=current_turn,
            l2_active_at_registration=False,
            node_id=node.node_id,
        )
        self._graph.nodes.append(node)
        self._nodes_by_name[tool.name] = node
        self._graph.late_registrations.append(record)
        ok, err = _apply_new_signature(self._graph.signing_payload())
        if not ok:
            self._graph.nodes.pop()
            self._nodes_by_name.pop(tool.name, None)
            self._graph.late_registrations.pop()
            return False, err
        return True, f"Tool '{tool.name}' successfully registered and added to EGI graph"

    @property
    def graph_id(self) -> str:
        return self._graph.graph_id

    @property
    def registered_tools(self) -> list[str]:
        return [n.tool_name for n in self._graph.nodes]

    @property
    def late_registrations(self) -> list[LateRegistrationRecord]:
        return list(self._graph.late_registrations)

    @property
    def algorithm(self) -> str:
        return self._graph.algorithm

    @property
    def key_id(self) -> str:
        return self._graph.key_id
