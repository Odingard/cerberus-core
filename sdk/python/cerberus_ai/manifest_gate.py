"""
cerberus_ai.manifest_gate
~~~~~~~~~~~~~~~~~~~~~~~~~
Per-turn cryptographic authorization gate.

Runs before any detector or tool executor is invoked. If the session
carries a signed execution-graph manifest (the delegation graph),
the manifest's signature is verified against its bound canonical
payload. Any failure produces a ``MANIFEST_SIGNATURE_INVALID`` event
and the inspector short-circuits the turn to ``BLOCKED`` —
the "no valid signature → no state transition" rule.

Fail-closed by design: a missing verifier, an algorithm mismatch, a
``key_id`` mismatch, or a bad signature all yield the same outcome.
Callers MUST NOT downgrade a signature failure to a soft alert — the
inspector bypasses action resolution for integrity signals.

Parity port of ``src/engine/manifest-gate.ts``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from cerberus_ai.egi.signer import Verifier
from cerberus_ai.graph.delegation import DelegationGraph, verify_graph_integrity

ManifestInvalidReason = Literal[
    "ALGORITHM_MISMATCH",
    "KEY_ID_MISMATCH",
    "SIGNATURE_MISMATCH",
    "VERIFIER_MISSING",
]


@dataclass(frozen=True)
class ManifestSignatureInvalidSignal:
    session_id: str
    turn_id: str
    algorithm: str
    key_id: str
    reason: ManifestInvalidReason
    timestamp: int


def verify_manifest_before_turn(
    graph: DelegationGraph | None,
    session_id: str,
    turn_id: str,
    verifier: Verifier | None = None,
) -> ManifestSignatureInvalidSignal | None:
    """
    Verify the session's signed manifest before a turn begins.

    Returns ``None`` when there is no manifest (single-agent mode) or when
    verification succeeds; returns a :class:`ManifestSignatureInvalidSignal`
    otherwise.
    """
    if graph is None:
        return None

    if verifier is not None:
        if verifier.algorithm != graph.algorithm:
            return ManifestSignatureInvalidSignal(
                session_id=session_id,
                turn_id=turn_id,
                algorithm=graph.algorithm,
                key_id=graph.key_id,
                reason="ALGORITHM_MISMATCH",
                timestamp=int(time.time() * 1000),
            )
        if verifier.key_id != graph.key_id:
            return ManifestSignatureInvalidSignal(
                session_id=session_id,
                turn_id=turn_id,
                algorithm=graph.algorithm,
                key_id=graph.key_id,
                reason="KEY_ID_MISMATCH",
                timestamp=int(time.time() * 1000),
            )

    ok = verify_graph_integrity(graph, verifier)
    if ok:
        return None

    available = verifier or graph._verifier
    return ManifestSignatureInvalidSignal(
        session_id=session_id,
        turn_id=turn_id,
        algorithm=graph.algorithm,
        key_id=graph.key_id,
        reason="SIGNATURE_MISMATCH" if available is not None else "VERIFIER_MISSING",
        timestamp=int(time.time() * 1000),
    )
