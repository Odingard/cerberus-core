"""
cerberus_ai.graph.ledger
~~~~~~~~~~~~~~~~~~~~~~~~
Provenance ledger — SQLite-backed store for memory-write provenance.

Every memory write the L4 tracker sees is recorded here: node id,
session id, trust level, source, content hash, and timestamp. Queries
support cross-session taint checks and full history lookups.

Parity port of ``src/graph/ledger.ts``. Uses Python's stdlib
``sqlite3`` so there are no extra runtime dependencies.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from typing import Literal

TrustLevel = Literal["trusted", "untrusted", "unknown"]


@dataclass(frozen=True)
class ProvenanceRecord:
    node_id: str
    session_id: str
    trust_level: TrustLevel
    source: str
    content_hash: str
    timestamp: int


_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_provenance (
  node_id      TEXT    NOT NULL,
  session_id   TEXT    NOT NULL,
  trust_level  TEXT    NOT NULL CHECK(trust_level IN ('trusted','untrusted','unknown')),
  source       TEXT    NOT NULL,
  content_hash TEXT    NOT NULL,
  timestamp    INTEGER NOT NULL,
  PRIMARY KEY (node_id, timestamp)
);
CREATE INDEX IF NOT EXISTS idx_provenance_node ON memory_provenance(node_id);
CREATE INDEX IF NOT EXISTS idx_provenance_session ON memory_provenance(session_id);
"""


def hash_content(content: str) -> str:
    """djb2 hash, 32-bit hex. Not cryptographic — used for change detection."""
    h = 5381
    for ch in content:
        h = ((h * 33) ^ ord(ch)) & 0xFFFFFFFF
    return f"{h:08x}"


class ProvenanceLedger:
    """Thread-safe SQLite-backed provenance ledger."""

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = db_path or ":memory:"
        # ``check_same_thread=False`` because we guard with our own lock.
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        try:
            self._db.execute("PRAGMA journal_mode = WAL")
        except sqlite3.DatabaseError:
            pass
        self._lock = threading.Lock()

    def record_write(self, record: ProvenanceRecord) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO memory_provenance "
                "(node_id, session_id, trust_level, source, content_hash, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    record.node_id,
                    record.session_id,
                    record.trust_level,
                    record.source,
                    record.content_hash,
                    record.timestamp,
                ),
            )
            self._db.commit()

    def get_node_history(self, node_id: str) -> list[ProvenanceRecord]:
        with self._lock:
            cur = self._db.execute(
                "SELECT node_id, session_id, trust_level, source, content_hash, timestamp "
                "FROM memory_provenance WHERE node_id = ? ORDER BY timestamp DESC",
                (node_id,),
            )
            rows = cur.fetchall()
        return [ProvenanceRecord(*r) for r in rows]

    def get_latest_write(self, node_id: str) -> ProvenanceRecord | None:
        history = self.get_node_history(node_id)
        return history[0] if history else None

    def get_session_writes(self, session_id: str) -> list[ProvenanceRecord]:
        with self._lock:
            cur = self._db.execute(
                "SELECT node_id, session_id, trust_level, source, content_hash, timestamp "
                "FROM memory_provenance WHERE session_id = ? ORDER BY timestamp ASC",
                (session_id,),
            )
            rows = cur.fetchall()
        return [ProvenanceRecord(*r) for r in rows]

    def is_node_tainted(self, node_id: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "SELECT COUNT(*) FROM memory_provenance "
                "WHERE node_id = ? AND trust_level = 'untrusted'",
                (node_id,),
            )
            (count,) = cur.fetchone()
        return bool(count > 0)

    def is_cross_session_tainted(self, node_id: str, current_session_id: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "SELECT COUNT(*) FROM memory_provenance "
                "WHERE node_id = ? AND trust_level = 'untrusted' AND session_id != ?",
                (node_id, current_session_id),
            )
            (count,) = cur.fetchone()
        return bool(count > 0)

    def close(self) -> None:
        with self._lock:
            self._db.close()
