/**
 * Provenance Ledger — SQLite-backed provenance store.
 *
 * Tags every memory write with source, trust level, timestamp,
 * session ID, and content hash. Enables cross-session queries
 * for the L4 Memory Contamination detection layer.
 *
 * Depends on: better-sqlite3, src/types/signals.ts
 */

import Database from 'better-sqlite3';
import type { TrustLevel } from '../types/signals.js';

// ── Types ───────────────────────────────────────────────────────────

/** A single provenance record from the ledger. */
export interface ProvenanceRecord {
  readonly nodeId: string;
  readonly sessionId: string;
  readonly trustLevel: TrustLevel;
  readonly source: string;
  readonly contentHash: string;
  readonly timestamp: number;
}

/** Options for creating a ledger instance. */
export interface LedgerOptions {
  readonly dbPath?: string;
}

/** Provenance ledger backed by better-sqlite3. */
export interface ProvenanceLedger {
  /** Record a memory write. */
  readonly recordWrite: (record: ProvenanceRecord) => void;
  /** Query all writes to a node, ordered by timestamp desc. */
  readonly getNodeHistory: (nodeId: string) => readonly ProvenanceRecord[];
  /** Query the latest write to a node. */
  readonly getLatestWrite: (nodeId: string) => ProvenanceRecord | undefined;
  /** Query all writes from a specific session. */
  readonly getSessionWrites: (sessionId: string) => readonly ProvenanceRecord[];
  /** Check if a node was ever written by an untrusted source. */
  readonly isNodeTainted: (nodeId: string) => boolean;
  /** Check if a node was written by an untrusted source in a different session. */
  readonly isCrossSessionTainted: (nodeId: string, currentSessionId: string) => boolean;
  /** Close the database connection. */
  readonly close: () => void;
}

// ── Hashing ─────────────────────────────────────────────────────────

/**
 * Simple djb2 hash for content deduplication.
 * Not cryptographic — used for change detection only.
 */
export function hashContent(content: string): string {
  let hash = 5381;
  for (let i = 0; i < content.length; i++) {
    hash = (hash * 33) ^ content.charCodeAt(i);
  }
  // Convert to unsigned 32-bit hex string
  return (hash >>> 0).toString(16).padStart(8, '0');
}

// ── Schema ──────────────────────────────────────────────────────────

const SCHEMA = `
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
`;

// ── Row mapping ─────────────────────────────────────────────────────

interface RawRow {
  node_id: string;
  session_id: string;
  trust_level: string;
  source: string;
  content_hash: string;
  timestamp: number;
}

function rowToRecord(row: RawRow): ProvenanceRecord {
  return {
    nodeId: row.node_id,
    sessionId: row.session_id,
    trustLevel: row.trust_level as TrustLevel,
    source: row.source,
    contentHash: row.content_hash,
    timestamp: row.timestamp,
  };
}

// ── Factory ─────────────────────────────────────────────────────────

/** Create a new provenance ledger backed by SQLite. */
export function createLedger(options?: LedgerOptions): ProvenanceLedger {
  const dbPath = options?.dbPath ?? ':memory:';
  const db = new Database(dbPath);

  // Enable WAL mode for better concurrent read performance
  db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);

  // Prepare statements once for reuse
  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO memory_provenance
      (node_id, session_id, trust_level, source, content_hash, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const historyStmt = db.prepare(`
    SELECT * FROM memory_provenance
    WHERE node_id = ?
    ORDER BY timestamp DESC
  `);

  const latestStmt = db.prepare(`
    SELECT * FROM memory_provenance
    WHERE node_id = ?
    ORDER BY timestamp DESC
    LIMIT 1
  `);

  const sessionStmt = db.prepare(`
    SELECT * FROM memory_provenance
    WHERE session_id = ?
    ORDER BY timestamp ASC
  `);

  const taintedStmt = db.prepare(`
    SELECT COUNT(*) as cnt FROM memory_provenance
    WHERE node_id = ? AND trust_level = 'untrusted'
  `);

  const crossSessionStmt = db.prepare(`
    SELECT COUNT(*) as cnt FROM memory_provenance
    WHERE node_id = ? AND trust_level = 'untrusted' AND session_id != ?
  `);

  const recordWrite = (record: ProvenanceRecord): void => {
    insertStmt.run(
      record.nodeId,
      record.sessionId,
      record.trustLevel,
      record.source,
      record.contentHash,
      record.timestamp,
    );
  };

  const getNodeHistory = (nodeId: string): readonly ProvenanceRecord[] => {
    const rows = historyStmt.all(nodeId) as RawRow[];
    return rows.map(rowToRecord);
  };

  const getLatestWrite = (nodeId: string): ProvenanceRecord | undefined => {
    const row = latestStmt.get(nodeId) as RawRow | undefined;
    return row ? rowToRecord(row) : undefined;
  };

  const getSessionWrites = (sessionId: string): readonly ProvenanceRecord[] => {
    const rows = sessionStmt.all(sessionId) as RawRow[];
    return rows.map(rowToRecord);
  };

  const isNodeTainted = (nodeId: string): boolean => {
    const result = taintedStmt.get(nodeId) as { cnt: number };
    return result.cnt > 0;
  };

  const isCrossSessionTainted = (nodeId: string, currentSessionId: string): boolean => {
    const result = crossSessionStmt.get(nodeId, currentSessionId) as {
      cnt: number;
    };
    return result.cnt > 0;
  };

  const close = (): void => {
    db.close();
  };

  return {
    recordWrite,
    getNodeHistory,
    getLatestWrite,
    getSessionWrites,
    isNodeTainted,
    isCrossSessionTainted,
    close,
  };
}
