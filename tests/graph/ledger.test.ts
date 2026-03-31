/**
 * Tests for the SQLite-backed Provenance Ledger.
 */

import { describe, it, expect, afterEach } from 'vitest';
import { createLedger, hashContent } from '../../src/graph/ledger.js';
import type { ProvenanceLedger, ProvenanceRecord } from '../../src/graph/ledger.js';

// ── Helpers ─────────────────────────────────────────────────────────

function makeRecord(overrides: Partial<ProvenanceRecord> = {}): ProvenanceRecord {
  return {
    nodeId: 'node-1',
    sessionId: 'session-A',
    trustLevel: 'untrusted',
    source: 'fetchUrl',
    contentHash: hashContent('test content'),
    timestamp: 1000,
    ...overrides,
  };
}

// ── hashContent ─────────────────────────────────────────────────────

describe('hashContent', () => {
  it('should return an 8-character hex string', () => {
    const hash = hashContent('hello world');
    expect(hash).toHaveLength(8);
    expect(hash).toMatch(/^[0-9a-f]{8}$/);
  });

  it('should produce deterministic output', () => {
    expect(hashContent('same input')).toBe(hashContent('same input'));
  });

  it('should produce different hashes for different inputs', () => {
    expect(hashContent('input a')).not.toBe(hashContent('input b'));
  });

  it('should handle empty string', () => {
    const hash = hashContent('');
    expect(hash).toHaveLength(8);
    expect(hash).toMatch(/^[0-9a-f]{8}$/);
  });
});

// ── createLedger ────────────────────────────────────────────────────

describe('createLedger', () => {
  let ledger: ProvenanceLedger;

  afterEach(() => {
    ledger?.close();
  });

  it('should create an in-memory ledger by default', () => {
    ledger = createLedger();
    expect(ledger).toBeDefined();
  });

  it('should record and retrieve a write', () => {
    ledger = createLedger();
    const record = makeRecord();

    ledger.recordWrite(record);
    const history = ledger.getNodeHistory('node-1');

    expect(history).toHaveLength(1);
    expect(history[0].nodeId).toBe('node-1');
    expect(history[0].sessionId).toBe('session-A');
    expect(history[0].trustLevel).toBe('untrusted');
    expect(history[0].source).toBe('fetchUrl');
  });

  it('should return node history in descending timestamp order', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ timestamp: 1000 }));
    ledger.recordWrite(makeRecord({ timestamp: 3000 }));
    ledger.recordWrite(makeRecord({ timestamp: 2000 }));

    const history = ledger.getNodeHistory('node-1');
    expect(history).toHaveLength(3);
    expect(history[0].timestamp).toBe(3000);
    expect(history[1].timestamp).toBe(2000);
    expect(history[2].timestamp).toBe(1000);
  });

  it('should return latest write for a node', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ timestamp: 1000, source: 'old' }));
    ledger.recordWrite(makeRecord({ timestamp: 2000, source: 'new' }));

    const latest = ledger.getLatestWrite('node-1');
    expect(latest).toBeDefined();
    expect(latest!.source).toBe('new');
    expect(latest!.timestamp).toBe(2000);
  });

  it('should return undefined for nonexistent node latest write', () => {
    ledger = createLedger();
    expect(ledger.getLatestWrite('nonexistent')).toBeUndefined();
  });

  it('should return empty history for nonexistent node', () => {
    ledger = createLedger();
    expect(ledger.getNodeHistory('nonexistent')).toHaveLength(0);
  });

  it('should query writes by session ID', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ sessionId: 'session-A', timestamp: 1000 }));
    ledger.recordWrite(makeRecord({ sessionId: 'session-A', nodeId: 'node-2', timestamp: 2000 }));
    ledger.recordWrite(makeRecord({ sessionId: 'session-B', nodeId: 'node-3', timestamp: 3000 }));

    const sessionAWrites = ledger.getSessionWrites('session-A');
    expect(sessionAWrites).toHaveLength(2);
    expect(sessionAWrites[0].timestamp).toBe(1000); // ASC order
    expect(sessionAWrites[1].timestamp).toBe(2000);

    const sessionBWrites = ledger.getSessionWrites('session-B');
    expect(sessionBWrites).toHaveLength(1);
  });

  it('should detect tainted nodes', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ trustLevel: 'untrusted' }));

    expect(ledger.isNodeTainted('node-1')).toBe(true);
  });

  it('should not flag trusted nodes as tainted', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ trustLevel: 'trusted' }));

    expect(ledger.isNodeTainted('node-1')).toBe(false);
  });

  it('should detect cross-session taint', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ sessionId: 'session-A', trustLevel: 'untrusted' }));

    expect(ledger.isCrossSessionTainted('node-1', 'session-B')).toBe(true);
    expect(ledger.isCrossSessionTainted('node-1', 'session-A')).toBe(false);
  });

  it('should handle INSERT OR REPLACE on duplicate primary key', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ timestamp: 1000, source: 'first' }));
    ledger.recordWrite(makeRecord({ timestamp: 1000, source: 'second' }));

    const history = ledger.getNodeHistory('node-1');
    expect(history).toHaveLength(1);
    expect(history[0].source).toBe('second');
  });

  it('should close without error', () => {
    ledger = createLedger();
    ledger.recordWrite(makeRecord());
    ledger.close();
    // Prevent afterEach double-close
    ledger = createLedger();
  });

  it('should persist data within the same instance', () => {
    ledger = createLedger();

    ledger.recordWrite(makeRecord({ nodeId: 'a', timestamp: 1 }));
    ledger.recordWrite(makeRecord({ nodeId: 'b', timestamp: 2 }));

    expect(ledger.getNodeHistory('a')).toHaveLength(1);
    expect(ledger.getNodeHistory('b')).toHaveLength(1);
    expect(ledger.isNodeTainted('a')).toBe(true);
  });
});
