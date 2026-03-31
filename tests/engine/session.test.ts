/**
 * Tests for DetectionSession state management.
 */

import { describe, it, expect } from 'vitest';
import { createSession, recordSignal, resetSession } from '../../src/engine/session.js';
import type { PrivilegedDataSignal, UntrustedTokensSignal } from '../../src/types/signals.js';

describe('createSession', () => {
  it('should create a session with a default ID', () => {
    const session = createSession();
    expect(session.sessionId).toMatch(/^session-\d+-\d+$/);
  });

  it('should create a session with a custom ID', () => {
    const session = createSession('my-session');
    expect(session.sessionId).toBe('my-session');
  });

  it('should initialize all state as empty', () => {
    const session = createSession();
    expect(session.accessedFields.size).toBe(0);
    expect(session.privilegedValues.size).toBe(0);
    expect(session.sensitiveEntities).toHaveLength(0);
    expect(session.trustedSourcesAccessed.size).toBe(0);
    expect(session.untrustedTokenCount).toBe(0);
    expect(session.untrustedSources.size).toBe(0);
    expect(session.signalsByTurn.size).toBe(0);
    expect(session.turnCounter).toBe(0);
  });
});

describe('recordSignal', () => {
  it('should record a signal under its turn ID', () => {
    const session = createSession();
    const signal: PrivilegedDataSignal = {
      layer: 'L1',
      signal: 'PRIVILEGED_DATA_ACCESSED',
      turnId: 'turn-001',
      source: 'readData',
      fields: ['email'],
      trustLevel: 'trusted',
      timestamp: Date.now(),
    };

    recordSignal(session, signal);

    expect(session.signalsByTurn.get('turn-001')).toHaveLength(1);
    expect(session.signalsByTurn.get('turn-001')![0].layer).toBe('L1');
  });

  it('should append multiple signals to the same turn', () => {
    const session = createSession();
    const l1: PrivilegedDataSignal = {
      layer: 'L1',
      signal: 'PRIVILEGED_DATA_ACCESSED',
      turnId: 'turn-001',
      source: 'readData',
      fields: ['email'],
      trustLevel: 'trusted',
      timestamp: Date.now(),
    };
    const l2: UntrustedTokensSignal = {
      layer: 'L2',
      signal: 'UNTRUSTED_TOKENS_IN_CONTEXT',
      turnId: 'turn-001',
      source: 'fetchUrl',
      tokenCount: 100,
      trustLevel: 'untrusted',
      timestamp: Date.now(),
    };

    recordSignal(session, l1);
    recordSignal(session, l2);

    expect(session.signalsByTurn.get('turn-001')).toHaveLength(2);
  });

  it('should separate signals by turn ID', () => {
    const session = createSession();
    const s1: PrivilegedDataSignal = {
      layer: 'L1',
      signal: 'PRIVILEGED_DATA_ACCESSED',
      turnId: 'turn-001',
      source: 'readData',
      fields: ['email'],
      trustLevel: 'trusted',
      timestamp: Date.now(),
    };
    const s2: PrivilegedDataSignal = {
      layer: 'L1',
      signal: 'PRIVILEGED_DATA_ACCESSED',
      turnId: 'turn-002',
      source: 'readData',
      fields: ['ssn'],
      trustLevel: 'trusted',
      timestamp: Date.now(),
    };

    recordSignal(session, s1);
    recordSignal(session, s2);

    expect(session.signalsByTurn.size).toBe(2);
    expect(session.signalsByTurn.get('turn-001')).toHaveLength(1);
    expect(session.signalsByTurn.get('turn-002')).toHaveLength(1);
  });
});

describe('resetSession', () => {
  it('should clear all session state', () => {
    const session = createSession();
    session.accessedFields.add('email');
    session.privilegedValues.add('test@example.com');
    session.sensitiveEntities.push({
      type: 'email',
      rawValue: 'test@example.com',
      canonicalValue: 'test@example.com',
      confidence: 'high',
    });
    session.trustedSourcesAccessed.add('readData');
    session.untrustedTokenCount = 500;
    session.untrustedSources.add('fetchUrl');
    session.turnCounter = 5;
    recordSignal(session, {
      layer: 'L1',
      signal: 'PRIVILEGED_DATA_ACCESSED',
      turnId: 'turn-001',
      source: 'readData',
      fields: ['email'],
      trustLevel: 'trusted',
      timestamp: Date.now(),
    });

    resetSession(session);

    expect(session.accessedFields.size).toBe(0);
    expect(session.privilegedValues.size).toBe(0);
    expect(session.sensitiveEntities).toHaveLength(0);
    expect(session.trustedSourcesAccessed.size).toBe(0);
    expect(session.untrustedTokenCount).toBe(0);
    expect(session.untrustedSources.size).toBe(0);
    expect(session.signalsByTurn.size).toBe(0);
    expect(session.turnCounter).toBe(0);
  });

  it('should rotate session ID on reset for L4 cross-session detection', () => {
    const session = createSession('old-id');
    resetSession(session);
    expect(session.sessionId).not.toBe('old-id');
    expect(session.sessionId).toMatch(/^session-\d+-\d+$/);
  });
});
