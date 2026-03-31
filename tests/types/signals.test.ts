/**
 * Tests for core signal and risk vector types.
 * Validates type contracts are correctly defined and usable.
 */

import { describe, it, expect } from 'vitest';
import type {
  PrivilegedDataSignal,
  UntrustedTokensSignal,
  ExfiltrationRiskSignal,
  ContaminatedMemorySignal,
  RiskVector,
  RiskAssessment,
  DetectionSignal,
} from '../../src/types/signals.js';

describe('Signal Types', () => {
  it('should construct a valid L1 PrivilegedDataSignal', () => {
    const signal: PrivilegedDataSignal = {
      layer: 'L1',
      signal: 'PRIVILEGED_DATA_ACCESSED',
      turnId: 'turn-001',
      source: 'customer_records.json',
      fields: ['email', 'phone', 'ssn'],
      trustLevel: 'trusted',
      timestamp: Date.now(),
    };

    expect(signal.layer).toBe('L1');
    expect(signal.signal).toBe('PRIVILEGED_DATA_ACCESSED');
    expect(signal.fields).toHaveLength(3);
  });

  it('should construct a valid L2 UntrustedTokensSignal', () => {
    const signal: UntrustedTokensSignal = {
      layer: 'L2',
      signal: 'UNTRUSTED_TOKENS_IN_CONTEXT',
      turnId: 'turn-002',
      source: 'external_fetch',
      tokenCount: 150,
      trustLevel: 'untrusted',
      timestamp: Date.now(),
    };

    expect(signal.layer).toBe('L2');
    expect(signal.trustLevel).toBe('untrusted');
  });

  it('should construct a valid L3 ExfiltrationRiskSignal', () => {
    const signal: ExfiltrationRiskSignal = {
      layer: 'L3',
      signal: 'EXFILTRATION_RISK',
      turnId: 'turn-003',
      matchedFields: ['email'],
      destination: 'https://webhook.site/test',
      similarityScore: 0.92,
      timestamp: Date.now(),
    };

    expect(signal.layer).toBe('L3');
    expect(signal.similarityScore).toBeGreaterThan(0.9);
  });

  it('should construct a valid L4 ContaminatedMemorySignal', () => {
    const signal: ContaminatedMemorySignal = {
      layer: 'L4',
      signal: 'CONTAMINATED_MEMORY_ACTIVE',
      turnId: 'turn-004',
      sessionId: 'session-2026-02-28',
      nodeId: 'ext_fetch_3',
      contaminationSource: 'fetchExternalContent',
      timestamp: Date.now(),
    };

    expect(signal.layer).toBe('L4');
    expect(signal.sessionId).toContain('2026');
  });
});

describe('RiskVector', () => {
  it('should represent a clean turn with no signals', () => {
    const vector: RiskVector = { l1: false, l2: false, l3: false, l4: false };
    const score = [vector.l1, vector.l2, vector.l3, vector.l4].filter(Boolean).length;

    expect(score).toBe(0);
  });

  it('should represent a full Lethal Trifecta + memory contamination', () => {
    const vector: RiskVector = { l1: true, l2: true, l3: true, l4: true };
    const score = [vector.l1, vector.l2, vector.l3, vector.l4].filter(Boolean).length;

    expect(score).toBe(4);
  });
});

describe('RiskAssessment', () => {
  it('should aggregate signals into a scored assessment', () => {
    const signals: DetectionSignal[] = [
      {
        layer: 'L1',
        signal: 'PRIVILEGED_DATA_ACCESSED',
        turnId: 'turn-007',
        source: 'customer_records.json',
        fields: ['email'],
        trustLevel: 'trusted',
        timestamp: Date.now(),
      },
      {
        layer: 'L2',
        signal: 'UNTRUSTED_TOKENS_IN_CONTEXT',
        turnId: 'turn-007',
        source: 'external_fetch',
        tokenCount: 200,
        trustLevel: 'untrusted',
        timestamp: Date.now(),
      },
    ];

    const assessment: RiskAssessment = {
      turnId: 'turn-007',
      vector: { l1: true, l2: true, l3: false, l4: false },
      score: 2,
      action: 'log',
      signals,
      timestamp: Date.now(),
    };

    expect(assessment.score).toBe(2);
    expect(assessment.action).toBe('log');
    expect(assessment.signals).toHaveLength(2);
  });
});
