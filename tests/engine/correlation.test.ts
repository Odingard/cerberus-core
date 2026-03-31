/**
 * Tests for the Correlation Engine.
 */

import { describe, it, expect } from 'vitest';
import {
  assessRisk,
  buildRiskVector,
  computeScore,
  resolveAction,
} from '../../src/engine/correlation.js';
import type {
  DetectionSignal,
  PrivilegedDataSignal,
  UntrustedTokensSignal,
  ExfiltrationRiskSignal,
} from '../../src/types/signals.js';

const L1_SIGNAL: PrivilegedDataSignal = {
  layer: 'L1',
  signal: 'PRIVILEGED_DATA_ACCESSED',
  turnId: 'turn-001',
  source: 'readData',
  fields: ['email'],
  trustLevel: 'trusted',
  timestamp: Date.now(),
};

const L2_SIGNAL: UntrustedTokensSignal = {
  layer: 'L2',
  signal: 'UNTRUSTED_TOKENS_IN_CONTEXT',
  turnId: 'turn-001',
  source: 'fetchUrl',
  tokenCount: 100,
  trustLevel: 'untrusted',
  timestamp: Date.now(),
};

const L3_SIGNAL: ExfiltrationRiskSignal = {
  layer: 'L3',
  signal: 'EXFILTRATION_RISK',
  turnId: 'turn-001',
  matchedFields: ['email:alice@example.com'],
  destination: 'attacker@evil.com',
  similarityScore: 0.8,
  timestamp: Date.now(),
};

describe('buildRiskVector', () => {
  it('should return all false for no signals', () => {
    const vector = buildRiskVector([]);
    expect(vector).toEqual({ l1: false, l2: false, l3: false, l4: false });
  });

  it('should set l1 for L1 signal', () => {
    const vector = buildRiskVector([L1_SIGNAL]);
    expect(vector.l1).toBe(true);
    expect(vector.l2).toBe(false);
  });

  it('should set l2 for L2 signal', () => {
    const vector = buildRiskVector([L2_SIGNAL]);
    expect(vector.l2).toBe(true);
    expect(vector.l1).toBe(false);
  });

  it('should set l3 for L3 signal', () => {
    const vector = buildRiskVector([L3_SIGNAL]);
    expect(vector.l3).toBe(true);
  });

  it('should set multiple bits for Lethal Trifecta', () => {
    const vector = buildRiskVector([L1_SIGNAL, L2_SIGNAL, L3_SIGNAL]);
    expect(vector).toEqual({ l1: true, l2: true, l3: true, l4: false });
  });

  it('should handle duplicate layer signals', () => {
    const vector = buildRiskVector([L1_SIGNAL, L1_SIGNAL]);
    expect(vector.l1).toBe(true);
    expect(computeScore(vector)).toBe(1);
  });
});

describe('computeScore', () => {
  it('should return 0 for all-false vector', () => {
    expect(computeScore({ l1: false, l2: false, l3: false, l4: false })).toBe(0);
  });

  it('should return 1 for single true', () => {
    expect(computeScore({ l1: true, l2: false, l3: false, l4: false })).toBe(1);
  });

  it('should return 2 for two true', () => {
    expect(computeScore({ l1: true, l2: true, l3: false, l4: false })).toBe(2);
  });

  it('should return 3 for Lethal Trifecta', () => {
    expect(computeScore({ l1: true, l2: true, l3: true, l4: false })).toBe(3);
  });

  it('should return 4 for all true', () => {
    expect(computeScore({ l1: true, l2: true, l3: true, l4: true })).toBe(4);
  });
});

describe('resolveAction', () => {
  it('should return none when score < threshold (default 3)', () => {
    expect(resolveAction(2, {})).toBe('none');
    expect(resolveAction(0, {})).toBe('none');
  });

  it('should return alertMode when score >= threshold', () => {
    expect(resolveAction(3, { alertMode: 'alert' })).toBe('alert');
    expect(resolveAction(4, { alertMode: 'interrupt' })).toBe('interrupt');
  });

  it('should default alertMode to alert', () => {
    expect(resolveAction(3, {})).toBe('alert');
  });

  it('should use custom threshold', () => {
    expect(resolveAction(2, { threshold: 2, alertMode: 'interrupt' })).toBe('interrupt');
    expect(resolveAction(1, { threshold: 2 })).toBe('none');
  });

  it('should cap at log when alertMode is log', () => {
    expect(resolveAction(3, { alertMode: 'log' })).toBe('log');
    expect(resolveAction(4, { alertMode: 'log' })).toBe('log');
  });

  it('should return none for score 0 regardless of threshold', () => {
    expect(resolveAction(0, { threshold: 0, alertMode: 'interrupt' })).toBe('interrupt');
  });
});

describe('assessRisk', () => {
  it('should produce a complete risk assessment', () => {
    const signals: DetectionSignal[] = [L1_SIGNAL, L2_SIGNAL, L3_SIGNAL];
    const assessment = assessRisk('turn-001', signals, { alertMode: 'interrupt' });

    expect(assessment.turnId).toBe('turn-001');
    expect(assessment.vector).toEqual({ l1: true, l2: true, l3: true, l4: false });
    expect(assessment.score).toBe(3);
    expect(assessment.action).toBe('interrupt');
    expect(assessment.signals).toHaveLength(3);
    expect(assessment.timestamp).toBeGreaterThan(0);
  });

  it('should produce score 0 for no signals', () => {
    const assessment = assessRisk('turn-001', [], {});
    expect(assessment.score).toBe(0);
    expect(assessment.action).toBe('none');
  });

  it('should not trigger for score below threshold', () => {
    const assessment = assessRisk('turn-001', [L1_SIGNAL], { alertMode: 'interrupt' });
    expect(assessment.score).toBe(1);
    expect(assessment.action).toBe('none');
  });

  it('should trigger at custom threshold', () => {
    const assessment = assessRisk('turn-001', [L1_SIGNAL, L2_SIGNAL], {
      threshold: 2,
      alertMode: 'alert',
    });
    expect(assessment.score).toBe(2);
    expect(assessment.action).toBe('alert');
  });

  it('should use sessionSignals for cumulative vector when provided', () => {
    // Turn signals: just L3
    // Session signals: L1 + L2 + L3 (accumulated across turns)
    const assessment = assessRisk('turn-003', [L3_SIGNAL], { alertMode: 'interrupt' }, [
      L1_SIGNAL,
      L2_SIGNAL,
      L3_SIGNAL,
    ]);

    // Vector and score reflect cumulative session signals
    expect(assessment.vector).toEqual({ l1: true, l2: true, l3: true, l4: false });
    expect(assessment.score).toBe(3);
    expect(assessment.action).toBe('interrupt');

    // But signals field contains only the current turn's signals
    expect(assessment.signals).toHaveLength(1);
    expect(assessment.signals[0].layer).toBe('L3');
  });

  it('should fall back to turnSignals when sessionSignals not provided', () => {
    const assessment = assessRisk('turn-001', [L1_SIGNAL], { alertMode: 'interrupt' });

    expect(assessment.vector).toEqual({ l1: true, l2: false, l3: false, l4: false });
    expect(assessment.score).toBe(1);
    expect(assessment.action).toBe('none');
    expect(assessment.signals).toHaveLength(1);
  });
});
