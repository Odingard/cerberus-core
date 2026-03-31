/**
 * Tests for the benchmark runner — comparison logic, summary aggregation.
 */

import { describe, it, expect } from 'vitest';
import {
  compareBenchmark,
  summarizeBenchmark,
  createBenchmarkGuard,
  formatBenchmarkTable,
  BENCHMARK_CONFIG,
  BENCHMARK_OUTBOUND_TOOLS,
} from '../../harness/benchmark.js';
import type { PayloadBenchmarkResult } from '../../harness/benchmark.js';
import type { GroundTruthLabels } from '../../harness/types.js';
import type { RiskAssessment } from '../../src/types/signals.js';

// ── Helpers ─────────────────────────────────────────────────────────

function makeLabels(overrides: Partial<GroundTruthLabels> = {}): GroundTruthLabels {
  return {
    privilegedAccessOccurred: true,
    injectionDelivered: true,
    exfiltrationAttempted: true,
    privateDataInExfiltration: true,
    exfiltratedFields: ['email:alice@example.com'],
    riskVector: { l1: true, l2: true, l3: true, l4: false },
    outcome: 'success',
    ...overrides,
  };
}

function makeAssessment(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    turnId: 'turn-000',
    vector: { l1: false, l2: false, l3: false, l4: false },
    score: 0,
    action: 'none',
    signals: [],
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeResult(overrides: Partial<PayloadBenchmarkResult> = {}): PayloadBenchmarkResult {
  const labels = makeLabels();
  const assessments = [
    makeAssessment({ vector: { l1: true, l2: false, l3: false, l4: false }, score: 1 }),
    makeAssessment({ vector: { l1: false, l2: true, l3: false, l4: false }, score: 1 }),
    makeAssessment({
      vector: { l1: false, l2: false, l3: true, l4: false },
      score: 1,
      action: 'interrupt',
    }),
  ];
  const comparison = compareBenchmark(labels, assessments);
  return {
    ...comparison,
    payloadId: 'DI-001',
    category: 'direct-injection',
    ...overrides,
  };
}

// ── compareBenchmark ────────────────────────────────────────────────

describe('compareBenchmark', () => {
  it('should classify TP when ground truth and detection match', () => {
    const labels = makeLabels();
    const assessments = [
      makeAssessment({
        vector: { l1: true, l2: true, l3: true, l4: false },
        score: 3,
        action: 'interrupt',
      }),
    ];

    const result = compareBenchmark(labels, assessments);

    expect(result.layerResults).toHaveLength(3);
    expect(result.layerResults[0]).toEqual({
      layer: 'L1',
      expected: true,
      detected: true,
      result: 'TP',
    });
    expect(result.layerResults[1]).toEqual({
      layer: 'L2',
      expected: true,
      detected: true,
      result: 'TP',
    });
    expect(result.layerResults[2]).toEqual({
      layer: 'L3',
      expected: true,
      detected: true,
      result: 'TP',
    });
  });

  it('should classify FN when expected but not detected', () => {
    const labels = makeLabels();
    const assessments = [
      makeAssessment({ vector: { l1: true, l2: false, l3: false, l4: false }, score: 1 }),
    ];

    const result = compareBenchmark(labels, assessments);

    expect(result.layerResults[0].result).toBe('TP');
    expect(result.layerResults[1].result).toBe('FN');
    expect(result.layerResults[2].result).toBe('FN');
  });

  it('should classify FP when detected but not expected', () => {
    const labels = makeLabels({
      riskVector: { l1: false, l2: false, l3: false, l4: false },
    });
    const assessments = [
      makeAssessment({ vector: { l1: true, l2: false, l3: false, l4: false }, score: 1 }),
    ];

    const result = compareBenchmark(labels, assessments);

    expect(result.layerResults[0].result).toBe('FP');
    expect(result.layerResults[1].result).toBe('TN');
    expect(result.layerResults[2].result).toBe('TN');
  });

  it('should classify TN when neither expected nor detected', () => {
    const labels = makeLabels({
      riskVector: { l1: false, l2: false, l3: false, l4: false },
    });
    const assessments: RiskAssessment[] = [];

    const result = compareBenchmark(labels, assessments);

    expect(result.layerResults[0].result).toBe('TN');
    expect(result.layerResults[1].result).toBe('TN');
    expect(result.layerResults[2].result).toBe('TN');
  });

  it('should compute maxScore from all assessments', () => {
    const labels = makeLabels();
    const assessments = [
      makeAssessment({ score: 1 }),
      makeAssessment({ score: 3 }),
      makeAssessment({ score: 2 }),
    ];

    const result = compareBenchmark(labels, assessments);
    expect(result.maxScore).toBe(3);
  });

  it('should return maxScore 0 for empty assessments', () => {
    const labels = makeLabels();
    const result = compareBenchmark(labels, []);
    expect(result.maxScore).toBe(0);
  });

  it('should set wouldHaveBlocked when any assessment has interrupt', () => {
    const labels = makeLabels();
    const assessments = [
      makeAssessment({ action: 'none' }),
      makeAssessment({ action: 'interrupt' }),
    ];

    const result = compareBenchmark(labels, assessments);
    expect(result.wouldHaveBlocked).toBe(true);
  });

  it('should not set wouldHaveBlocked when no interrupt', () => {
    const labels = makeLabels();
    const assessments = [makeAssessment({ action: 'none' }), makeAssessment({ action: 'alert' })];

    const result = compareBenchmark(labels, assessments);
    expect(result.wouldHaveBlocked).toBe(false);
  });

  it('should OR risk vectors across multiple assessments', () => {
    const labels = makeLabels();
    const assessments = [
      makeAssessment({ vector: { l1: true, l2: false, l3: false, l4: false } }),
      makeAssessment({ vector: { l1: false, l2: true, l3: false, l4: false } }),
      makeAssessment({ vector: { l1: false, l2: false, l3: true, l4: false } }),
    ];

    const result = compareBenchmark(labels, assessments);
    expect(result.cerberusVector).toEqual({ l1: true, l2: true, l3: true, l4: false });
  });
});

// ── summarizeBenchmark ──────────────────────────────────────────────

describe('summarizeBenchmark', () => {
  it('should compute overall detection rate', () => {
    const results = [
      makeResult(), // all detected
      makeResult(), // all detected
    ];

    const summary = summarizeBenchmark(results);
    expect(summary.detectionRate).toBe(1.0);
    expect(summary.totalPayloads).toBe(2);
  });

  it('should compute block rate', () => {
    const fullDetect = makeResult();
    const noBlock = makeResult({
      wouldHaveBlocked: false,
      layerResults: [
        { layer: 'L1', expected: true, detected: true, result: 'TP' },
        { layer: 'L2', expected: true, detected: true, result: 'TP' },
        { layer: 'L3', expected: true, detected: true, result: 'TP' },
      ],
    });

    const summary = summarizeBenchmark([fullDetect, noBlock]);
    expect(summary.blockRate).toBe(0.5);
  });

  it('should accumulate per-layer TP/FP/FN/TN', () => {
    const r1 = makeResult({
      layerResults: [
        { layer: 'L1', expected: true, detected: true, result: 'TP' },
        { layer: 'L2', expected: true, detected: false, result: 'FN' },
        { layer: 'L3', expected: false, detected: false, result: 'TN' },
      ],
    });
    const r2 = makeResult({
      layerResults: [
        { layer: 'L1', expected: false, detected: true, result: 'FP' },
        { layer: 'L2', expected: true, detected: true, result: 'TP' },
        { layer: 'L3', expected: true, detected: true, result: 'TP' },
      ],
    });

    const summary = summarizeBenchmark([r1, r2]);
    expect(summary.perLayer.L1.tp).toBe(1);
    expect(summary.perLayer.L1.fp).toBe(1);
    expect(summary.perLayer.L2.tp).toBe(1);
    expect(summary.perLayer.L2.fn).toBe(1);
    expect(summary.perLayer.L3.tn).toBe(1);
    expect(summary.perLayer.L3.tp).toBe(1);
  });

  it('should compute per-layer accuracy', () => {
    const r1 = makeResult({
      layerResults: [
        { layer: 'L1', expected: true, detected: true, result: 'TP' },
        { layer: 'L2', expected: true, detected: true, result: 'TP' },
        { layer: 'L3', expected: true, detected: true, result: 'TP' },
      ],
    });

    const summary = summarizeBenchmark([r1]);
    expect(summary.perLayer.L1.accuracy).toBe(1.0);
    expect(summary.perLayer.L2.accuracy).toBe(1.0);
    expect(summary.perLayer.L3.accuracy).toBe(1.0);
  });

  it('should track per-category statistics', () => {
    const r1 = makeResult({ category: 'direct-injection' });
    const r2 = makeResult({ category: 'social-engineering' });

    const summary = summarizeBenchmark([r1, r2]);
    expect(summary.byCategory['direct-injection'].total).toBe(1);
    expect(summary.byCategory['social-engineering'].total).toBe(1);
  });

  it('should handle empty results array', () => {
    const summary = summarizeBenchmark([]);
    expect(summary.totalPayloads).toBe(0);
    expect(summary.detectionRate).toBe(0);
    expect(summary.blockRate).toBe(0);
  });
});

// ── createBenchmarkGuard ────────────────────────────────────────────

describe('createBenchmarkGuard', () => {
  it('should wrap executors with guard', () => {
    const executors = {
      readPrivateData: (): Promise<string> => Promise.resolve('{}'),
      fetchExternalContent: (): Promise<string> => Promise.resolve('<html></html>'),
      sendOutboundReport: (): Promise<string> => Promise.resolve('sent'),
    };

    const guarded = createBenchmarkGuard(executors);
    expect(guarded.executors).toHaveProperty('readPrivateData');
    expect(guarded.executors).toHaveProperty('fetchExternalContent');
    expect(guarded.executors).toHaveProperty('sendOutboundReport');
    expect(guarded.session).toBeDefined();
    expect(guarded.assessments).toHaveLength(0);
  });

  it('should use default BENCHMARK_CONFIG', async () => {
    const executors = {
      readPrivateData: (): Promise<string> =>
        Promise.resolve('{"records":[{"email":"test@test.com"}]}'),
    };

    const guarded = createBenchmarkGuard(executors);
    await guarded.executors.readPrivateData({});

    // Should detect L1 signal since readPrivateData is 'trusted' in BENCHMARK_CONFIG
    expect(guarded.assessments).toHaveLength(1);
    expect(guarded.assessments[0].vector.l1).toBe(true);
  });

  it('should accept custom config', async () => {
    const executors = {
      readPrivateData: (): Promise<string> => Promise.resolve('{}'),
    };

    const customConfig: import('../../src/types/config.js').CerberusConfig = {
      alertMode: 'log',
    };

    const guarded = createBenchmarkGuard(executors, customConfig);
    await guarded.executors.readPrivateData({});

    // No trust overrides → no L1 signal
    expect(guarded.assessments[0].vector.l1).toBe(false);
  });
});

// ── formatBenchmarkTable ────────────────────────────────────────────

describe('formatBenchmarkTable', () => {
  it('should produce formatted output', () => {
    const results = [makeResult()];
    const summary = summarizeBenchmark(results);
    const output = formatBenchmarkTable(summary);

    expect(output).toContain('CERBERUS BENCHMARK RESULTS');
    expect(output).toContain('Detection Rate');
    expect(output).toContain('Block Rate');
    expect(output).toContain('L1');
    expect(output).toContain('L2');
    expect(output).toContain('L3');
  });

  it('should include per-category data', () => {
    const results = [makeResult({ category: 'direct-injection' })];
    const summary = summarizeBenchmark(results);
    const output = formatBenchmarkTable(summary);

    expect(output).toContain('direct-injection');
  });
});

// ── Constants ───────────────────────────────────────────────────────

describe('benchmark constants', () => {
  it('should have correct BENCHMARK_CONFIG', () => {
    expect(BENCHMARK_CONFIG.alertMode).toBe('interrupt');
    expect(BENCHMARK_CONFIG.threshold).toBe(3);
    expect(BENCHMARK_CONFIG.trustOverrides).toHaveLength(2);
  });

  it('should have correct BENCHMARK_OUTBOUND_TOOLS', () => {
    expect(BENCHMARK_OUTBOUND_TOOLS).toContain('sendOutboundReport');
    expect(BENCHMARK_OUTBOUND_TOOLS).toHaveLength(1);
  });
});
