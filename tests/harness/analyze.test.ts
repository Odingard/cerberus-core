/**
 * Tests for the stress test analyzer.
 */

import { describe, it, expect } from 'vitest';
import { isStressSummary, computePerPayloadStats } from '../../harness/analyze.js';
import type {
  RunSummary,
  StressSummary,
  ExecutionTrace,
  PayloadCategory,
} from '../../harness/types.js';

/** Create a minimal RunSummary for testing. */
function makeRunSummary(overrides?: Partial<RunSummary>): RunSummary {
  return {
    totalRuns: 10,
    successCount: 8,
    partialCount: 1,
    failureCount: 1,
    errorCount: 0,
    successRate: 0.8,
    byCategory: {
      'direct-injection': { total: 2, successes: 2, rate: 1 },
      'encoded-obfuscated': { total: 2, successes: 2, rate: 1 },
      'social-engineering': { total: 2, successes: 1, rate: 0.5 },
      'multi-turn': { total: 2, successes: 2, rate: 1 },
      multilingual: { total: 1, successes: 1, rate: 1 },
      'advanced-technique': { total: 1, successes: 0, rate: 0 },
    },
    completedAt: new Date().toISOString(),
    ...overrides,
  };
}

/** Create a minimal mock ExecutionTrace for testing. */
function makeTrace(
  payloadId: string,
  category: PayloadCategory,
  outcome: 'success' | 'failure' | 'partial' | 'error',
): ExecutionTrace {
  return {
    schemaVersion: '1.0.0',
    runId: `run-${payloadId}-${Date.now()}`,
    payload: {
      id: payloadId,
      category,
      content: 'test',
      description: 'test',
      expectedOutcome: 'exfiltration-success',
      tags: ['test'],
    },
    config: {
      toolMode: 'simulated',
      model: 'gpt-4o-mini',
      maxTurns: 10,
      externalContentUrl: '',
      exfiltrationWebhookUrl: '',
      userPrompt: 'test',
      systemPromptId: 'permissive',
    },
    turns: [],
    labels: {
      privilegedAccessOccurred: outcome === 'success',
      injectionDelivered: outcome === 'success',
      exfiltrationAttempted: outcome === 'success' || outcome === 'partial',
      privateDataInExfiltration: outcome === 'success',
      exfiltratedFields: [],
      riskVector: {
        l1: outcome === 'success',
        l2: outcome === 'success',
        l3: outcome === 'success',
        l4: false,
      },
      outcome,
    },
    tokenUsage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
    durationMs: 5000,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
  };
}

describe('isStressSummary', () => {
  it('should return true for a StressSummary', () => {
    const stress: StressSummary = {
      ...makeRunSummary(),
      trialsPerPayload: 3,
      systemPromptId: 'permissive',
      perPayload: [],
      meanSuccessRate: 0.8,
      successRateVariance: 0.01,
    };
    expect(isStressSummary(stress)).toBe(true);
  });

  it('should return false for a plain RunSummary', () => {
    expect(isStressSummary(makeRunSummary())).toBe(false);
  });
});

describe('computePerPayloadStats', () => {
  it('should group traces by payload ID and compute stats', () => {
    const traces = [
      makeTrace('DI-001', 'direct-injection', 'success'),
      makeTrace('DI-001', 'direct-injection', 'success'),
      makeTrace('DI-001', 'direct-injection', 'failure'),
      makeTrace('DI-002', 'direct-injection', 'success'),
    ];

    const stats = computePerPayloadStats(traces);

    expect(stats).toHaveLength(2);

    const di001 = stats.find((s) => s.payloadId === 'DI-001');
    expect(di001).toBeDefined();
    expect(di001!.trials).toBe(3);
    expect(di001!.successes).toBe(2);
    expect(di001!.failures).toBe(1);
    expect(di001!.successRate).toBeCloseTo(2 / 3);

    const di002 = stats.find((s) => s.payloadId === 'DI-002');
    expect(di002).toBeDefined();
    expect(di002!.trials).toBe(1);
    expect(di002!.successes).toBe(1);
    expect(di002!.successRate).toBe(1);
  });

  it('should return empty array for no traces', () => {
    expect(computePerPayloadStats([])).toHaveLength(0);
  });

  it('should sort results by payload ID', () => {
    const traces = [
      makeTrace('MT-001', 'multi-turn', 'success'),
      makeTrace('AT-001', 'advanced-technique', 'failure'),
      makeTrace('DI-001', 'direct-injection', 'success'),
    ];

    const stats = computePerPayloadStats(traces);

    expect(stats[0].payloadId).toBe('AT-001');
    expect(stats[1].payloadId).toBe('DI-001');
    expect(stats[2].payloadId).toBe('MT-001');
  });

  it('should track partial and error outcomes', () => {
    const traces = [
      makeTrace('DI-001', 'direct-injection', 'partial'),
      makeTrace('DI-001', 'direct-injection', 'error'),
    ];

    const stats = computePerPayloadStats(traces);
    expect(stats[0].partials).toBe(1);
    expect(stats[0].errors).toBe(1);
    expect(stats[0].successRate).toBe(0);
  });
});
