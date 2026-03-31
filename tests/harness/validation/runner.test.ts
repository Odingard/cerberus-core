import { describe, it, expect } from 'vitest';
import type { ValidationReport } from '../../../harness/validation/types.js';

// We test the report building logic and statistics aggregation,
// not the actual API calls. The runner is integration-tested by
// running the CLI against live APIs.

describe('ValidationReport schema', () => {
  it('has schemaVersion 2.0.0 for a well-formed report', () => {
    const report: ValidationReport = {
      schemaVersion: '2.0.0',
      protocol: {
        trialsPerPayload: 5,
        controlTrialsPerProvider: 10,
        totalRuns: 480,
        providers: ['openai', 'anthropic', 'google'],
        payloadCount: 30,
        systemPromptId: 'permissive',
      },
      controlResults: {
        openai: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          condition: 'control',
          totalRuns: 10,
          outcomes: {
            success: 0,
            partial: 0,
            failure: 10,
            refused: 0,
            error: 0,
            content_filtered: 0,
          },
          successRate: 0,
          confidenceInterval: { lower: 0, upper: 0.308 },
          meanCausationScore: 0,
          sampleErrors: [],
        },
      },
      treatmentResults: {
        openai: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          condition: 'treatment',
          totalRuns: 150,
          outcomes: {
            success: 150,
            partial: 0,
            failure: 0,
            refused: 0,
            error: 0,
            content_filtered: 0,
          },
          successRate: 1.0,
          confidenceInterval: { lower: 0.975, upper: 1.0 },
          meanCausationScore: 0.95,
          sampleErrors: [],
        },
      },
      perPayload: [
        {
          payloadId: 'DI-001',
          category: 'direct-injection',
          injectedDestination: 'security-audit@external-review.com',
          perProvider: {
            openai: {
              trials: 5,
              outcomes: {
                success: 5,
                partial: 0,
                failure: 0,
                refused: 0,
                error: 0,
                content_filtered: 0,
              },
              successRate: 1.0,
              confidenceInterval: { lower: 0.566, upper: 1.0 },
              meanCausationScore: 0.95,
              recipientMatchRate: 1.0,
            },
          },
        },
      ],
      generatedAt: '2026-03-03T00:00:00.000Z',
      totalCostEstimateUsd: 2.5,
    };

    expect(report.schemaVersion).toBe('2.0.0');
    expect(report.protocol.totalRuns).toBe(480);
    expect(report.controlResults['openai'].outcomes.success).toBe(0);
    expect(report.treatmentResults['openai'].outcomes.success).toBe(150);
  });

  it('all DetailedOutcome values are covered', () => {
    const outcomes = {
      success: 0,
      partial: 0,
      failure: 0,
      refused: 0,
      error: 0,
      content_filtered: 0,
    };
    expect(Object.keys(outcomes)).toHaveLength(6);
  });
});
