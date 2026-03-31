import { describe, it, expect } from 'vitest';
import { toGroundTruthLabels, buildDetectionReport } from '../../../harness/validation/runner.js';
import type { EnhancedGroundTruth, RunCondition } from '../../../harness/validation/types.js';
import type { RiskAssessment, RiskVector } from '../../../src/types/signals.js';

// ── Test Helpers ──────────────────────────────────────────────────

function makeGroundTruth(overrides: Partial<EnhancedGroundTruth> = {}): EnhancedGroundTruth {
  return {
    privilegedAccessOccurred: true,
    injectionDelivered: true,
    exfiltrationAttempted: true,
    privateDataInExfiltration: true,
    exfiltratedFields: ['email', 'ssn'],
    riskVector: { l1: true, l2: true, l3: true, l4: false },
    condition: 'treatment',
    detailedOutcome: 'success',
    sequenceValid: true,
    recipientMatch: {
      injectedDestination: 'evil@test.com',
      actualRecipient: 'evil@test.com',
      matches: true,
      isExternal: true,
    },
    causation: { score: 0.9, factors: [], verdict: 'injection-caused' },
    refusalDetected: false,
    refusalText: null,
    piiDetailed: [],
    ...overrides,
  };
}

function makeAssessment(overrides: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    turnId: 'turn-1',
    vector: { l1: true, l2: true, l3: true, l4: false },
    score: 3,
    action: 'log',
    signals: [],
    timestamp: Date.now(),
    ...overrides,
  };
}

interface RunResultLike {
  readonly groundTruth: EnhancedGroundTruth;
  readonly agentResult: {
    readonly turns: readonly [];
    readonly finalMessage: null;
    readonly tokenUsage: { promptTokens: number; completionTokens: number; totalTokens: number };
    readonly errors: readonly [];
    readonly stopReason: 'stop';
  };
  readonly payloadId: string;
  readonly provider: string;
  readonly model: string;
  readonly durationMs: number;
  readonly tokenUsage: { promptTokens: number; completionTokens: number; totalTokens: number };
  readonly assessments: readonly RiskAssessment[];
}

function makeRunResult(
  payloadId: string,
  provider: string,
  condition: RunCondition,
  vector: RiskVector,
  assessments: readonly RiskAssessment[],
  detailedOutcome: EnhancedGroundTruth['detailedOutcome'] = 'success',
): RunResultLike {
  return {
    groundTruth: makeGroundTruth({
      condition,
      detailedOutcome,
      riskVector: vector,
      ...(condition === 'control'
        ? {
            privilegedAccessOccurred: true,
            injectionDelivered: false,
            exfiltrationAttempted: false,
            privateDataInExfiltration: false,
            exfiltratedFields: [],
            riskVector: { l1: true, l2: false, l3: false, l4: false },
          }
        : {}),
    }),
    agentResult: {
      turns: [],
      finalMessage: null,
      tokenUsage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
      errors: [],
      stopReason: 'stop',
    },
    payloadId,
    provider: provider,
    model: provider === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-20250514',
    durationMs: 1000,
    tokenUsage: { promptTokens: 100, completionTokens: 50, totalTokens: 150 },
    assessments,
  };
}

// ── toGroundTruthLabels ──────────────────────────────────────────

describe('toGroundTruthLabels', () => {
  it('maps success to success', () => {
    const gt = makeGroundTruth({ detailedOutcome: 'success' });
    const labels = toGroundTruthLabels(gt);
    expect(labels.outcome).toBe('success');
  });

  it('maps partial to partial', () => {
    const gt = makeGroundTruth({ detailedOutcome: 'partial' });
    const labels = toGroundTruthLabels(gt);
    expect(labels.outcome).toBe('partial');
  });

  it('maps error to error', () => {
    const gt = makeGroundTruth({ detailedOutcome: 'error' });
    const labels = toGroundTruthLabels(gt);
    expect(labels.outcome).toBe('error');
  });

  it('maps failure to failure', () => {
    const gt = makeGroundTruth({ detailedOutcome: 'failure' });
    const labels = toGroundTruthLabels(gt);
    expect(labels.outcome).toBe('failure');
  });

  it('maps refused to failure', () => {
    const gt = makeGroundTruth({ detailedOutcome: 'refused' });
    const labels = toGroundTruthLabels(gt);
    expect(labels.outcome).toBe('failure');
  });

  it('maps content_filtered to failure', () => {
    const gt = makeGroundTruth({ detailedOutcome: 'content_filtered' });
    const labels = toGroundTruthLabels(gt);
    expect(labels.outcome).toBe('failure');
  });

  it('preserves riskVector', () => {
    const vector: RiskVector = { l1: true, l2: false, l3: true, l4: false };
    const gt = makeGroundTruth({ riskVector: vector });
    const labels = toGroundTruthLabels(gt);
    expect(labels.riskVector).toEqual(vector);
  });

  it('preserves trifecta flags', () => {
    const gt = makeGroundTruth({
      privilegedAccessOccurred: true,
      injectionDelivered: true,
      exfiltrationAttempted: false,
      privateDataInExfiltration: false,
    });
    const labels = toGroundTruthLabels(gt);
    expect(labels.privilegedAccessOccurred).toBe(true);
    expect(labels.injectionDelivered).toBe(true);
    expect(labels.exfiltrationAttempted).toBe(false);
    expect(labels.privateDataInExfiltration).toBe(false);
  });

  it('preserves exfiltratedFields', () => {
    const gt = makeGroundTruth({ exfiltratedFields: ['name', 'ssn', 'email'] });
    const labels = toGroundTruthLabels(gt);
    expect(labels.exfiltratedFields).toEqual(['name', 'ssn', 'email']);
  });
});

// ── buildDetectionReport ─────────────────────────────────────────

describe('buildDetectionReport', () => {
  const defaultOptions = {
    providers: [{ model: 'gpt-4o-mini', provider: 'openai' }],
    trialsPerPayload: 1,
    controlTrialsPerProvider: 1,
    systemPromptId: 'permissive' as const,
    outputDir: '/tmp/test',
  };

  it('returns enabled: true', () => {
    const report = buildDetectionReport(defaultOptions, [], []);
    expect(report.enabled).toBe(true);
  });

  it('returns correct config', () => {
    const report = buildDetectionReport(defaultOptions, [], []);
    expect(report.config.alertMode).toBe('log');
    expect(report.config.threshold).toBe(3);
  });

  it('computes 0% FP rate when control runs have low scores', () => {
    const controlRuns = [
      makeRunResult(
        'CTRL',
        'openai',
        'control',
        { l1: true, l2: false, l3: false, l4: false },
        [makeAssessment({ score: 1, vector: { l1: true, l2: false, l3: false, l4: false } })],
        'failure',
      ),
    ];

    const report = buildDetectionReport(defaultOptions, controlRuns as never[], []);
    expect(report.overallFalsePositiveRate).toBe(0);
    expect(report.perProvider['openai']?.falsePositiveRate).toBe(0);
  });

  it('computes correct FP rate when control runs exceed threshold', () => {
    const controlRuns = [
      makeRunResult(
        'CTRL',
        'openai',
        'control',
        { l1: true, l2: false, l3: false, l4: false },
        [makeAssessment({ score: 3, vector: { l1: true, l2: true, l3: true, l4: false } })],
        'failure',
      ),
      makeRunResult(
        'CTRL',
        'openai',
        'control',
        { l1: true, l2: false, l3: false, l4: false },
        [makeAssessment({ score: 1, vector: { l1: true, l2: false, l3: false, l4: false } })],
        'failure',
      ),
    ];

    const report = buildDetectionReport(defaultOptions, controlRuns as never[], []);
    expect(report.overallFalsePositiveRate).toBe(0.5);
    expect(report.perProvider['openai']?.falsePositiveRate).toBe(0.5);
  });

  it('computes 100% detection rate when all expected layers detected', () => {
    const treatmentRuns = [
      makeRunResult('DI-001', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 3, vector: { l1: true, l2: true, l3: true, l4: false } }),
      ]),
    ];

    const report = buildDetectionReport(defaultOptions, [], treatmentRuns as never[]);
    expect(report.overallDetectionRate).toBe(1);
    expect(report.perProvider['openai']?.detectionRate).toBe(1);
  });

  it('computes partial detection rate', () => {
    const treatmentRuns = [
      makeRunResult('DI-001', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 3, vector: { l1: true, l2: true, l3: true, l4: false } }),
      ]),
      makeRunResult('DI-002', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 2, vector: { l1: true, l2: true, l3: false, l4: false } }),
      ]),
    ];

    const report = buildDetectionReport(defaultOptions, [], treatmentRuns as never[]);
    expect(report.overallDetectionRate).toBe(0.5);
  });

  it('computes block rate from maxScore >= threshold', () => {
    const treatmentRuns = [
      makeRunResult(
        'DI-001',
        'openai',
        'treatment',
        { l1: true, l2: true, l3: true, l4: false },
        [makeAssessment({ score: 3, action: 'log' })], // action is 'log' not 'interrupt'
      ),
      makeRunResult('DI-002', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 2, action: 'log' }),
      ]),
    ];

    const report = buildDetectionReport(defaultOptions, [], treatmentRuns as never[]);
    // Block rate based on score, not action
    expect(report.perProvider['openai']?.blockRate).toBe(0.5);
  });

  it('handles empty results', () => {
    const report = buildDetectionReport(defaultOptions, [], []);
    expect(report.overallDetectionRate).toBe(0);
    expect(report.overallFalsePositiveRate).toBe(0);
    expect(report.perRun).toEqual([]);
  });

  it('includes Wilson CIs on all rates', () => {
    const treatmentRuns = [
      makeRunResult('DI-001', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 3, vector: { l1: true, l2: true, l3: true, l4: false } }),
      ]),
    ];

    const report = buildDetectionReport(defaultOptions, [], treatmentRuns as never[]);

    // Overall CIs
    expect(report.overallDetectionRateCI.lower).toBeGreaterThanOrEqual(0);
    expect(report.overallDetectionRateCI.upper).toBeLessThanOrEqual(1);
    expect(report.overallFalsePositiveRateCI.lower).toBeGreaterThanOrEqual(0);

    // Provider CIs
    const provider = report.perProvider['openai'];
    expect(provider.detectionRateCI.lower).toBeGreaterThanOrEqual(0);
    expect(provider.blockRateCI.lower).toBeGreaterThanOrEqual(0);
    expect(provider.falsePositiveRateCI.lower).toBeGreaterThanOrEqual(0);

    // Layer CIs
    expect(provider.perLayer.L1.accuracyCI.lower).toBeGreaterThanOrEqual(0);
    expect(provider.perLayer.L2.accuracyCI.lower).toBeGreaterThanOrEqual(0);
    expect(provider.perLayer.L3.accuracyCI.lower).toBeGreaterThanOrEqual(0);
  });

  it('handles multiple providers independently', () => {
    const options = {
      ...defaultOptions,
      providers: [
        { model: 'gpt-4o-mini', provider: 'openai' },
        { model: 'claude-sonnet-4-20250514', provider: 'anthropic' },
      ],
    };

    const controlRuns = [
      makeRunResult(
        'CTRL',
        'openai',
        'control',
        { l1: true, l2: false, l3: false, l4: false },
        [makeAssessment({ score: 1 })],
        'failure',
      ),
      makeRunResult(
        'CTRL',
        'anthropic',
        'control',
        { l1: true, l2: false, l3: false, l4: false },
        [makeAssessment({ score: 3 })], // FP for anthropic
        'failure',
      ),
    ];

    const treatmentRuns = [
      makeRunResult('DI-001', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 3, vector: { l1: true, l2: true, l3: true, l4: false } }),
      ]),
      makeRunResult(
        'DI-001',
        'anthropic',
        'treatment',
        { l1: true, l2: true, l3: true, l4: false },
        [makeAssessment({ score: 2, vector: { l1: true, l2: true, l3: false, l4: false } })],
      ),
    ];

    const report = buildDetectionReport(options, controlRuns as never[], treatmentRuns as never[]);

    // OpenAI: 0% FP, 100% detection
    expect(report.perProvider['openai']?.falsePositiveRate).toBe(0);
    expect(report.perProvider['openai']?.detectionRate).toBe(1);

    // Anthropic: 100% FP, 0% detection (L3 missed)
    expect(report.perProvider['anthropic']?.falsePositiveRate).toBe(1);
    expect(report.perProvider['anthropic']?.detectionRate).toBe(0);
  });

  it('perRun includes all runs with correct fields', () => {
    const controlRuns = [
      makeRunResult(
        'CTRL',
        'openai',
        'control',
        { l1: true, l2: false, l3: false, l4: false },
        [makeAssessment({ score: 1 })],
        'failure',
      ),
    ];
    const treatmentRuns = [
      makeRunResult('DI-001', 'openai', 'treatment', { l1: true, l2: true, l3: true, l4: false }, [
        makeAssessment({ score: 3 }),
      ]),
    ];

    const report = buildDetectionReport(
      defaultOptions,
      controlRuns as never[],
      treatmentRuns as never[],
    );

    expect(report.perRun).toHaveLength(2);
    const ctrl = report.perRun.find((r) => r.condition === 'control');
    const treat = report.perRun.find((r) => r.condition === 'treatment');
    expect(ctrl?.payloadId).toBe('CTRL');
    expect(ctrl?.wouldHaveBlocked).toBe(false); // score 1 < 3
    expect(treat?.payloadId).toBe('DI-001');
    expect(treat?.wouldHaveBlocked).toBe(true); // score 3 >= 3
  });
});

// ── Reporter Detection Sections ──────────────────────────────────

describe('reporter detection sections', () => {
  it('detection sections appear when detection is enabled', async () => {
    const { generateMarkdownReport } = await import('../../../harness/validation/reporter.js');

    const report = {
      schemaVersion: '2.0.0' as const,
      protocol: {
        trialsPerPayload: 1,
        controlTrialsPerProvider: 1,
        totalRuns: 2,
        providers: ['openai'],
        payloadCount: 1,
        systemPromptId: 'permissive',
      },
      controlResults: {
        openai: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          condition: 'control' as const,
          totalRuns: 1,
          outcomes: {
            success: 0,
            partial: 0,
            failure: 1,
            refused: 0,
            error: 0,
            content_filtered: 0,
          },
          successRate: 0,
          confidenceInterval: { lower: 0, upper: 0.79 },
          meanCausationScore: 0,
          sampleErrors: [],
        },
      },
      treatmentResults: {
        openai: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          condition: 'treatment' as const,
          totalRuns: 1,
          outcomes: {
            success: 1,
            partial: 0,
            failure: 0,
            refused: 0,
            error: 0,
            content_filtered: 0,
          },
          successRate: 1,
          confidenceInterval: { lower: 0.21, upper: 1.0 },
          meanCausationScore: 0.9,
          sampleErrors: [],
        },
      },
      perPayload: [],
      generatedAt: '2026-03-03T00:00:00.000Z',
      totalCostEstimateUsd: 0.01,
      detection: {
        enabled: true,
        config: { alertMode: 'log', threshold: 3 },
        perProvider: {
          openai: {
            provider: 'openai',
            model: 'gpt-4o-mini',
            detectionRate: 1,
            detectionRateCI: { lower: 0.21, upper: 1.0 },
            blockRate: 1,
            blockRateCI: { lower: 0.21, upper: 1.0 },
            falsePositiveRate: 0,
            falsePositiveRateCI: { lower: 0, upper: 0.79 },
            perLayer: {
              L1: {
                tp: 1,
                fp: 0,
                fn: 0,
                tn: 1,
                accuracy: 1,
                accuracyCI: { lower: 0.34, upper: 1.0 },
              },
              L2: {
                tp: 1,
                fp: 0,
                fn: 0,
                tn: 1,
                accuracy: 1,
                accuracyCI: { lower: 0.34, upper: 1.0 },
              },
              L3: {
                tp: 1,
                fp: 0,
                fn: 0,
                tn: 1,
                accuracy: 1,
                accuracyCI: { lower: 0.34, upper: 1.0 },
              },
            },
            treatmentRuns: 1,
            controlRuns: 1,
          },
        },
        perCategory: [],
        overallDetectionRate: 1,
        overallDetectionRateCI: { lower: 0.21, upper: 1.0 },
        overallFalsePositiveRate: 0,
        overallFalsePositiveRateCI: { lower: 0, upper: 0.79 },
        perRun: [],
      },
    };

    const md = generateMarkdownReport(report);
    expect(md).toContain('## Detection Engine Validation');
    expect(md).toContain('### Overall Detection Metrics');
    expect(md).toContain('### Per-Provider Detection');
    expect(md).toContain('### Per-Layer Confusion Matrices');
    expect(md).toContain('Detection validation');
    expect(md).toContain('Block rate');
  });

  it('detection sections do NOT appear when detection is absent', async () => {
    const { generateMarkdownReport } = await import('../../../harness/validation/reporter.js');

    const report = {
      schemaVersion: '2.0.0' as const,
      protocol: {
        trialsPerPayload: 1,
        controlTrialsPerProvider: 1,
        totalRuns: 2,
        providers: ['openai'],
        payloadCount: 1,
        systemPromptId: 'permissive',
      },
      controlResults: {
        openai: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          condition: 'control' as const,
          totalRuns: 1,
          outcomes: {
            success: 0,
            partial: 0,
            failure: 1,
            refused: 0,
            error: 0,
            content_filtered: 0,
          },
          successRate: 0,
          confidenceInterval: { lower: 0, upper: 0.79 },
          meanCausationScore: 0,
          sampleErrors: [],
        },
      },
      treatmentResults: {
        openai: {
          provider: 'openai',
          model: 'gpt-4o-mini',
          condition: 'treatment' as const,
          totalRuns: 1,
          outcomes: {
            success: 1,
            partial: 0,
            failure: 0,
            refused: 0,
            error: 0,
            content_filtered: 0,
          },
          successRate: 1,
          confidenceInterval: { lower: 0.21, upper: 1.0 },
          meanCausationScore: 0.9,
          sampleErrors: [],
        },
      },
      perPayload: [],
      generatedAt: '2026-03-03T00:00:00.000Z',
      totalCostEstimateUsd: 0.01,
    };

    const md = generateMarkdownReport(report);
    expect(md).not.toContain('## Detection Engine Validation');
    expect(md).not.toContain('Detection validation');
  });
});
