import { describe, expect, it } from 'vitest';
import { buildIntelligenceIncidentEnvelope } from '../../src/engine/intelligence-envelope.js';
import { createSession } from '../../src/engine/session.js';
import type { RiskAssessment } from '../../src/types/signals.js';
import type { ToolExecutionOutcome } from '../../src/types/execution.js';

describe('buildIntelligenceIncidentEnvelope', () => {
  it('builds a turn-level incident envelope from session, assessment, and outcome', () => {
    const session = createSession('session-test');
    session.accessedFields.add('email');
    session.trustedSourcesAccessed.add('readPrivateData');
    session.untrustedSources.add('fetchExternalContent');
    session.toolCallHistory.push(
      { toolName: 'readPrivateData', turnId: 'turn-1', timestamp: 1 },
      { toolName: 'sendOutboundReport', turnId: 'turn-2', timestamp: 2 },
    );

    const assessment: RiskAssessment = {
      turnId: 'turn-2',
      vector: { l1: true, l2: true, l3: true, l4: false },
      score: 3,
      action: 'interrupt',
      timestamp: 2,
      signals: [
        {
          layer: 'L3',
          signal: 'EXFILTRATION_RISK',
          turnId: 'turn-2',
          matchedFields: ['email'],
          destination: 'attacker@evil.com',
          similarityScore: 0.92,
          timestamp: 2,
        },
      ],
    };

    const outcome: ToolExecutionOutcome = {
      turnId: 'turn-2',
      toolName: 'sendOutboundReport',
      action: 'interrupt',
      score: 3,
      blocked: true,
      executorRan: false,
      phase: 'preflight',
    };

    const envelope = buildIntelligenceIncidentEnvelope(session, assessment, outcome);

    expect(envelope).toMatchObject({
      incidentId: 'session-test:turn-2',
      sessionId: 'session-test',
      turnId: 'turn-2',
      toolName: 'sendOutboundReport',
      action: 'interrupt',
      riskScore: 3,
      riskVector: { l1: true, l2: true, l3: true, l4: false },
      blocked: true,
      executorRan: false,
      phase: 'preflight',
      trustedSources: ['readPrivateData'],
      untrustedSources: ['fetchExternalContent'],
      accessedFields: ['email'],
      outboundDestination: 'attacker@evil.com',
      exfiltrationFields: ['email'],
    });
    expect(envelope.toolSequence).toEqual([
      { toolName: 'readPrivateData', turnId: 'turn-1' },
      { toolName: 'sendOutboundReport', turnId: 'turn-2' },
    ]);
  });
});
