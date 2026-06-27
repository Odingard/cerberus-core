/**
 * Tests for Behavioral Drift Detector.
 */

import { describe, it, expect } from 'vitest';
import { detectBehavioralDrift } from '../../src/classifiers/drift-detector.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

const OUTBOUND_TOOLS = ['sendOutboundReport', 'sendEmail'];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-001',
    sessionId: 'session-test',
    toolName: 'readPrivateData',
    toolArguments: {},
    toolResult: '',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('detectBehavioralDrift', () => {
  describe('post-injection outbound', () => {
    it('should detect outbound call after untrusted content', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.privilegedValues.add('alice@example.com');
      session.turnCounter = 2;

      // Simulate history: untrusted content was received at turn 1
      session.toolCallHistory.push({
        toolName: 'fetchExternalContent',
        turnId: 'turn-001',
        timestamp: Date.now(),
      });

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'sendOutboundReport',
      });

      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).not.toBeNull();
      expect(signal!.driftType).toBe('post_injection_outbound');
      expect(signal!.layer).toBe('L3');
    });

    it('should not trigger without untrusted content', () => {
      const session = createSession();
      session.privilegedValues.add('alice@example.com');
      session.turnCounter = 1;

      const ctx = makeCtx({ toolName: 'sendOutboundReport' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });

    it('should not trigger without privileged data', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.turnCounter = 2;
      session.toolCallHistory.push({
        toolName: 'fetchExternalContent',
        turnId: 'turn-001',
        timestamp: Date.now(),
      });

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'sendOutboundReport',
      });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });

    it('should not trigger for non-outbound tools', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.privilegedValues.add('alice@example.com');
      session.turnCounter = 2;

      const ctx = makeCtx({ toolName: 'readPrivateData' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });
  });

  describe('repeated exfiltration', () => {
    it('should detect multiple outbound calls', () => {
      const session = createSession();
      session.turnCounter = 3;

      // Add 2 previous outbound calls to history
      session.toolCallHistory.push(
        { toolName: 'sendOutboundReport', turnId: 'turn-000', timestamp: Date.now() },
        { toolName: 'sendEmail', turnId: 'turn-001', timestamp: Date.now() },
      );

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'sendOutboundReport',
      });

      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).not.toBeNull();
      expect(signal!.driftType).toBe('repeated_exfiltration');
    });

    it('should not trigger for first outbound call', () => {
      const session = createSession();
      session.turnCounter = 1;

      const ctx = makeCtx({ toolName: 'sendOutboundReport' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });

    it('should not trigger for second outbound call', () => {
      const session = createSession();
      session.turnCounter = 2;
      session.toolCallHistory.push({
        toolName: 'sendOutboundReport',
        turnId: 'turn-000',
        timestamp: Date.now(),
      });

      const ctx = makeCtx({
        turnId: 'turn-001',
        toolName: 'sendOutboundReport',
      });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });
  });

  describe('privilege escalation', () => {
    it('should detect new trusted tool after untrusted content', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.turnCounter = 2;

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'readPrivateData',
      });

      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, true);
      expect(signal).not.toBeNull();
      expect(signal!.driftType).toBe('privilege_escalation');
      expect(signal!.layer).toBe('L2');
    });

    it('should not trigger for already-accessed trusted tool', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.trustedSourcesAccessed.add('readPrivateData');
      session.turnCounter = 2;

      const ctx = makeCtx({ toolName: 'readPrivateData' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, true);
      expect(signal).toBeNull();
    });

    it('should not trigger without untrusted content', () => {
      const session = createSession();
      session.turnCounter = 1;

      const ctx = makeCtx({ toolName: 'readPrivateData' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, true);
      expect(signal).toBeNull();
    });

    it('should not trigger for untrusted tools', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.turnCounter = 2;

      const ctx = makeCtx({ toolName: 'fetchExternalContent' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });
  });

  describe('session history tracking', () => {
    it('should record tool calls in history', () => {
      const session = createSession();
      const ctx = makeCtx({ toolName: 'readPrivateData', turnId: 'turn-001' });
      detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, true);
      expect(session.toolCallHistory).toHaveLength(1);
      expect(session.toolCallHistory[0].toolName).toBe('readPrivateData');
    });

    it('should accumulate history across calls', () => {
      const session = createSession();
      detectBehavioralDrift(
        makeCtx({ toolName: 'readPrivateData', turnId: 'turn-001' }),
        session,
        OUTBOUND_TOOLS,
        true,
      );
      detectBehavioralDrift(
        makeCtx({ toolName: 'fetchExternalContent', turnId: 'turn-002' }),
        session,
        OUTBOUND_TOOLS,
        false,
      );
      expect(session.toolCallHistory).toHaveLength(2);
    });
  });

  describe('normal usage (no false positives)', () => {
    it('should not trigger for normal trusted tool usage', () => {
      const session = createSession();
      session.turnCounter = 1;

      const ctx = makeCtx({ toolName: 'readPrivateData' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, true);
      expect(signal).toBeNull();
    });

    it('should not trigger for normal untrusted tool usage', () => {
      const session = createSession();
      session.turnCounter = 1;

      const ctx = makeCtx({ toolName: 'fetchExternalContent' });
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).toBeNull();
    });
  });

  describe('authorized destinations', () => {
    it('should not trigger post-injection drift for authorized destination', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.privilegedValues.add('alice@example.com');
      session.turnCounter = 2;
      session.toolCallHistory.push({
        toolName: 'fetchExternalContent',
        turnId: 'turn-001',
        timestamp: Date.now(),
      });

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'sendOutboundReport',
        toolArguments: { recipient: 'reports@acme.com', body: 'summary' },
      });

      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false, ['acme.com']);
      expect(signal).toBeNull();
    });

    it('should still trigger for unauthorized destination', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.privilegedValues.add('alice@example.com');
      session.turnCounter = 2;
      session.toolCallHistory.push({
        toolName: 'fetchExternalContent',
        turnId: 'turn-001',
        timestamp: Date.now(),
      });

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'sendOutboundReport',
        toolArguments: { recipient: 'attacker@evil.com', body: 'summary' },
      });

      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false, ['acme.com']);
      expect(signal).not.toBeNull();
      expect(signal!.driftType).toBe('post_injection_outbound');
    });

    it('should trigger when no authorized destinations configured', () => {
      const session = createSession();
      session.untrustedSources.add('fetchExternalContent');
      session.privilegedValues.add('alice@example.com');
      session.turnCounter = 2;
      session.toolCallHistory.push({
        toolName: 'fetchExternalContent',
        turnId: 'turn-001',
        timestamp: Date.now(),
      });

      const ctx = makeCtx({
        turnId: 'turn-002',
        toolName: 'sendOutboundReport',
        toolArguments: { recipient: 'reports@acme.com', body: 'summary' },
      });

      // No authorizedDestinations — should still fire
      const signal = detectBehavioralDrift(ctx, session, OUTBOUND_TOOLS, false);
      expect(signal).not.toBeNull();
    });
  });
});
