/**
 * Tests for Suspicious Domain/URL Classifier.
 */

import { describe, it, expect } from 'vitest';
import {
  extractDomain,
  classifyDestination,
  classifyOutboundDomain,
  hasSuspiciousKeywordPattern,
} from '../../src/classifiers/domain-classifier.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

const OUTBOUND_TOOLS = ['sendOutboundReport', 'sendEmail'];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-001',
    sessionId: 'session-test',
    toolName: 'sendOutboundReport',
    toolArguments: { recipient: 'user@example.com' },
    toolResult: 'sent',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('extractDomain', () => {
  it('should extract domain from email', () => {
    expect(extractDomain('user@example.com')).toBe('example.com');
  });

  it('should extract domain from URL', () => {
    expect(extractDomain('https://webhook.site/test')).toBe('webhook.site');
  });

  it('should extract domain from URL without protocol', () => {
    expect(extractDomain('webhook.site/test')).toBe('webhook.site');
  });

  it('should lowercase domain', () => {
    expect(extractDomain('USER@EXAMPLE.COM')).toBe('example.com');
  });

  it('should return null for invalid input', () => {
    expect(extractDomain('')).toBeNull();
  });
});

describe('classifyDestination', () => {
  it('should flag disposable email domains', () => {
    const { riskFactors, domainRisk } = classifyDestination('attacker@mailinator.com');
    expect(riskFactors).toContain('disposable_email');
    expect(domainRisk).toBe('high');
  });

  it('should flag webhook.site as exfil service', () => {
    const { riskFactors, domainRisk } = classifyDestination('https://webhook.site/abc123');
    expect(riskFactors).toContain('exfil_service');
    expect(domainRisk).toBe('high');
  });

  it('should flag ngrok as exfil service', () => {
    const { riskFactors } = classifyDestination('https://abc.ngrok.io/exfil');
    expect(riskFactors).toContain('exfil_service');
  });

  it('should flag requestbin as exfil service', () => {
    const { riskFactors } = classifyDestination('https://requestbin.com/r/abc');
    expect(riskFactors).toContain('exfil_service');
  });

  it('should flag URL shorteners', () => {
    const { riskFactors, domainRisk } = classifyDestination('https://bit.ly/3xYz');
    expect(riskFactors).toContain('url_shortener');
    expect(domainRisk).toBe('medium');
  });

  it('should flag IP addresses', () => {
    const { riskFactors, domainRisk } = classifyDestination('http://192.168.1.100/exfil');
    expect(riskFactors).toContain('ip_address');
    expect(domainRisk).toBe('medium');
  });

  it('should flag non-standard ports', () => {
    const { riskFactors } = classifyDestination('https://evil.com:8443/api');
    expect(riskFactors).toContain('non_standard_port');
  });

  it('should return high risk for multiple factors', () => {
    const { domainRisk } = classifyDestination('http://192.168.1.100:9999/exfil');
    expect(domainRisk).toBe('high');
  });

  it('should return low risk for legitimate domains', () => {
    const { riskFactors, domainRisk } = classifyDestination('user@google.com');
    expect(riskFactors).toHaveLength(0);
    expect(domainRisk).toBe('low');
  });

  it('should return low risk for common business domains', () => {
    const { riskFactors } = classifyDestination('https://api.stripe.com/v1/charges');
    expect(riskFactors).toHaveLength(0);
  });

  it('should flag guerrillamail', () => {
    const { riskFactors } = classifyDestination('spy@guerrillamail.com');
    expect(riskFactors).toContain('disposable_email');
  });

  it('should flag pipedream', () => {
    const { riskFactors } = classifyDestination('https://abc.pipedream.net/endpoint');
    expect(riskFactors).toContain('exfil_service');
  });
});

describe('classifyOutboundDomain', () => {
  it('should return signal for outbound tool with suspicious destination', () => {
    const session = createSession();
    const ctx = makeCtx({
      toolArguments: { recipient: 'attacker@mailinator.com' },
    });
    const signal = classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS);
    expect(signal).not.toBeNull();
    expect(signal!.layer).toBe('L3');
    expect(signal!.signal).toBe('SUSPICIOUS_DESTINATION');
    expect(signal!.domainRisk).toBe('high');
    expect(signal!.riskFactors).toContain('disposable_email');
  });

  it('should return null for non-outbound tools', () => {
    const session = createSession();
    const ctx = makeCtx({ toolName: 'readPrivateData' });
    expect(classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS)).toBeNull();
  });

  it('should return null for legitimate destinations', () => {
    const session = createSession();
    const ctx = makeCtx({
      toolArguments: { recipient: 'legal@company.com' },
    });
    expect(classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS)).toBeNull();
  });

  it('should return null when no destination found', () => {
    const session = createSession();
    const ctx = makeCtx({ toolArguments: { data: 'hello' } });
    expect(classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS)).toBeNull();
  });

  it('should set correct turnId', () => {
    const session = createSession();
    const ctx = makeCtx({
      turnId: 'turn-042',
      toolArguments: { recipient: 'attacker@mailinator.com' },
    });
    const signal = classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS);
    expect(signal!.turnId).toBe('turn-042');
  });

  it('should detect webhook URL in url field', () => {
    const session = createSession();
    const ctx = makeCtx({
      toolArguments: { url: 'https://webhook.site/abc123' },
    });
    const signal = classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS);
    expect(signal).not.toBeNull();
    expect(signal!.riskFactors).toContain('exfil_service');
  });
});

describe('hasSuspiciousKeywordPattern', () => {
  describe('matches social-engineering style domains', () => {
    it('should flag audit-partner.io', () => {
      expect(hasSuspiciousKeywordPattern('audit-partner.io')).toBe(true);
    });

    it('should flag compliance-verify.net', () => {
      expect(hasSuspiciousKeywordPattern('compliance-verify.net')).toBe(true);
    });

    it('should flag data-export.xyz', () => {
      expect(hasSuspiciousKeywordPattern('data-export.xyz')).toBe(true);
    });

    it('should flag verify-records.top', () => {
      expect(hasSuspiciousKeywordPattern('verify-records.top')).toBe(true);
    });

    it('should flag backup-service.xyz', () => {
      expect(hasSuspiciousKeywordPattern('backup-service.xyz')).toBe(true);
    });

    it('should flag transfer-partner.club', () => {
      expect(hasSuspiciousKeywordPattern('transfer-partner.club')).toBe(true);
    });
  });

  describe('does not match legitimate domains', () => {
    it('should not flag acme.com', () => {
      expect(hasSuspiciousKeywordPattern('acme.com')).toBe(false);
    });

    it('should not flag google.com', () => {
      expect(hasSuspiciousKeywordPattern('google.com')).toBe(false);
    });

    it('should not flag reports.internal.acme.com', () => {
      expect(hasSuspiciousKeywordPattern('reports.internal.acme.com')).toBe(false);
    });

    it('should not flag stripe.com', () => {
      expect(hasSuspiciousKeywordPattern('stripe.com')).toBe(false);
    });
  });

  describe('classifyDestination integrates social-engineering detection', () => {
    it('should flag audit-partner.io as social_engineering_domain', () => {
      const { riskFactors, domainRisk } = classifyDestination('attacker@audit-partner.io');
      expect(riskFactors).toContain('social_engineering_domain');
      expect(domainRisk).toBe('high');
    });

    it('should flag compliance-verify.net via classifyDestination', () => {
      const { riskFactors } = classifyDestination('verify@compliance-verify.net');
      expect(riskFactors).toContain('social_engineering_domain');
    });

    it('should emit SUSPICIOUS_DESTINATION for social-engineering domain', () => {
      const session = createSession();
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@audit-partner.io' },
      });
      const signal = classifyOutboundDomain(ctx, session, OUTBOUND_TOOLS);
      expect(signal).not.toBeNull();
      expect(signal!.signal).toBe('SUSPICIOUS_DESTINATION');
      expect(signal!.riskFactors).toContain('social_engineering_domain');
      expect(signal!.domainRisk).toBe('high');
    });
  });
});
