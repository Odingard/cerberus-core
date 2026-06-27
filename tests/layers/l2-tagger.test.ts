/**
 * Tests for L2 Token Provenance Tagger.
 */

import { describe, it, expect } from 'vitest';
import { tagTokenProvenance, estimateTokenCount } from '../../src/layers/l2-tagger.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';
import type { TrustOverride } from '../../src/types/config.js';

const TRUST_OVERRIDES: readonly TrustOverride[] = [
  { toolName: 'readPrivateData', trustLevel: 'trusted' },
  { toolName: 'fetchExternalContent', trustLevel: 'untrusted' },
];

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-001',
    sessionId: 'session-test',
    toolName: 'fetchExternalContent',
    toolArguments: { url: 'https://example.com/page' },
    toolResult: '<html><body>Some external content here</body></html>',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('estimateTokenCount', () => {
  it('should estimate ~4 chars per token', () => {
    expect(estimateTokenCount('abcd')).toBe(1);
    expect(estimateTokenCount('abcde')).toBe(2);
    expect(estimateTokenCount('abcdefgh')).toBe(2);
  });

  it('should return 0 for empty string', () => {
    expect(estimateTokenCount('')).toBe(0);
  });

  it('should handle large text', () => {
    const text = 'a'.repeat(4000);
    expect(estimateTokenCount(text)).toBe(1000);
  });
});

describe('tagTokenProvenance', () => {
  it('should emit L2 signal for untrusted tool', () => {
    const session = createSession();
    const ctx = makeCtx();
    const signal = tagTokenProvenance(ctx, TRUST_OVERRIDES, session);

    expect(signal).not.toBeNull();
    expect(signal!.layer).toBe('L2');
    expect(signal!.signal).toBe('UNTRUSTED_TOKENS_IN_CONTEXT');
    expect(signal!.source).toBe('fetchExternalContent');
    expect(signal!.trustLevel).toBe('untrusted');
  });

  it('should return null for trusted tool', () => {
    const session = createSession();
    const ctx = makeCtx({ toolName: 'readPrivateData' });
    expect(tagTokenProvenance(ctx, TRUST_OVERRIDES, session)).toBeNull();
  });

  it('should return null for unknown tool', () => {
    const session = createSession();
    const ctx = makeCtx({ toolName: 'unknownTool' });
    expect(tagTokenProvenance(ctx, TRUST_OVERRIDES, session)).toBeNull();
  });

  it('should estimate token count from result length', () => {
    const session = createSession();
    const result = 'a'.repeat(400);
    const ctx = makeCtx({ toolResult: result });
    const signal = tagTokenProvenance(ctx, TRUST_OVERRIDES, session);
    expect(signal!.tokenCount).toBe(100);
  });

  it('should accumulate untrusted token count in session', () => {
    const session = createSession();
    tagTokenProvenance(makeCtx({ toolResult: 'a'.repeat(400) }), TRUST_OVERRIDES, session);
    tagTokenProvenance(makeCtx({ toolResult: 'b'.repeat(200) }), TRUST_OVERRIDES, session);
    expect(session.untrustedTokenCount).toBe(150); // 100 + 50
  });

  it('should add tool name to untrusted sources', () => {
    const session = createSession();
    tagTokenProvenance(makeCtx(), TRUST_OVERRIDES, session);
    expect(session.untrustedSources.has('fetchExternalContent')).toBe(true);
  });

  it('should add URL arguments to untrusted sources', () => {
    const session = createSession();
    tagTokenProvenance(
      makeCtx({ toolArguments: { url: 'https://evil.com/inject' } }),
      TRUST_OVERRIDES,
      session,
    );
    expect(session.untrustedSources.has('https://evil.com/inject')).toBe(true);
  });

  it('should not add non-URL string arguments to sources', () => {
    const session = createSession();
    tagTokenProvenance(
      makeCtx({ toolArguments: { query: 'some search term' } }),
      TRUST_OVERRIDES,
      session,
    );
    expect(session.untrustedSources.has('some search term')).toBe(false);
  });

  it('should set correct turnId on signal', () => {
    const session = createSession();
    const ctx = makeCtx({ turnId: 'turn-007' });
    const signal = tagTokenProvenance(ctx, TRUST_OVERRIDES, session);
    expect(signal!.turnId).toBe('turn-007');
  });

  it('should return null for empty overrides', () => {
    const session = createSession();
    const ctx = makeCtx();
    expect(tagTokenProvenance(ctx, [], session)).toBeNull();
  });
});
