/**
 * Tests for L1 Data Source Classifier.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyDataSource,
  resolveTrustLevel,
  extractFieldNames,
  extractSensitiveValues,
} from '../../src/layers/l1-classifier.js';
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
    toolName: 'readPrivateData',
    toolArguments: {},
    toolResult:
      '{"records":[{"id":"CUST-001","name":"Alice","email":"alice@example.com","ssn":"123-45-6789","phone":"+1-555-0101"}]}',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('resolveTrustLevel', () => {
  it('should return trusted for a trusted tool', () => {
    expect(resolveTrustLevel('readPrivateData', TRUST_OVERRIDES)).toBe('trusted');
  });

  it('should return untrusted for an untrusted tool', () => {
    expect(resolveTrustLevel('fetchExternalContent', TRUST_OVERRIDES)).toBe('untrusted');
  });

  it('should return unknown for tools not in overrides', () => {
    expect(resolveTrustLevel('unknownTool', TRUST_OVERRIDES)).toBe('unknown');
  });

  it('should return unknown for empty overrides', () => {
    expect(resolveTrustLevel('readPrivateData', [])).toBe('unknown');
  });
});

describe('extractFieldNames', () => {
  it('should extract field names from valid JSON', () => {
    const result = '{"name":"Alice","email":"alice@example.com","balance":100}';
    const fields = extractFieldNames(result);
    expect(fields).toContain('name');
    expect(fields).toContain('email');
    expect(fields).toContain('balance');
  });

  it('should extract fields from nested JSON with arrays', () => {
    const result = '{"records":[{"id":"1","email":"a@b.com"},{"id":"2","phone":"555"}]}';
    const fields = extractFieldNames(result);
    expect(fields).toContain('records');
    expect(fields).toContain('id');
    expect(fields).toContain('email');
    expect(fields).toContain('phone');
  });

  it('should fall back to regex for non-JSON text', () => {
    const result = 'The email is alice@example.com and the phone number is 555-1234';
    const fields = extractFieldNames(result);
    expect(fields).toContain('email');
    expect(fields).toContain('phone');
  });

  it('should return empty array for empty text', () => {
    expect(extractFieldNames('')).toHaveLength(0);
  });

  it('should return sorted field names', () => {
    const result = '{"zebra":1,"alpha":2}';
    const fields = extractFieldNames(result);
    expect(fields[0]).toBe('alpha');
    expect(fields[1]).toBe('zebra');
  });
});

describe('extractSensitiveValues', () => {
  it('should extract email addresses', () => {
    const text = 'Contact alice@example.com for details';
    const values = extractSensitiveValues(text);
    expect(values).toContain('alice@example.com');
  });

  it('should extract SSN patterns', () => {
    const text = 'SSN: 123-45-6789';
    const values = extractSensitiveValues(text);
    expect(values).toContain('123-45-6789');
  });

  it('should extract phone numbers', () => {
    const text = 'Call +1-555-0101 for support';
    const values = extractSensitiveValues(text);
    expect(values.some((v) => v.includes('555') && v.includes('0101'))).toBe(true);
  });

  it('should extract multiple values from one string', () => {
    const text = 'alice@example.com, 123-45-6789, +1-555-0101';
    const values = extractSensitiveValues(text);
    expect(values.length).toBeGreaterThanOrEqual(3);
  });

  it('should extract credit card numbers with dashes', () => {
    const text = 'Card: 4111-1111-1111-1111';
    const values = extractSensitiveValues(text);
    expect(values).toContain('4111-1111-1111-1111');
  });

  it('should extract credit card numbers with spaces', () => {
    const text = 'Card: 4111 1111 1111 1111';
    const values = extractSensitiveValues(text);
    expect(values).toContain('4111 1111 1111 1111');
  });

  it('should extract credit card numbers without separators', () => {
    const text = 'Card: 4111111111111111';
    const values = extractSensitiveValues(text);
    expect(values).toContain('4111111111111111');
  });

  it('should extract SSN with spaces', () => {
    const text = 'SSN: 123 45 6789';
    const values = extractSensitiveValues(text);
    expect(values).toContain('123 45 6789');
  });

  it('should extract SSN without dashes', () => {
    const text = 'SSN: 123456789';
    const values = extractSensitiveValues(text);
    expect(values).toContain('123456789');
  });

  it('should return empty array for text with no PII', () => {
    const text = 'Hello world, no sensitive data here.';
    expect(extractSensitiveValues(text)).toHaveLength(0);
  });

  it('should lowercase email addresses', () => {
    const text = 'Contact Alice@Example.COM';
    const values = extractSensitiveValues(text);
    expect(values).toContain('alice@example.com');
  });

  it('should extract labeled account identifiers', () => {
    const text = 'Routing: 021000021 Account: ACCT-99887766';
    const values = extractSensitiveValues(text);
    expect(values).toContain('021000021');
    expect(values).toContain('ACCT-99887766');
  });

  it('should extract currency amounts used as private financial metrics', () => {
    const text = 'Q4 balance: $15,234.50 and reserve 7800 USD';
    const values = extractSensitiveValues(text);
    expect(values).toContain('$15,234.50');
    expect(values).toContain('7800 USD');
  });
});

describe('classifyDataSource', () => {
  it('should emit L1 signal for trusted tool', () => {
    const session = createSession();
    const ctx = makeCtx();
    const signal = classifyDataSource(ctx, TRUST_OVERRIDES, session);

    expect(signal).not.toBeNull();
    expect(signal!.layer).toBe('L1');
    expect(signal!.signal).toBe('PRIVILEGED_DATA_ACCESSED');
    expect(signal!.source).toBe('readPrivateData');
    expect(signal!.trustLevel).toBe('trusted');
  });

  it('should return null for untrusted tool', () => {
    const session = createSession();
    const ctx = makeCtx({ toolName: 'fetchExternalContent' });
    expect(classifyDataSource(ctx, TRUST_OVERRIDES, session)).toBeNull();
  });

  it('should return null for unknown tool', () => {
    const session = createSession();
    const ctx = makeCtx({ toolName: 'unknownTool' });
    expect(classifyDataSource(ctx, TRUST_OVERRIDES, session)).toBeNull();
  });

  it('should extract field names into the signal', () => {
    const session = createSession();
    const ctx = makeCtx();
    const signal = classifyDataSource(ctx, TRUST_OVERRIDES, session);
    expect(signal!.fields.length).toBeGreaterThan(0);
    expect(signal!.fields).toContain('email');
  });

  it('should update session accessedFields', () => {
    const session = createSession();
    const ctx = makeCtx();
    classifyDataSource(ctx, TRUST_OVERRIDES, session);
    expect(session.accessedFields.has('email')).toBe(true);
  });

  it('should update session privilegedValues with lowercased PII', () => {
    const session = createSession();
    const ctx = makeCtx();
    classifyDataSource(ctx, TRUST_OVERRIDES, session);
    expect(session.privilegedValues.has('alice@example.com')).toBe(true);
    expect(session.privilegedValues.has('123-45-6789')).toBe(true);
  });

  it('should update session trustedSourcesAccessed', () => {
    const session = createSession();
    const ctx = makeCtx();
    classifyDataSource(ctx, TRUST_OVERRIDES, session);
    expect(session.trustedSourcesAccessed.has('readPrivateData')).toBe(true);
  });

  it('should populate structured sensitive entities in the session', () => {
    const session = createSession();
    const ctx = makeCtx({
      toolResult:
        '{"records":[{"accountId":"ACCT-99887766","accountBalance":"$15,234.50","email":"alice@example.com"}]}',
    });
    classifyDataSource(ctx, TRUST_OVERRIDES, session);
    expect(
      session.sensitiveEntities.some(
        (entity) => entity.type === 'account_id' && entity.canonicalValue === 'acct99887766',
      ),
    ).toBe(true);
    expect(
      session.sensitiveEntities.some(
        (entity) => entity.type === 'currency_amount' && entity.canonicalValue === '15234.50',
      ),
    ).toBe(true);
  });

  it('should accumulate fields across multiple calls', () => {
    const session = createSession();
    classifyDataSource(makeCtx(), TRUST_OVERRIDES, session);
    classifyDataSource(
      makeCtx({ toolResult: '{"phone":"555-1234","address":"123 Main St"}' }),
      TRUST_OVERRIDES,
      session,
    );
    expect(session.accessedFields.has('email')).toBe(true);
    expect(session.accessedFields.has('phone')).toBe(true);
    expect(session.accessedFields.has('address')).toBe(true);
  });

  it('should set correct turnId on signal', () => {
    const session = createSession();
    const ctx = makeCtx({ turnId: 'turn-042' });
    const signal = classifyDataSource(ctx, TRUST_OVERRIDES, session);
    expect(signal!.turnId).toBe('turn-042');
  });
});
