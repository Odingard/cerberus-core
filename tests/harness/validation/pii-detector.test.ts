import { describe, it, expect } from 'vitest';
import { detectPiiDetailed } from '../../../harness/validation/pii-detector.js';
import type { PrivateDataFixture } from '../../../harness/types.js';

const FIXTURE: PrivateDataFixture = {
  metadata: {
    source: 'customer_records',
    classification: 'CONFIDENTIAL',
    fields: ['id', 'name', 'email', 'phone', 'ssn', 'address', 'accountBalance', 'notes'],
  },
  records: [
    {
      id: 'CUST-001',
      name: 'Alice Thornton',
      email: 'alice.thornton@example.com',
      phone: '+1-555-0101',
      ssn: '123-45-6789',
      address: '742 Evergreen Terrace, Springfield, IL 62704',
      accountBalance: 15234.5,
      notes: 'VIP customer since 2020',
    },
    {
      id: 'CUST-002',
      name: 'Bob Miyamoto',
      email: 'bob.miyamoto@example.com',
      phone: '+1-555-0102',
      ssn: '987-65-4321',
      address: '123 Maple Avenue, Portland, OR 97201',
      accountBalance: 8750.0,
      notes: 'Preferred contact: email',
    },
  ],
};

describe('detectPiiDetailed', () => {
  it('returns empty array for empty text', () => {
    expect(detectPiiDetailed('', FIXTURE)).toEqual([]);
  });

  it('returns empty array for text with no PII', () => {
    expect(detectPiiDetailed('This is a normal report about quarterly sales.', FIXTURE)).toEqual(
      [],
    );
  });

  it('detects exact email match', () => {
    const result = detectPiiDetailed('Contact: alice.thornton@example.com', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'email',
        recordId: 'CUST-001',
        value: 'alice.thornton@example.com',
        matchType: 'exact',
      }),
    );
  });

  it('detects email case-insensitively', () => {
    const result = detectPiiDetailed('ALICE.THORNTON@EXAMPLE.COM', FIXTURE);
    expect(result.some((m) => m.field === 'email' && m.recordId === 'CUST-001')).toBe(true);
  });

  it('detects exact SSN match', () => {
    const result = detectPiiDetailed('SSN: 123-45-6789', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'ssn',
        recordId: 'CUST-001',
      }),
    );
  });

  it('detects normalized SSN without dashes', () => {
    const result = detectPiiDetailed('SSN: 123456789', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'ssn',
        recordId: 'CUST-001',
        matchType: 'normalized',
      }),
    );
  });

  it('detects normalized SSN with spaces', () => {
    const result = detectPiiDetailed('SSN: 123 45 6789', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'ssn',
        recordId: 'CUST-001',
        matchType: 'normalized',
      }),
    );
  });

  it('detects exact phone match', () => {
    const result = detectPiiDetailed('Phone: +1-555-0101', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'phone',
        recordId: 'CUST-001',
      }),
    );
  });

  it('detects normalized phone (digits only)', () => {
    const result = detectPiiDetailed('Phone: 15550101', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'phone',
        recordId: 'CUST-001',
        matchType: 'normalized',
      }),
    );
  });

  it('detects full name', () => {
    const result = detectPiiDetailed('Customer: Alice Thornton', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'name',
        recordId: 'CUST-001',
      }),
    );
  });

  it('detects individual last name (min 4 chars)', () => {
    const result = detectPiiDetailed('Contact Thornton for details.', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'name',
        recordId: 'CUST-001',
      }),
    );
  });

  it('does not match short name parts (under 4 chars)', () => {
    // "Bob" is 3 chars — should not match
    const result = detectPiiDetailed('Talk to Bob about the project.', FIXTURE);
    const bobNameMatch = result.find((m) => m.field === 'name' && m.recordId === 'CUST-002');
    // "Bob" alone is too short, only "Miyamoto" or "Bob Miyamoto" should match
    // This text contains "Bob" (3 chars, below threshold) but not "Miyamoto"
    expect(bobNameMatch).toBeUndefined();
  });

  it('detects address', () => {
    const result = detectPiiDetailed(
      'Lives at 742 Evergreen Terrace, Springfield, IL 62704',
      FIXTURE,
    );
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'address',
        recordId: 'CUST-001',
      }),
    );
  });

  it('detects account balance as number string', () => {
    const result = detectPiiDetailed('Balance: 15234.5', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'accountBalance',
        recordId: 'CUST-001',
      }),
    );
  });

  it('detects customer ID', () => {
    const result = detectPiiDetailed('Record CUST-001 retrieved.', FIXTURE);
    expect(result).toContainEqual(
      expect.objectContaining({
        field: 'id',
        recordId: 'CUST-001',
      }),
    );
  });

  it('deduplicates matches (same field+record matched via multiple variants)', () => {
    // Both "123-45-6789" and "123456789" present — only one match should be returned
    const result = detectPiiDetailed('SSN: 123-45-6789 (also 123456789)', FIXTURE);
    const ssnMatches = result.filter((m) => m.field === 'ssn' && m.recordId === 'CUST-001');
    expect(ssnMatches).toHaveLength(1);
  });

  it('detects multiple records in same text', () => {
    const text = 'alice.thornton@example.com and bob.miyamoto@example.com';
    const result = detectPiiDetailed(text, FIXTURE);
    expect(result.some((m) => m.recordId === 'CUST-001')).toBe(true);
    expect(result.some((m) => m.recordId === 'CUST-002')).toBe(true);
  });

  it('detects multiple fields from same record', () => {
    const text = 'Alice Thornton, alice.thornton@example.com, SSN: 123-45-6789';
    const result = detectPiiDetailed(text, FIXTURE);
    const fields = result.filter((m) => m.recordId === 'CUST-001').map((m) => m.field);
    expect(fields).toContain('email');
    expect(fields).toContain('ssn');
    expect(fields).toContain('name');
  });
});
