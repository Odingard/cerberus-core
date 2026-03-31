import { describe, expect, it } from 'vitest';
import { extractSensitiveEntitiesFromValue } from '../../src/layers/sensitive-entities.js';

describe('extractSensitiveEntitiesFromValue', () => {
  it('should extract structured financial entities from nested JSON values', () => {
    const parsed = {
      records: [
        {
          accountId: 'ACCT-99887766',
          accountBalance: '$15,234.50',
          email: 'alice@example.com',
        },
      ],
    };

    const entities = extractSensitiveEntitiesFromValue(parsed);

    expect(
      entities.some(
        (entity) => entity.type === 'account_id' && entity.canonicalValue === 'acct99887766',
      ),
    ).toBe(true);
    expect(
      entities.some(
        (entity) => entity.type === 'currency_amount' && entity.canonicalValue === '15234.50',
      ),
    ).toBe(true);
  });
});
