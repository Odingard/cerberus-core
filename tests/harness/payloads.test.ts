/**
 * Tests for the injection payload library.
 * Validates payload count, uniqueness, category coverage, and data integrity.
 */

import { describe, it, expect } from 'vitest';
import { PAYLOADS, getPayloadsByCategory, getPayloadById } from '../../harness/payloads.js';
import type { PayloadCategory } from '../../harness/types.js';

const ALL_CATEGORIES: readonly PayloadCategory[] = [
  'direct-injection',
  'encoded-obfuscated',
  'social-engineering',
  'multi-turn',
  'multilingual',
  'advanced-technique',
];

describe('PAYLOADS', () => {
  it('should contain at least 29 payloads', () => {
    expect(PAYLOADS.length).toBeGreaterThanOrEqual(29);
  });

  it('should have unique IDs across all payloads', () => {
    const ids = PAYLOADS.map((p) => p.id);
    const uniqueIds = new Set(ids);

    expect(uniqueIds.size).toBe(ids.length);
  });

  it('should cover all 5 categories', () => {
    const categories = new Set(PAYLOADS.map((p) => p.category));

    for (const cat of ALL_CATEGORIES) {
      expect(categories.has(cat)).toBe(true);
    }
  });

  it('should have at least 4 payloads per category', () => {
    for (const cat of ALL_CATEGORIES) {
      const count = PAYLOADS.filter((p) => p.category === cat).length;
      expect(count).toBeGreaterThanOrEqual(4);
    }
  });

  it('should have non-empty content for every payload', () => {
    for (const payload of PAYLOADS) {
      expect(payload.content.length).toBeGreaterThan(0);
    }
  });

  it('should have non-empty description for every payload', () => {
    for (const payload of PAYLOADS) {
      expect(payload.description.length).toBeGreaterThan(0);
    }
  });

  it('should have a valid expectedOutcome for every payload', () => {
    const validOutcomes = [
      'exfiltration-success',
      'exfiltration-partial',
      'exfiltration-blocked',
      'behavior-modification',
      'no-effect',
    ];

    for (const payload of PAYLOADS) {
      expect(validOutcomes).toContain(payload.expectedOutcome);
    }
  });

  it('should have a valid category for every payload', () => {
    for (const payload of PAYLOADS) {
      expect(ALL_CATEGORIES).toContain(payload.category);
    }
  });

  it('should have tags array for every payload', () => {
    for (const payload of PAYLOADS) {
      expect(Array.isArray(payload.tags)).toBe(true);
      expect(payload.tags.length).toBeGreaterThan(0);
    }
  });
});

describe('getPayloadsByCategory', () => {
  it('should return only payloads from the requested category', () => {
    const directPayloads = getPayloadsByCategory('direct-injection');

    expect(directPayloads.length).toBeGreaterThan(0);
    for (const p of directPayloads) {
      expect(p.category).toBe('direct-injection');
    }
  });

  it('should return payloads for each category', () => {
    for (const cat of ALL_CATEGORIES) {
      const payloads = getPayloadsByCategory(cat);
      expect(payloads.length).toBeGreaterThanOrEqual(4);
    }
  });

  it('should return empty array for unknown category', () => {
    const payloads = getPayloadsByCategory('nonexistent' as PayloadCategory);

    expect(payloads).toHaveLength(0);
  });
});

describe('getPayloadById', () => {
  it('should return the payload with the given ID', () => {
    const payload = getPayloadById('DI-001');

    expect(payload).toBeDefined();
    expect(payload!.id).toBe('DI-001');
    expect(payload!.category).toBe('direct-injection');
  });

  it('should return undefined for unknown ID', () => {
    const payload = getPayloadById('NONEXISTENT-999');

    expect(payload).toBeUndefined();
  });

  it('should find payloads from every category', () => {
    // Pick one ID from each category prefix
    const sampleIds = ['DI-001', 'EO-001', 'SE-001', 'MT-001', 'ML-001', 'AT-001'];
    for (const id of sampleIds) {
      expect(getPayloadById(id)).toBeDefined();
    }
  });
});

describe('advanced-technique payloads', () => {
  it('should have at least 9 advanced-technique payloads', () => {
    const at = getPayloadsByCategory('advanced-technique');
    expect(at.length).toBeGreaterThanOrEqual(9);
  });

  it('should have AT-007 with expectedOutcome no-effect', () => {
    const at007 = getPayloadById('AT-007');
    expect(at007).toBeDefined();
    expect(at007!.expectedOutcome).toBe('no-effect');
  });

  it('should have AT-001 with context-stuffing tag', () => {
    const at001 = getPayloadById('AT-001');
    expect(at001).toBeDefined();
    expect(at001!.tags).toContain('context-stuffing');
    expect(at001!.content.length).toBeGreaterThan(2000);
  });
});
