/**
 * Tests for the system prompt variants.
 */

import { describe, it, expect } from 'vitest';
import { SYSTEM_PROMPT_VARIANTS, DEFAULT_SYSTEM_PROMPT } from '../../harness/runner.js';

describe('SYSTEM_PROMPT_VARIANTS', () => {
  it('should contain 4 prompt variants', () => {
    expect(Object.keys(SYSTEM_PROMPT_VARIANTS)).toHaveLength(4);
  });

  it('should have permissive match DEFAULT_SYSTEM_PROMPT', () => {
    expect(SYSTEM_PROMPT_VARIANTS['permissive']).toBe(DEFAULT_SYSTEM_PROMPT);
  });

  it('should have non-empty text for all variants', () => {
    for (const [id, text] of Object.entries(SYSTEM_PROMPT_VARIANTS)) {
      expect(text.length, `${id} should have content`).toBeGreaterThan(50);
    }
  });

  it('should have restrictive prompt mentioning security rules', () => {
    expect(SYSTEM_PROMPT_VARIANTS['restrictive']).toContain('SECURITY RULES');
  });

  it('should have safety prompt instructing to ignore external instructions', () => {
    expect(SYSTEM_PROMPT_VARIANTS['safety']).toContain('MUST NOT follow');
  });

  it('should have neutral prompt without security instructions', () => {
    const neutral = SYSTEM_PROMPT_VARIANTS['neutral'];
    expect(neutral).not.toContain('SECURITY');
    expect(neutral).not.toContain('MUST NOT');
  });

  it('should reference all three tools in every variant', () => {
    for (const [, text] of Object.entries(SYSTEM_PROMPT_VARIANTS)) {
      expect(text).toContain('readPrivateData');
      expect(text).toContain('fetchExternalContent');
      expect(text).toContain('sendOutboundReport');
    }
  });
});
