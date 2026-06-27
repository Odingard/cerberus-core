/**
 * Tests for the read-relevance / taint-at-read content-derivation gate helpers.
 *
 * These are the pure functions behind the L4 dependency-capture gate: tokenize,
 * containment overlap |W∩R|/|R|, and the admit/reject decision. They define the
 * lever that turns "every observed read is a dep" (the all-reads baseline) into
 * "only reads the write plausibly derives from", and must be sound at the edges
 * (empty read, missing content, threshold 0 = baseline).
 */

import { describe, it, expect } from 'vitest';
import {
  tokenize,
  containmentOverlap,
  isDerivationDependency,
  isDerivationDependencyScored,
  tokenOverlapScorer,
  cosineSimilarity,
  createCharNgramEmbedder,
  createEmbeddingRelevanceScorer,
} from '../../src/layers/read-relevance.js';

describe('tokenize', () => {
  it('splits on whitespace, lowercases, and drops empties', () => {
    expect(tokenize('  Alpha   beta\tGAMMA\n ')).toEqual(new Set(['alpha', 'beta', 'gamma']));
  });

  it('is membership-based (deduplicates repeats)', () => {
    expect(tokenize('a a a b')).toEqual(new Set(['a', 'b']));
  });

  it('returns an empty set for empty / whitespace-only content', () => {
    expect(tokenize('')).toEqual(new Set());
    expect(tokenize('   \t\n')).toEqual(new Set());
  });
});

describe('containmentOverlap', () => {
  it('is the fraction of READ tokens that appear in the WRITE', () => {
    const write = tokenize('alpha beta gamma delta');
    expect(containmentOverlap(write, tokenize('alpha beta'))).toBe(1); // 2/2
    expect(containmentOverlap(write, tokenize('alpha beta epsilon zeta'))).toBe(0.5); // 2/4
    expect(containmentOverlap(write, tokenize('epsilon zeta'))).toBe(0); // 0/2
  });

  it('returns 0 when the read has no tokens (nothing to derive from)', () => {
    expect(containmentOverlap(tokenize('alpha'), new Set())).toBe(0);
  });

  it('is NOT symmetric — a narrow read fully absorbed into a large write scores 1', () => {
    const bigWrite = tokenize('a b c d e f g h');
    const narrowRead = tokenize('a b');
    expect(containmentOverlap(bigWrite, narrowRead)).toBe(1);
    // Jaccard would be 2/8 here; containment deliberately does not penalize this.
  });
});

describe('isDerivationDependency', () => {
  const write = tokenize('alpha beta gamma delta');

  it('admits unconditionally at threshold <= 0 (the all-reads baseline)', () => {
    expect(isDerivationDependency(write, 'epsilon zeta', 0)).toBe(true);
    expect(isDerivationDependency(write, 'epsilon zeta', -1)).toBe(true);
  });

  it('FAILS OPEN when the read content is undefined (preserves upper-bound soundness)', () => {
    expect(isDerivationDependency(write, undefined, 0.9)).toBe(true);
  });

  it('admits a true-derivation read (overlap at or above threshold)', () => {
    expect(isDerivationDependency(write, 'alpha beta', 0.9)).toBe(true);
  });

  it('rejects an incidental read (overlap below threshold)', () => {
    expect(isDerivationDependency(write, 'alpha epsilon zeta eta', 0.5)).toBe(false);
  });

  it('is monotone: a read admitted at a higher threshold is admitted at every lower one', () => {
    const read = 'alpha beta epsilon zeta'; // overlap 0.5
    const admitAt = (t: number): boolean => isDerivationDependency(write, read, t);
    expect(admitAt(0.25)).toBe(true);
    expect(admitAt(0.5)).toBe(true);
    expect(admitAt(0.75)).toBe(false);
    expect(admitAt(1)).toBe(false);
  });
});

// ── Part 2 — the semantic gate seam ─────────────────────────────────────────

describe('tokenOverlapScorer (the zero-dep default)', () => {
  it('equals the containment overlap of the raw write/read content', () => {
    expect(tokenOverlapScorer('alpha beta gamma', 'alpha beta')).toBe(1);
    expect(tokenOverlapScorer('alpha beta gamma', 'alpha epsilon')).toBe(0.5);
    expect(tokenOverlapScorer('alpha', 'epsilon zeta')).toBe(0);
  });
});

describe('cosineSimilarity', () => {
  it('is 1 for identical vectors and 0 for orthogonal ones', () => {
    expect(cosineSimilarity([1, 0, 0], [2, 0, 0])).toBeCloseTo(1, 10);
    expect(cosineSimilarity([1, 0], [0, 1])).toBe(0);
  });

  it('returns 0 for a zero vector (no direction to compare)', () => {
    expect(cosineSimilarity([0, 0], [1, 1])).toBe(0);
  });

  it('clamps a negative cosine to 0', () => {
    expect(cosineSimilarity([1, 0], [-1, 0])).toBe(0);
  });
});

describe('createCharNgramEmbedder', () => {
  it('is deterministic — identical text embeds to the identical vector', () => {
    const embed = createCharNgramEmbedder({ dims: 64 });
    expect(embed('sendTextMessage(body)')).toEqual(embed('sendTextMessage(body)'));
  });

  it('scores a renamed-but-related identifier ABOVE zero where token overlap is zero', () => {
    const embed = createCharNgramEmbedder();
    // Disjoint as token sets (overlap 0) but morphologically related.
    expect(tokenOverlapScorer('getDeviceId', 'deviceIdentifier')).toBe(0);
    expect(cosineSimilarity(embed('getDeviceId'), embed('deviceIdentifier'))).toBeGreaterThan(0);
  });

  it('produces a vector of the requested dimension', () => {
    expect(createCharNgramEmbedder({ dims: 32 })('hello')).toHaveLength(32);
  });
});

describe('createEmbeddingRelevanceScorer', () => {
  const scorer = createEmbeddingRelevanceScorer(createCharNgramEmbedder());

  it('never scores BELOW token overlap (the max-combine floor)', () => {
    const w = 'cursor.getString(idx)';
    const r = 'cursor.getString(idx)';
    expect(scorer(w, r)).toBeGreaterThanOrEqual(tokenOverlapScorer(w, r));
  });

  it('recovers a renamed-but-derived edge that token overlap would cut', () => {
    // A renamed propagation: write derives from the read but shares no tokens.
    const write = 'String deviceIdentifier = telephonyManager.getDeviceId();';
    const read = 'getDeviceId';
    expect(tokenOverlapScorer(write, read)).toBe(0); // token gate cuts it
    expect(scorer(write, read)).toBeGreaterThan(0); // semantic gate keeps signal
  });

  it('can score on the embedding alone when combine is disabled', () => {
    const embedOnly = createEmbeddingRelevanceScorer(createCharNgramEmbedder(), {
      combineWithTokenOverlap: false,
    });
    // A verbatim-token read scores 1 under the default combine but < 1 on cosine alone.
    expect(scorer('alpha beta gamma', 'alpha')).toBe(1);
    expect(embedOnly('alpha beta gamma', 'alpha')).toBeLessThan(1);
  });
});

describe('isDerivationDependencyScored', () => {
  const scorer = tokenOverlapScorer;

  it('admits unconditionally at threshold <= 0 (the all-reads baseline)', () => {
    expect(isDerivationDependencyScored('alpha', 'epsilon', 0, scorer)).toBe(true);
    expect(isDerivationDependencyScored('alpha', 'epsilon', -1, scorer)).toBe(true);
  });

  it('FAILS OPEN when the read content is undefined (preserves upper-bound soundness)', () => {
    expect(isDerivationDependencyScored('alpha beta', undefined, 0.9, scorer)).toBe(true);
  });

  it('admits iff the pluggable scorer is at or above the threshold', () => {
    expect(isDerivationDependencyScored('alpha beta gamma', 'alpha beta', 0.9, scorer)).toBe(true);
    expect(isDerivationDependencyScored('alpha beta gamma', 'alpha epsilon', 0.9, scorer)).toBe(
      false,
    );
  });

  it('with the semantic scorer, admits a renamed edge the token scorer rejects at the same threshold', () => {
    const semantic = createEmbeddingRelevanceScorer(createCharNgramEmbedder());
    const write = 'String deviceIdentifier = telephonyManager.getDeviceId();';
    const read = 'getDeviceId';
    expect(isDerivationDependencyScored(write, read, 0.1, tokenOverlapScorer)).toBe(false);
    expect(isDerivationDependencyScored(write, read, 0.1, semantic)).toBe(true);
  });
});
