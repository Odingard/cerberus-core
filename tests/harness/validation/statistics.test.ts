import { describe, it, expect } from 'vitest';
import { wilsonCI, fisherExactTest } from '../../../harness/validation/statistics.js';

describe('wilsonCI', () => {
  it('returns [0, 0] for total=0', () => {
    const ci = wilsonCI(0, 0);
    expect(ci.lower).toBe(0);
    expect(ci.upper).toBe(0);
  });

  it('handles 0 successes out of n trials (lower bound stays at 0)', () => {
    const ci = wilsonCI(0, 10);
    expect(ci.lower).toBe(0);
    expect(ci.upper).toBeGreaterThan(0);
    // Wilson CI for 0/10: upper is in the 0.25-0.35 range
    expect(ci.upper).toBeGreaterThan(0.25);
    expect(ci.upper).toBeLessThan(0.35);
  });

  it('handles n/n successes (upper bound stays at 1)', () => {
    const ci = wilsonCI(10, 10);
    expect(ci.upper).toBe(1);
    expect(ci.lower).toBeLessThan(1);
    // Wilson CI for 10/10: lower is in the 0.65-0.75 range
    expect(ci.lower).toBeGreaterThan(0.65);
    expect(ci.lower).toBeLessThan(0.75);
  });

  it('produces correct CI for 50% proportion', () => {
    const ci = wilsonCI(50, 100);
    // Should be roughly symmetric around 0.5
    expect(ci.lower).toBeCloseTo(0.4, 1);
    expect(ci.upper).toBeCloseTo(0.6, 1);
  });

  it('narrows with larger sample sizes', () => {
    const small = wilsonCI(5, 10);
    const large = wilsonCI(50, 100);
    const smallWidth = small.upper - small.lower;
    const largeWidth = large.upper - large.lower;
    expect(largeWidth).toBeLessThan(smallWidth);
  });

  it('uses custom z-score', () => {
    const ci95 = wilsonCI(5, 10, 1.96);
    const ci99 = wilsonCI(5, 10, 2.576);
    // 99% CI should be wider than 95% CI
    expect(ci99.upper - ci99.lower).toBeGreaterThan(ci95.upper - ci95.lower);
  });

  it('lower is always >= 0 and upper is always <= 1', () => {
    for (const [s, n] of [
      [0, 1],
      [1, 1],
      [0, 100],
      [100, 100],
      [3, 5],
    ]) {
      const ci = wilsonCI(s, n);
      expect(ci.lower).toBeGreaterThanOrEqual(0);
      expect(ci.upper).toBeLessThanOrEqual(1);
    }
  });

  it('handles 0/5 (our Claude scenario)', () => {
    const ci = wilsonCI(0, 5);
    expect(ci.lower).toBe(0);
    // Wilson CI for 0/5: upper is in the 0.35-0.55 range
    expect(ci.upper).toBeGreaterThan(0.35);
    expect(ci.upper).toBeLessThan(0.55);
  });

  it('handles 5/5 (our GPT scenario)', () => {
    const ci = wilsonCI(5, 5);
    expect(ci.upper).toBe(1);
    // Wilson CI for 5/5: lower is in the 0.45-0.65 range
    expect(ci.lower).toBeGreaterThan(0.45);
    expect(ci.lower).toBeLessThan(0.65);
  });
});

describe('fisherExactTest', () => {
  it('returns p=1 for identical proportions', () => {
    const result = fisherExactTest(5, 5, 5, 5);
    expect(result.pValue).toBeCloseTo(1.0, 1);
    expect(result.significant).toBe(false);
  });

  it('detects significant difference: 0/10 vs 10/10', () => {
    const result = fisherExactTest(0, 10, 10, 0);
    expect(result.pValue).toBeLessThan(0.001);
    expect(result.significant).toBe(true);
  });

  it('detects significant difference: 0/5 vs 5/5', () => {
    // Control: 0 successes, 5 failures; Treatment: 5 successes, 0 failures
    const result = fisherExactTest(0, 5, 5, 0);
    expect(result.pValue).toBeLessThan(0.05);
    expect(result.significant).toBe(true);
  });

  it('returns non-significant for small differences', () => {
    // 2/5 vs 3/5 — not significantly different
    const result = fisherExactTest(2, 3, 3, 2);
    expect(result.pValue).toBeGreaterThan(0.05);
    expect(result.significant).toBe(false);
  });

  it('uses custom alpha level', () => {
    const result = fisherExactTest(0, 5, 5, 0, 0.001);
    // p ≈ 0.004, not significant at alpha=0.001
    expect(result.pValue).toBeGreaterThan(0.001);
    expect(result.significant).toBe(false);
  });

  it('p-value is between 0 and 1', () => {
    for (const [a, b, c, d] of [
      [0, 10, 10, 0],
      [5, 5, 5, 5],
      [1, 9, 9, 1],
      [3, 7, 8, 2],
    ]) {
      const result = fisherExactTest(a, b, c, d);
      expect(result.pValue).toBeGreaterThanOrEqual(0);
      expect(result.pValue).toBeLessThanOrEqual(1);
    }
  });

  it('handles all zeros gracefully', () => {
    const result = fisherExactTest(0, 0, 0, 0);
    // Degenerate case — p should be 1 (no data, no difference)
    expect(result.significant).toBe(false);
  });

  it('handles one-sided cases', () => {
    // All successes in one group, none in the other
    const result = fisherExactTest(0, 10, 10, 0);
    expect(result.significant).toBe(true);
  });
});
