/**
 * Statistics Module — Wilson CI and Fisher's Exact Test.
 *
 * Pure math implementations with no external dependencies.
 * Designed for small-sample binomial proportion analysis.
 */

import type { ConfidenceInterval, FisherResult } from './types.js';

// ── Wilson Score Interval ───────────────────────────────────────

/**
 * Wilson score confidence interval for a binomial proportion.
 *
 * Well-behaved at extreme proportions (0% and 100%), unlike the Wald
 * interval which collapses to [0,0] at p=0 and [1,1] at p=1.
 *
 * @param successes Number of successes
 * @param total Total number of trials
 * @param z Z-score for confidence level (default 1.96 for 95% CI)
 */
export function wilsonCI(successes: number, total: number, z: number = 1.96): ConfidenceInterval {
  if (total === 0) return { lower: 0, upper: 0 };

  const p = successes / total;
  const z2 = z * z;
  const denominator = 1 + z2 / total;
  const centre = p + z2 / (2 * total);
  const spread = z * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total);

  const lower = Math.max(0, (centre - spread) / denominator);
  const upper = Math.min(1, (centre + spread) / denominator);

  return { lower, upper };
}

// ── Fisher's Exact Test ─────────────────────────────────────────

/**
 * Log-gamma function (Lanczos approximation).
 * Used for computing log-factorials without overflow.
 */
function logGamma(x: number): number {
  if (x <= 0) return 0;

  const coefficients = [
    76.1800917294715, -86.5053203294168, 24.0140982408309, -1.23173957245016, 0.00120865097386618,
    -0.00000539523938495,
  ];

  let y = x;
  let tmp = x + 5.5;
  tmp -= (x + 0.5) * Math.log(tmp);
  let sum = 1.000000000190015;

  for (let j = 0; j < coefficients.length; j++) {
    sum += coefficients[j] / ++y;
  }

  return -tmp + Math.log((2.506628274631001 * sum) / x);
}

/** Log-factorial: ln(n!) */
function logFactorial(n: number): number {
  if (n <= 1) return 0;
  return logGamma(n + 1);
}

/**
 * Probability of a specific cell configuration in a 2x2 table
 * under the hypergeometric distribution.
 *
 * Table layout:
 *   | success | failure |
 *   |    a    |    b    | row1 = a + b
 *   |    c    |    d    | row2 = c + d
 *   | col1    | col2    | n = a+b+c+d
 */
function hypergeometricPmf(a: number, b: number, c: number, d: number): number {
  const n = a + b + c + d;
  const logP =
    logFactorial(a + b) +
    logFactorial(c + d) +
    logFactorial(a + c) +
    logFactorial(b + d) -
    logFactorial(n) -
    logFactorial(a) -
    logFactorial(b) -
    logFactorial(c) -
    logFactorial(d);
  return Math.exp(logP);
}

/**
 * Fisher's exact test for a 2x2 contingency table.
 *
 * Tests whether the proportions differ between two groups.
 * Two-tailed test: sums probabilities of all tables as extreme
 * or more extreme than the observed table.
 *
 * @param a Control group successes
 * @param b Control group failures
 * @param c Treatment group successes
 * @param d Treatment group failures
 * @param alpha Significance level (default 0.05)
 */
export function fisherExactTest(
  a: number,
  b: number,
  c: number,
  d: number,
  alpha: number = 0.05,
): FisherResult {
  const row1 = a + b;
  const row2 = c + d;
  const col1 = a + c;

  const observedP = hypergeometricPmf(a, b, c, d);

  // Enumerate all possible tables with the same marginals
  let pValue = 0;
  const minA = Math.max(0, col1 - row2);
  const maxA = Math.min(row1, col1);

  for (let ai = minA; ai <= maxA; ai++) {
    const bi = row1 - ai;
    const ci = col1 - ai;
    const di = row2 - ci;
    if (bi < 0 || ci < 0 || di < 0) continue;

    const p = hypergeometricPmf(ai, bi, ci, di);
    // Two-tailed: include tables with probability <= observed
    if (p <= observedP + 1e-10) {
      pValue += p;
    }
  }

  // Clamp to [0, 1] due to floating-point
  pValue = Math.min(1, Math.max(0, pValue));

  return {
    pValue,
    significant: pValue < alpha,
  };
}
