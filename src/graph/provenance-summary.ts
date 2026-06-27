/**
 * Provenance summary — type contracts (open tier).
 *
 * These are the bounded-size ancestor-sketch TYPE contracts only. The sketch
 * IMPLEMENTATION (the Bloom / accumulator construction, serialization, and the
 * `resolveSummaryParams` builder) is the licensed scale lever (§5.3f) and lives
 * in `@cerberus-ai/enterprise` (`graph/provenance-summary.ts`). The open tier
 * ships only the contracts so `LedgerOptions.summary` and `CerberusConfig`
 * remain type-complete without shipping the paid implementation.
 *
 * Depends on: (nothing — pure type contracts).
 */

/** Which bounded-size ancestor sketch a summary uses. */
export type ProvenanceSummaryKind = 'bloom' | 'accumulator';

/** Fully-resolved summary parameters (after defaulting/clamping). */
export interface ProvenanceSummaryParams {
  readonly kind: ProvenanceSummaryKind;
  /** Bit width m of the sketch (fixed per node — the storage bound). */
  readonly bits: number;
  /** Hash functions k per element. `accumulator` always resolves to 1. */
  readonly hashes: number;
}

/**
 * A bounded-size ancestor membership sketch. `add` inserts one ancestor id,
 * `unionInPlace` merges another summary with identical params (bitwise OR), and
 * `mayContain` tests membership (true = possibly an ancestor; false = certainly
 * NOT — the no-false-negative direction). `bytes` serializes the bit array for
 * persistence; `byteLength` is its on-the-wire size.
 */
export interface AncestorSummary {
  readonly params: ProvenanceSummaryParams;
  add: (id: string) => void;
  unionInPlace: (other: AncestorSummary) => void;
  mayContain: (id: string) => boolean;
  bytes: () => Uint8Array;
  readonly byteLength: number;
}
