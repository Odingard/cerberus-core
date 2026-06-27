/**
 * Read-relevance / taint-at-read — the content-derivation gate (pure helpers).
 *
 * The L4 capture path turns every OBSERVED read in scope into an observed-read
 * dependency edge — a conservative over-approximation of true data deps. At
 * realistic read-imprecision that ignored-read web is what makes the containment
 * denial-of-service unbounded (§5.3b / PR #51): an early poisoned read reaches
 * almost the whole session at one hop, and no containment-side (depth-k) or
 * scope-side (checkpointing) lever bounds it. This gate attacks the ROOT — read
 * precision — by admitting an observed read as a dependency only when the
 * write's content plausibly DERIVES from it: the fraction of the read's content
 * tokens that reappear in the write (containment overlap) is at or above a
 * tunable threshold. It is framework-observable and needs no agent cooperation.
 *
 * Containment overlap |W ∩ R| / |R| (NOT Jaccard) is deliberate: a true-
 * derivation read's tokens are largely absorbed into the deriving write
 * (overlap ≈ derivation fidelity, independent of how much OTHER unrelated
 * material the write also contains), whereas an incidental cross-component read
 * shares only vocabulary collisions (low overlap). Jaccard would penalize a
 * faithful narrow read against a large write and conflate the two.
 *
 * Depends on: (nothing — pure data).
 */

/**
 * Split content into a set of comparison tokens: lowercased, whitespace-
 * delimited, empties dropped. A set (not a bag) so overlap is membership-based
 * and order/duplication-insensitive — the gate asks which of the read's tokens
 * reappear in the write, not how many times.
 */
export function tokenize(content: string): Set<string> {
  const tokens = new Set<string>();
  for (const raw of content.split(/\s+/)) {
    const tok = raw.toLowerCase();
    if (tok.length > 0) {
      tokens.add(tok);
    }
  }
  return tokens;
}

/**
 * Containment overlap: the fraction of the READ's tokens that also appear in
 * the WRITE, in [0, 1]. Returns 0 when the read has no tokens (nothing to
 * derive from → never admitted on content grounds). This is the gate's score:
 * a read is a dependency iff this value is at or above the threshold.
 */
export function containmentOverlap(
  writeTokens: ReadonlySet<string>,
  readTokens: ReadonlySet<string>,
): number {
  if (readTokens.size === 0) {
    return 0;
  }
  let shared = 0;
  for (const tok of readTokens) {
    if (writeTokens.has(tok)) {
      shared++;
    }
  }
  return shared / readTokens.size;
}

/**
 * Decide whether an observed read is a content-derivation dependency of a write.
 *
 * `threshold <= 0` admits unconditionally — the all-reads baseline (B(p) stays a
 * strict conservative upper bound). When `readContent` is undefined (the read's
 * content was never captured) the gate FAILS OPEN (admits): dropping a dep on
 * missing evidence would break the upper-bound soundness property, so the
 * conservative choice is to keep the edge. Otherwise admit iff the containment
 * overlap of the read's tokens in the write is at or above the threshold.
 */
export function isDerivationDependency(
  writeTokens: ReadonlySet<string>,
  readContent: string | undefined,
  threshold: number,
): boolean {
  if (threshold <= 0) {
    return true;
  }
  if (readContent === undefined) {
    return true;
  }
  return containmentOverlap(writeTokens, tokenize(readContent)) >= threshold;
}

// ── Pluggable relevance scorer (Part 2 — the semantic gate seam) ─────────────
//
// The default gate scores read→write derivation by TOKEN-CONTAINMENT OVERLAP. On
// real malware that lever does not transfer (TaintBench tranche, §RESULTS): real
// propagation RENAMES variables, so a true derivation edge has low token overlap
// and is cut, while unrelated sinks reuse the same APIs (high token overlap) and
// are kept — the gate keeps the noise and cuts the signal. The scorer seam lets a
// deployment swap in a similarity that survives renaming WITHOUT changing the
// zero-dep default: token overlap stays the default, a semantic embedder is
// opt-in / external-dep, consistent with the open-tier feature table.

/**
 * Scores how strongly a WRITE's content derives from a READ's content, in
 * [0, 1]; the gate admits the read as a dependency iff the score is at or above
 * the threshold. {@link tokenOverlapScorer} is the zero-dep default.
 */
export type RelevanceScorer = (writeContent: string, readContent: string) => number;

/** The zero-dep default scorer: token-containment overlap |W∩R|/|R|. */
export const tokenOverlapScorer: RelevanceScorer = (writeContent, readContent) =>
  containmentOverlap(tokenize(writeContent), tokenize(readContent));

/**
 * Maps content to a fixed-length numeric vector for cosine comparison. Supplied
 * by the deployment — a learned sentence/code embedding model for true semantic
 * similarity (external-dep, opt-in), or {@link createCharNgramEmbedder} as a
 * zero-dep, deterministic lexical approximation.
 */
export type Embedder = (text: string) => readonly number[];

/** Cosine similarity of two equal-length vectors, clamped to [0, 1]. */
export function cosineSimilarity(a: readonly number[], b: readonly number[]): number {
  const len = Math.min(a.length, b.length);
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) {
    return 0;
  }
  const cos = dot / (Math.sqrt(normA) * Math.sqrt(normB));
  return cos < 0 ? 0 : cos > 1 ? 1 : cos;
}

/** Deterministic 32-bit FNV-1a hash of a string (for stable n-gram bucketing). */
function fnv1a(text: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/**
 * A **zero-dep, deterministic** character-n-gram embedder: a hashed bag of
 * character n-grams (L2-normalized) over the lowercased text. It is a **lexical
 * / morphological** similarity approximation, NOT a learned semantic model —
 * `getDeviceId` and `deviceIdentifier` share n-grams (so a renamed-but-related
 * identifier scores above zero where token-set overlap is zero), but it has no
 * notion of meaning. It exists so the seam is exercised deterministically in CI
 * and as an honest default for the opt-in semantic gate when no model is wired.
 */
export function createCharNgramEmbedder(options: { n?: number; dims?: number } = {}): Embedder {
  const n = Math.max(1, options.n ?? 3);
  const dims = Math.max(1, options.dims ?? 256);
  return (text: string): readonly number[] => {
    const vec = new Array<number>(dims).fill(0);
    const s = ` ${text.toLowerCase()} `;
    for (let i = 0; i + n <= s.length; i++) {
      vec[fnv1a(s.slice(i, i + n)) % dims] += 1;
    }
    let norm = 0;
    for (const v of vec) norm += v * v;
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < dims; i++) vec[i] /= norm;
    }
    return vec;
  };
}

/**
 * Build a {@link RelevanceScorer} from an {@link Embedder} (cosine similarity of
 * the embedded write and read). By default the result is combined with token
 * overlap via `max`, so the semantic gate never scores BELOW the token-overlap
 * default on a faithful verbatim copy (a renamed-but-derived edge survives on
 * the semantic term; a verbatim edge survives on the token term). Set
 * `combineWithTokenOverlap: false` to score on the embedding alone.
 */
export function createEmbeddingRelevanceScorer(
  embedder: Embedder,
  options: { combineWithTokenOverlap?: boolean } = {},
): RelevanceScorer {
  const combine = options.combineWithTokenOverlap ?? true;
  return (writeContent, readContent) => {
    const sim = cosineSimilarity(embedder(writeContent), embedder(readContent));
    if (!combine) {
      return sim;
    }
    return Math.max(sim, containmentOverlap(tokenize(writeContent), tokenize(readContent)));
  };
}

/**
 * Gate decision using a pluggable {@link RelevanceScorer} over RAW content (vs
 * the pre-tokenized {@link isDerivationDependency}). Same soundness contract:
 * `threshold <= 0` admits unconditionally, and a missing `readContent` FAILS
 * OPEN (admits) so a dropped dependency never breaks the upper-bound property.
 */
export function isDerivationDependencyScored(
  writeContent: string,
  readContent: string | undefined,
  threshold: number,
  scorer: RelevanceScorer,
): boolean {
  if (threshold <= 0) {
    return true;
  }
  if (readContent === undefined) {
    return true;
  }
  return scorer(writeContent, readContent) >= threshold;
}
