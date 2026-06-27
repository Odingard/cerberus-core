/**
 * `@cerberus-ai/core/internal` — engine internals consumed by the licensed
 * `@cerberus-ai/enterprise` package.
 *
 * This is NOT a stable public API. It exists so the paid package can program
 * against the open engine across the package boundary (the durable ledger, the
 * proxy, the enforcement gateway, and the Verdict-Weight evaluator all build on
 * open primitives). External consumers should use the public `@cerberus-ai/core`
 * surface; these symbols may change without a major-version bump.
 *
 * It re-exports the full public surface plus the additional contracts and
 * internal helpers the paid implementations depend on:
 *   - the enforcement type contracts (impl is paid),
 *   - the Verdict-Weight protocol contracts + schemas (impl is paid),
 *   - the intelligence-analysis type contracts (impl is paid),
 *   - a small set of engine internals (config validation, trust resolution,
 *     the session/interceptor types).
 */

export * from './index.js';

// Enforcement-gateway type contracts (the dispatch/gateway impls are paid).
export * from './enforcement/types.js';

// Verdict-Weight protocol contracts + Zod schemas (the evaluator/governor are paid).
export * from './intelligence-validation/types.js';

// Intelligence-analysis type contracts (the analyzer impl is paid).
export type {
  IntelligenceAnalysis,
  KillChainStep,
  PolicyRecommendation,
  SimilarIncidentRef,
} from './types/intelligence.js';

// Engine internals.
export { validateCerberusConfig } from './engine/config-validation.js';
export { resolveTrustLevel } from './layers/l1-classifier.js';
export type { DetectionSession } from './engine/session.js';
export type { RawToolExecutorFn } from './engine/interceptor.js';
export type { TrustOverride } from './types/config.js';
