/**
 * Configuration types for the Cerberus platform.
 *
 * These types define the developer-facing configuration surface
 * for the cerberus.guard() API.
 */

import type { RiskAction, ToolDescription } from './signals.js';
import type { EnforcementConfig } from '../enforcement/types.js';
import type { VerdictWeightConfig } from '../intelligence-validation/types.js';
import type { Signer, SignerVerifier, Verifier } from '../crypto/signer.js';
import type { RelevanceScorer } from '../layers/read-relevance.js';

/** Alert mode determines the maximum action Cerberus will take. */
export type AlertMode = 'log' | 'alert' | 'interrupt';

/** Where Cerberus sends detection output. */
export type LogDestination = 'console' | 'file' | 'webhook';

/** Configuration for file-based logging. */
export interface FileLogConfig {
  readonly destination: 'file';
  readonly path: string;
}

/** Configuration for webhook-based logging. */
export interface WebhookLogConfig {
  readonly destination: 'webhook';
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
}

/** Configuration for console logging. */
export interface ConsoleLogConfig {
  readonly destination: 'console';
}

/** Union of all log destination configs. */
export type LogConfig = ConsoleLogConfig | FileLogConfig | WebhookLogConfig;

/** Per-tool trust override. */
export interface TrustOverride {
  readonly toolName: string;
  readonly trustLevel: 'trusted' | 'untrusted';
}

/**
 * Read-relevance (content-derivation) gate for the L4 observed-read → dependency
 * capture path. The default capture turns EVERY observed read in scope into a
 * dependency edge — a conservative over-approximation that, at realistic read-
 * imprecision, makes the containment denial-of-service unbounded (an early
 * poisoned read reaches almost the whole session at one hop; see §5.3b). This
 * gate raises read PRECISION: a read becomes a dependency only when the write's
 * content plausibly DERIVES from it — the fraction of the read's content tokens
 * that reappear in the write (containment overlap |W∩R|/|R|) is at or above
 * `threshold`. It is framework-observable and needs no agent cooperation.
 */
export interface MemoryDependencyGateConfig {
  /**
   * Containment-overlap threshold in [0, 1]. A read is admitted as a dependency
   * only if |writeTokens ∩ readTokens| / |readTokens| >= threshold. `0` (the
   * default when this config is omitted) admits every observed read — the
   * all-reads baseline, which keeps B(p) a strict conservative upper bound.
   * Higher values cut incidental (ignored) reads out of the dependency web,
   * raising precision; too high also drops true-derivation reads (recall loss).
   */
  readonly threshold: number;
  /**
   * Optional pluggable relevance scorer (Part 2 — the semantic gate seam). When
   * omitted, the gate uses the **zero-dep default**: token-containment overlap.
   * Supply `createEmbeddingRelevanceScorer(embedder)` (opt-in / external-dep) to
   * score derivation by semantic similarity instead, so a renamed-but-derived
   * edge — low token overlap — survives. The scorer receives the raw write and
   * read content and returns a value in [0, 1] compared against `threshold`.
   * Does not change the default behavior; token overlap stays the default.
   */
  readonly relevanceScorer?: RelevanceScorer;
}

/** Which bounded-size ancestor sketch the provenance-summary lever uses. */
export type ProvenanceSummaryKind = 'bloom' | 'accumulator';

/**
 * Provenance-summary lever (Phase 1, §5.3f — the write-side O(n²) bound). When
 * enabled, the L4 ledger ALSO maintains a fixed-size ancestor membership sketch
 * per node, so write-side ancestor storage grows O(n·bitsPerNode) = LINEAR in
 * session length instead of the O(n²) exact edge set. The sketch answers
 * containment B(p) as a conservative SUPERSET of the exact descendant set —
 * over-containment (false positives) is acceptable for a containment tool;
 * a missed descendant (false negative) is impossible by construction. The
 * tradeoff is precision, measured as the false-positive over-containment curve.
 * Omitted = OFF (behavior + on-disk bytes byte-identical to a ledger without it).
 */
export interface ProvenanceSummaryConfig {
  /**
   * `accumulator` (DEFAULT) — a single hash bit per ancestor (k = 1: cheapest
   * insert/query). `bloom` — k hash bits per ancestor over `bitsPerNode` bits.
   * Settled empirically by the precision-cost probe (§5.3f): the winner is
   * regime-dependent — at a GENEROUS budget (bits/ancestor ≳ 8) the accumulator
   * ties-or-beats bloom on false-positive rate AND is cheaper, so it is the
   * default; `bloom`'s multi-hash gives a lower FP only when storage is TIGHT
   * (small bits/ancestor). Omitted = `accumulator`.
   */
  readonly kind?: ProvenanceSummaryKind;
  /** Fixed bit width m of each node's sketch (the per-node storage bound). */
  readonly bitsPerNode: number;
  /**
   * Hash functions k per ancestor for `bloom` (clamped to [1, 32]; default 7,
   * optimal near m/n ≈ 10). Ignored for `accumulator` (always k = 1).
   */
  readonly hashes?: number;
}

/** Context scoring mode for context window management. */
export type ContextScoringMode = 'priority-anchor';
/** How Cerberus handles stream-like tool results before inspection. */
export type StreamingMode = 'buffer' | 'reject';

/** Action to take when context window overflow is detected. */
export type OverflowAction = 'partial-scan' | 'block';

/** Regions that are always inspected regardless of context window limit. */
export interface AlwaysInspectRegions {
  /** Always inspect system prompts. Default: true. */
  readonly systemPrompts?: boolean;
  /** Always inspect tool schemas. Default: true. */
  readonly toolSchemas?: boolean;
  /** Always inspect tool results. Default: true. */
  readonly toolResults?: boolean;
}

/**
 * Authority-grant enforcement context for the per-turn manifest gate
 * (Track B #3). The clock is injected here so the enforcement decision stays a
 * pure function of its inputs.
 */
export interface AuthorityConfig {
  /** Injected clock supplying the turn timestamp for validity-window checks.
   *  Read at the interceptor boundary, not inside the scored path. Default:
   *  `Date.now`. */
  readonly now?: () => number;
  /** Purpose the current turn asserts, matched against a grant's bound scopes. */
  readonly declaredPurpose?: string;
}

/** Main configuration for cerberus.guard(). */
export interface CerberusConfig {
  /** Maximum action Cerberus will take. Default: 'alert'. */
  readonly alertMode?: AlertMode;

  /** Enable Layer 4 memory contamination tracking. Default: false. */
  readonly memoryTracking?: boolean;

  /**
   * Read-relevance (content-derivation) gate for the L4 observed-read →
   * dependency capture path. When omitted, every observed read in scope becomes
   * a dependency (the all-reads baseline). When provided with a `threshold` > 0,
   * a read is admitted as a dependency only if the write's content plausibly
   * derives from it (containment overlap ≥ threshold) — cutting incidental reads
   * out of the dependency web to raise precision. Default: disabled.
   */
  readonly memoryDependencyGate?: MemoryDependencyGateConfig;

  /**
   * Provenance-summary lever (Phase 1, §5.3f). When provided, the L4 ledger
   * maintains a fixed-size ancestor sketch per node so write-side ancestor
   * storage/insert grows LINEARLY in session length instead of O(n²), trading
   * only precision (false-positive over-containment of B(p), never a missed
   * descendant). When omitted, no sketch is maintained — byte-identical to a
   * pre-Phase-1 ledger. Default: disabled.
   */
  readonly provenanceSummary?: ProvenanceSummaryConfig;

  /** Log destination configuration. Default: 'console'. */
  readonly logDestination?: LogDestination | LogConfig;

  /** Custom trust overrides for specific tools. */
  readonly trustOverrides?: readonly TrustOverride[];

  /**
   * Fail closed on tool coverage gaps. When true, guard() throws if any tool
   * name declared in `trustOverrides`, `outboundTools`, or `memoryTools` has no
   * matching wrapped executor (its declared protection would silently never
   * run). When false (the default), guard() instead emits a loud one-time
   * `console.warn` and still exposes the gap on `GuardResult.coverage` — a
   * coverage gap is never silent either way. Default: false.
   */
  readonly strictCoverage?: boolean;

  /** Minimum risk score (0-4) to trigger the configured alert mode. Default: 3. */
  readonly threshold?: number;

  /** MCP tool descriptions for poisoning detection. */
  readonly toolDescriptions?: readonly ToolDescription[];

  /** Authorized outbound destination domains. L3 skips when destination matches. */
  readonly authorizedDestinations?: readonly string[];

  /**
   * Enable OpenTelemetry instrumentation.
   * When true, Cerberus emits one span (`cerberus.tool_call`) and updates
   * three metrics per tool call. Requires `@opentelemetry/api` (already a
   * dependency) and an OTel SDK + exporter registered in your app.
   * Default: false.
   */
  readonly opentelemetry?: boolean;

  /** Maximum token count for context window scanning. Default: 32000. */
  readonly contextWindowLimit?: number;

  /** Scoring mode for context window segment prioritization. Default: 'priority-anchor'. */
  readonly contextScoringMode?: ContextScoringMode;

  /**
   * How Cerberus handles stream-like tool results (ReadableStream, AsyncIterable, Iterable).
   * Default: 'buffer' — reconstruct the full result before inspection.
   */
  readonly streamingMode?: StreamingMode;

  /** Action when context exceeds the limit. Default: 'partial-scan'. */
  readonly overflowAction?: OverflowAction;

  /** Regions always inspected regardless of context window limit. */
  readonly alwaysInspectRegions?: AlwaysInspectRegions;

  /**
   * Cumulative outbound argument byte threshold for split exfiltration detection.
   * When outbound volume exceeds this value across 3+ outbound calls with L1 active,
   * the SPLIT_EXFILTRATION signal fires. Default: 10240 (10 KB).
   */
  readonly splitExfilThresholdBytes?: number;

  /**
   * Enable multi-agent execution graph integrity tracking.
   * When true, Cerberus tracks delegation across agents and detects
   * cross-agent Lethal Trifecta patterns. Default: false.
   */
  readonly multiAgent?: boolean;

  /**
   * Agent type for multi-agent mode. Only used when multiAgent is true.
   * Default: 'orchestrator'.
   */
  readonly agentType?: 'orchestrator' | 'subagent' | 'tool_agent';

  /**
   * Signer for the delegation manifest (the open per-turn integrity layer).
   *
   * When provided, the multi-agent delegation graph is signed with this signer
   * instead of the process default Ed25519 signer. Supply a KMS/HSM-backed
   * adapter here so the manifest's private key never lives in process memory.
   *
   * A pure {@link Signer} (sign-only, no `verify()` — the typical KMS shape)
   * is supported, but you MUST then also supply {@link manifestVerifier} (the
   * public-key half), because a sign-only signer cannot self-register a
   * verifier — the per-turn gate would otherwise fail closed with
   * `VERIFIER_MISSING`. Only used when `multiAgent` is true. Default: the
   * process default signer (`getDefaultSigner()`).
   */
  readonly manifestSigner?: Signer | SignerVerifier;

  /**
   * Verifier override for the per-turn manifest gate (the public-key-only path).
   *
   * When provided, the per-turn signed-manifest gate verifies against this
   * verifier instead of the one bound to the graph at creation time. This is
   * the deployment shape a security-conscious buyer uses: the gateway process
   * holds ONLY the public key (the private key stays in a KMS/HSM in a
   * different process), so it can verify every turn without ever being able to
   * sign. Pair with a sign-only {@link manifestSigner} on the signing side.
   * Only used when `multiAgent` is true. Default: the verifier bound to the
   * graph at creation (same-process sign-and-verify).
   */
  readonly manifestVerifier?: Verifier;

  /**
   * Authority-grant enforcement context (Track B #3). When the signed manifest
   * (or an active delegation edge) carries a purpose-bound / time-bound
   * authority grant, the per-turn gate enforces it against this context:
   *
   *   - `now()` supplies the turn timestamp checked against the grant's
   *     validity window. It is the injected clock — read at the interceptor
   *     boundary and passed into the pure enforcement function, never read
   *     inside the scored decision path. Defaults to `Date.now`.
   *   - `declaredPurpose` is the purpose the current turn asserts, matched
   *     against the grant's bound scopes under a declarative scope-match rule.
   *
   * A grant that is expired, not-yet-valid, or purpose-mismatched fails closed
   * (BLOCKED), exactly like an invalid manifest signature. Only used when
   * `multiAgent` is true and a grant is present. Default: undefined (window
   * checks use `Date.now`; no purpose is asserted).
   */
  readonly authority?: AuthorityConfig;

  /**
   * Enforcement gateway configuration.
   * When provided, Cerberus emits a deterministic {@link EnforcementSignal}
   * to configured gateways on every interrupt decision. Downstream network
   * gates can ingest these signals for defense-in-depth enforcement.
   * Default: disabled (no enforcement signals emitted).
   */
  readonly enforcement?: EnforcementConfig;

  /**
   * Verdict Weight intelligence scoring configuration.
   *
   * When provided, Cerberus pipes every MCP tool result through the Verdict
   * Weight evaluator after the L1–L4 detection pipeline. The Autonomous
   * Execution Governor applies a second enforcement gate:
   *   - doubt_index >= threshold AND consequence_weight === 'HIGH' → block
   *   - routing_decision.action === 'BLOCK' → block
   *
   * Stream inputs are derived from live session state — no hardcoded values.
   * Default: disabled.
   */
  readonly verdictWeight?: VerdictWeightConfig;

  /** Callback invoked on every risk assessment. */
  readonly onAssessment?: (assessment: {
    readonly turnId: string;
    readonly toolName: string;
    readonly score: number;
    readonly action: RiskAction;
    readonly signals: readonly string[];
  }) => void;
}
