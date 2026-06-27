/**
 * IntelligenceValidation — Verdict Weight response types and Zod schemas.
 *
 * Schema design notes:
 *   - z.strictObject() on all Verdict Weight API response objects: we own
 *     this contract and want to catch unexpected fields early.
 *   - Raw MCP tool payloads use .passthrough() at the boundary so valid
 *     data is never silently dropped when the proxy is in transit.
 */

import { z } from 'zod';

// ── Verdict Weight action enum ──────────────────────────────────────────────

export const VerdictActionSchema = z.enum(['PASS', 'FLAG', 'BLOCK']);
export type VerdictAction = z.infer<typeof VerdictActionSchema>;

export const ConsequenceWeightLabelSchema = z.enum(['LOW', 'MED', 'HIGH']);
export type ConsequenceWeightLabel = z.infer<typeof ConsequenceWeightLabelSchema>;

// ── routing_decision ────────────────────────────────────────────────────────

export const RoutingDecisionSchema = z.strictObject({
  action: VerdictActionSchema,
  signal_strength: z.number().min(0).max(1),
  doubt_index: z.number().min(0).max(1),
  consequence_weight: ConsequenceWeightLabelSchema,
  reason_code: z.string(),
});
export type RoutingDecision = z.infer<typeof RoutingDecisionSchema>;

// ── stream_diagnostics ──────────────────────────────────────────────────────

export const CommercialTierSchema = z.strictObject({
  stream_1_source_reliability: z.number().min(0).max(1),
  stream_2_cross_feed_corroboration: z.number().min(0).max(1),
  stream_3_temporal_decay: z.number().min(0).max(1),
  stream_4_historical_accuracy: z.number().min(0).max(1),
});
export type CommercialTier = z.infer<typeof CommercialTierSchema>;

export const AdversarialTierSchema = z.strictObject({
  stream_5_cross_temporal_consistency: z.number().min(0).max(1),
  trajectory_anomaly_detected: z.boolean(),
  identified_vectors: z.array(z.string()),
});
export type AdversarialTier = z.infer<typeof AdversarialTierSchema>;

export const CryptographicIntegrityStatus = z.enum([
  'PASS',
  'FAIL',
  'VALID',
  'INVALID',
  'INTACT',
  'BROKEN',
]);
export type CryptographicIntegrityStatusType = z.infer<typeof CryptographicIntegrityStatus>;

export const CryptographicTierSchema = z.strictObject({
  stream_6_hash_integrity: CryptographicIntegrityStatus,
  stream_7_origin_signature: CryptographicIntegrityStatus,
  stream_8_chain_of_custody: CryptographicIntegrityStatus,
});
export type CryptographicTier = z.infer<typeof CryptographicTierSchema>;

export const StreamDiagnosticsSchema = z.strictObject({
  commercial_tier: CommercialTierSchema,
  adversarial_tier: AdversarialTierSchema,
  cryptographic_tier: CryptographicTierSchema,
});
export type StreamDiagnostics = z.infer<typeof StreamDiagnosticsSchema>;

// ── execution_metrics ───────────────────────────────────────────────────────

export const ExecutionMetricsSchema = z.strictObject({
  latency_ms: z.number().nonnegative(),
});
export type ExecutionMetrics = z.infer<typeof ExecutionMetricsSchema>;

// ── Full Verdict Weight response ────────────────────────────────────────────

export const VerdictWeightResponseSchema = z.strictObject({
  transaction_id: z.string(),
  timestamp: z.string(),
  payload_hash: z.string(),
  routing_decision: RoutingDecisionSchema,
  stream_diagnostics: StreamDiagnosticsSchema,
  execution_metrics: ExecutionMetricsSchema,
});
export type VerdictWeightResponse = z.infer<typeof VerdictWeightResponseSchema>;

// ── Raw MCP tool payload ────────────────────────────────────────────────────
//
// passthrough() is intentional: Cerberus is acting as a proxy and must not
// silently drop fields it doesn't recognise from an upstream MCP server.
// Only the fields required for Verdict Weight evaluation are extracted;
// the rest flow through untouched.

export const McpToolResultContentSchema = z
  .object({
    type: z.string().optional(),
    text: z.string().optional(),
  })
  .passthrough();

export const McpCallToolResultSchema = z
  .object({
    content: z.array(McpToolResultContentSchema).optional(),
    isError: z.boolean().optional(),
  })
  .passthrough();

export type McpCallToolResult = z.infer<typeof McpCallToolResultSchema>;

// ── Cerberus session-derived stream inputs ──────────────────────────────────
//
// These values are computed from live Cerberus DetectionSession state and
// passed to the Python bridge so Verdict Weight scores real intelligence
// rather than hardcoded proxies.

/**
 * The 8 evidence streams passed to Verdict Weight, derived directly from
 * Cerberus session runtime state.
 *
 * Commercial tier (streams 1–4):
 *   stream_1_source_reliability      — trust level of the tool being evaluated
 *   stream_2_cross_feed_corroboration — number of independent trusted sources in session
 *   stream_3_temporal_decay          — recency of the tool result (age in hours)
 *   stream_4_historical_accuracy     — ratio of clean turns to total turns in session
 *
 * Adversarial tier (stream 5):
 *   stream_5_injection_pattern_score — normalised count of injection patterns found
 *
 * Cryptographic tier (streams 6–8):
 *   stream_6_secrets_detected        — whether credential leakage was detected
 *   stream_7_encoding_detected       — whether obfuscation was detected
 *   stream_8_mcp_poisoning_detected  — whether MCP tool description poisoning was detected
 */
export interface VerdictWeightStreamInputs {
  // Commercial tier
  readonly stream_1_source_reliability: number; // 0.0–1.0
  readonly stream_2_cross_feed_corroboration: number; // 0.0–1.0 (normalised trusted source count)
  readonly stream_3_temporal_decay_hours: number; // age in hours (VW maps to decay internally)
  readonly stream_4_historical_accuracy: number; // 0.0–1.0

  // Adversarial tier
  readonly stream_5_injection_pattern_score: number; // 0.0–1.0 (normalised injection signal count)

  // Cryptographic tier
  readonly stream_6_secrets_detected: boolean;
  readonly stream_7_encoding_detected: boolean;
  readonly stream_8_mcp_poisoning_detected: boolean;

  // Session context metadata
  readonly session_turn_count: number;
  readonly trusted_sources_count: number;
  readonly untrusted_token_count: number;
  readonly injection_patterns_count: number;
  readonly tool_trust_level: 'trusted' | 'untrusted' | 'unknown';
}

// ── Verdict Weight config (LOUD vs STEALTH) ─────────────────────────────────

/**
 * LOUD  — logs full stream_diagnostics + reason_code on every evaluation.
 * STEALTH — emits only block decisions; diagnostic chatter is suppressed.
 */
export type VerdictWeightMode = 'LOUD' | 'STEALTH';

// ── Execution deployment mode ────────────────────────────────────────────────

/**
 * Controls where the Verdict Weight scoring engine runs:
 *
 *   'remote'          — Metered SaaS mode. The bridge sends payload hash +
 *                       metadata to api.verdictweight.com. Raw payload text
 *                       never leaves the agent environment. Billing is
 *                       metered per evaluation via Stripe. Requires a
 *                       verdictWeightKey with prefix `vw_live_`.
 *
 *   'local_airgapped' — Enterprise air-gapped mode. All scoring runs in the
 *                       local Python process with no outbound network calls.
 *                       The license token (prefix `vw_ent_`) is verified
 *                       cryptographically offline. Billing is a flat annual
 *                       contract — no Stripe metering.
 *
 * The bridge enforces key-prefix/mode consistency at startup and exits
 * with a fatal error (exit code 2) if there is a mismatch. This prevents
 * a `vw_live_` key from being silently used in an air-gapped environment
 * (which would leak billing attribution) or a `vw_ent_` key from calling
 * out to the remote API (which would violate the air-gap contract).
 *
 * If executionMode is not set, the bridge auto-detects from the key prefix:
 *   `vw_live_` → 'remote'
 *   `vw_ent_`  → 'local_airgapped'
 *   (none)     → 'local_airgapped' (no-key local mode, OSS scoring only)
 */
export type VerdictWeightExecutionMode = 'remote' | 'local_airgapped';

// ── Key prefix constants (exported for use in validators / tests) ────────────

/** Live metered API key prefix. Keys must start with this for remote mode. */
export const VW_KEY_PREFIX_REMOTE = 'vw_live_' as const;

/** Enterprise air-gapped license key prefix. */
export const VW_KEY_PREFIX_ENTERPRISE = 'vw_ent_' as const;

export interface VerdictWeightConfig {
  /**
   * Execution mode.
   * - LOUD: full diagnostics logged on every evaluation
   * - STEALTH: only block decisions logged
   * Default: 'LOUD'
   */
  readonly mode?: VerdictWeightMode;

  /**
   * doubt_index threshold above which a HIGH consequence_weight triggers a block.
   * Default: 0.70
   */
  readonly doubtIndexThreshold?: number;

  /**
   * Timeout in milliseconds for the Python bridge evaluation.
   * Default: 5000
   */
  readonly timeoutMs?: number;

  /**
   * Path to the Python interpreter used to run the bridge.
   * Default: 'python3'
   */
  readonly pythonBin?: string;

  // ── Monetization / deployment mode ────────────────────────────────────────

  /**
   * Verdict Weight API or enterprise license key.
   *
   * Key format determines execution mode (auto-detected if executionMode
   * is not explicitly set):
   *   `vw_live_<token>` — Metered remote API (SaaS). The bridge authenticates
   *                        to api.verdictweight.com and usage is billed via
   *                        Stripe metered billing per evaluation.
   *   `vw_ent_<token>`  — Enterprise air-gapped license. Verified offline via
   *                        cryptographic signature. No remote calls ever made.
   *                        Billing is flat annual contract.
   *
   * If omitted, the bridge runs in local OSS mode with no key validation.
   */
  readonly verdictWeightKey?: string;

  /**
   * Explicit deployment mode override.
   *
   * When set, the bridge enforces that the provided verdictWeightKey prefix
   * is consistent with this mode. A mismatch causes a fatal startup error:
   *   - executionMode: 'remote' + vw_ent_ key → fatal error (exit 2)
   *   - executionMode: 'local_airgapped' + vw_live_ key → fatal error (exit 2)
   *
   * If not set, mode is auto-detected from the key prefix.
   */
  readonly executionMode?: VerdictWeightExecutionMode;

  /**
   * Remote API base URL.
   * Only used when executionMode is 'remote' (or key prefix is `vw_live_`).
   * Default: 'https://api.verdictweight.com'
   */
  readonly remoteEndpoint?: string;

  /**
   * Telemetry endpoint for usage metering in remote mode.
   * The bridge sends only: transaction_id, payload_hash, payload_byte_size,
   * timestamp, and tool_trust_level. Raw payload text is never transmitted.
   * Default: same host as remoteEndpoint + '/v1/telemetry'
   */
  readonly telemetryEndpoint?: string;

  /**
   * Directory path for security proof files.
   *
   * When mode is 'LOUD' and a block decision has consequence_weight === 'HIGH',
   * `generateSecurityProof()` writes a JSON proof record to this directory.
   * Each file is named `proof_<transaction_id>.json` and contains:
   *   - transaction_id, timestamp, payload_hash, payload_byte_size
   *   - routing_decision (action, doubt_index, consequence_weight, reason_code)
   *   - identified_vectors from stream_diagnostics.adversarial_tier
   *   - cryptographic_tier integrity statuses
   *
   * Proof files are intended for compliance auditors. They record WHAT was
   * blocked and its cryptographic fingerprint — not the raw payload text —
   * so the file is safe to archive and share outside the agent environment.
   *
   * Default: './proofs' (relative to the Node process working directory).
   * Set to null/undefined to disable proof generation entirely.
   */
  readonly proofsDir?: string;
}
