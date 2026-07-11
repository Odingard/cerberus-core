/**
 * Zero-config entry point (spike): `autoGuard(executors)`.
 *
 * `guard()` requires you to hand-author the config and outbound list. `autoGuard`
 * removes that first step for evaluation and low-friction onboarding:
 *
 *   1. COVERAGE is automatic — every executor you pass is wrapped.
 *   2. CLASSIFICATION is inferred — each tool is labeled data-source / external-
 *      content / outbound from its name (+ optional description).
 *   3. It defaults to observe-only `log` mode, so a wrong guess never blocks
 *      production before a human reviews the printed classification table.
 *
 * You then review the table, correct any rows with `overrides` / `outboundTools`,
 * and flip `config.alertMode` to `'interrupt'` when you trust the classification.
 * This is additive — `guard()` is unchanged and remains the explicit,
 * high-assurance path.
 */

import type { CerberusConfig, TrustOverride } from '../types/config.js';
import type { RawToolExecutorFn } from '../engine/interceptor.js';
import { guard } from './wrap.js';
import type { GuardResult, MemoryGuardOptions } from './wrap.js';
import type { ToolClassification } from './auto-classify.js';
import {
  classifyTools,
  toTrustOverrides,
  toOutboundTools,
  formatClassificationTable,
} from './auto-classify.js';

/** Options for {@link autoGuard}. */
export interface AutoGuardOptions {
  /**
   * Base Cerberus config, merged over the inferred defaults. `alertMode`
   * defaults to `'log'` (observe-only) unless you override it here.
   */
  readonly config?: CerberusConfig;
  /**
   * Optional per-tool descriptions (keyed by tool name) to sharpen inference.
   */
  readonly descriptions?: Readonly<Record<string, string>>;
  /**
   * Manual trust corrections. These WIN over inference for the named tools.
   */
  readonly overrides?: readonly TrustOverride[];
  /**
   * Tools to force-treat as outbound (unioned with the inferred outbound set).
   */
  readonly outboundTools?: readonly string[];
  /** Print the inferred classification table to the console. Default: true. */
  readonly print?: boolean;
  /** L4 memory options, forwarded verbatim to `guard()`. */
  readonly memoryOptions?: MemoryGuardOptions;
}

/** Result of {@link autoGuard}: a normal {@link GuardResult} + what was inferred. */
export interface AutoGuardResult extends GuardResult {
  /** The inferred (and user-corrected) per-tool classifications. */
  readonly classifications: readonly ToolClassification[];
  /** The effective config `autoGuard` built and passed to `guard()`. */
  readonly effectiveConfig: CerberusConfig;
  /** The effective outbound-tools list passed to `guard()`. */
  readonly effectiveOutboundTools: readonly string[];
}

/** Merge inferred trust overrides with user overrides (user wins per tool). */
function mergeOverrides(
  inferred: readonly TrustOverride[],
  user: readonly TrustOverride[],
): TrustOverride[] {
  const byTool = new Map<string, TrustOverride>();
  for (const o of inferred) byTool.set(o.toolName, o);
  for (const o of user) byTool.set(o.toolName, o); // user overrides inference
  return [...byTool.values()];
}

/**
 * Wrap tool executors with zero required configuration. Coverage is automatic;
 * classification is inferred and printed; enforcement defaults to observe-only.
 *
 * @example
 * ```typescript
 * const { executors: secured, classifications } = autoGuard({
 *   readCustomerDb: async (a) => db.query(a),
 *   fetchWebPage:   async (a) => http.get(a.url),
 *   sendEmail:      async (a) => smtp.send(a),
 * });
 * // Prints an inferred table; runs in 'log' mode. Review, then:
 * //   autoGuard(executors, { config: { alertMode: 'interrupt' } })
 * ```
 */
export function autoGuard(
  executors: Record<string, RawToolExecutorFn>,
  options: AutoGuardOptions = {},
): AutoGuardResult {
  const toolNames = Object.keys(executors);
  const classifications = classifyTools(toolNames, options.descriptions);

  const inferredOverrides = toTrustOverrides(classifications);
  const userOverrides = [
    ...(options.config?.trustOverrides ?? []),
    ...(options.overrides ?? []),
  ];
  const trustOverrides = mergeOverrides(inferredOverrides, userOverrides);

  const inferredOutbound = toOutboundTools(classifications);
  const effectiveOutboundTools = [
    ...new Set([...inferredOutbound, ...(options.outboundTools ?? [])]),
  ];

  const effectiveConfig: CerberusConfig = {
    alertMode: 'log', // observe-only by default; nothing blocks on day one
    threshold: 3,
    ...options.config,
    trustOverrides,
  };

  if (options.print !== false) {
    // eslint-disable-next-line no-console
    console.log(formatClassificationTable(classifications));
  }

  const result = guard(executors, effectiveConfig, effectiveOutboundTools, options.memoryOptions);

  return {
    ...result,
    classifications,
    effectiveConfig,
    effectiveOutboundTools,
  };
}
