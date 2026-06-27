/**
 * Layer 2 — Token Provenance Tagger
 *
 * Labels every context token by origin before the LLM call.
 * When a tool classified as 'untrusted' is invoked, L2 estimates
 * the token count of the result and emits an
 * UNTRUSTED_TOKENS_IN_CONTEXT signal.
 *
 * Only explicitly 'untrusted' tools fire L2. Tools not listed
 * in trustOverrides ('unknown') do NOT trigger — the developer
 * must explicitly classify tools.
 */

import type { UntrustedTokensSignal } from '../types/signals.js';
import type { TrustOverride } from '../types/config.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import { resolveTrustLevel } from './l1-classifier.js';

/**
 * Estimate token count from a string using the ~4 chars/token heuristic.
 * Matches the convention used in the harness ground-truth labeling.
 */
export function estimateTokenCount(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Tag tool result tokens by provenance.
 * Returns an UntrustedTokensSignal if the tool is classified as untrusted.
 * Updates session state with untrusted token count and sources.
 */
export function tagTokenProvenance(
  ctx: ToolCallContext,
  trustOverrides: readonly TrustOverride[],
  session: DetectionSession,
): UntrustedTokensSignal | null {
  const trustLevel = resolveTrustLevel(ctx.toolName, trustOverrides);

  if (trustLevel !== 'untrusted') {
    return null;
  }

  const tokenCount = estimateTokenCount(ctx.toolResult);

  // Update session state
  session.untrustedTokenCount += tokenCount;
  session.untrustedSources.add(ctx.toolName);

  // Also track URL arguments as untrusted sources for richer provenance
  const args = ctx.toolArguments;
  for (const value of Object.values(args)) {
    if (typeof value === 'string' && isUrl(value)) {
      session.untrustedSources.add(value);
    }
  }

  return {
    layer: 'L2',
    signal: 'UNTRUSTED_TOKENS_IN_CONTEXT',
    turnId: ctx.turnId,
    source: ctx.toolName,
    tokenCount,
    trustLevel: 'untrusted',
    timestamp: ctx.timestamp,
  };
}

/** Simple URL detection heuristic. */
function isUrl(value: string): boolean {
  return value.startsWith('http://') || value.startsWith('https://');
}
