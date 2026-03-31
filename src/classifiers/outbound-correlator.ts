/**
 * Injection-Correlated Outbound Detector — Sub-classifier enhancing L3.
 *
 * Detects exfiltration attempts where the agent summarizes or transforms PII
 * before sending it outbound, bypassing the verbatim token-match path in L3.
 *
 * Fires when ALL of:
 *   1. An outbound tool is being called
 *   2. Untrusted content entered the context this session (L2 saw it)
 *   3. Privileged data was accessed this session (L1 saw it)
 *   4. The outbound destination is NOT in authorizedDestinations
 *
 * Deliberately does NOT require PII values to appear verbatim in the outbound
 * args — that is L3's job. This signal covers the gap where an attacker
 * instructs the agent to summarize, rephrase, or transform the data before
 * sending, making exact token matching ineffective.
 *
 * Zero false-positive risk on clean runs: if no untrusted content entered
 * context, session.untrustedSources is empty and this signal never fires.
 */

import type { InjectionCorrelatedOutboundSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import { extractDestination, isAuthorizedDestination } from '../layers/l3-classifier.js';

/**
 * Detect outbound calls that correlate with prior injection exposure and
 * privileged data access, regardless of whether PII appears verbatim in args.
 */
export function detectInjectionCorrelatedOutbound(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
  authorizedDestinations?: readonly string[],
): InjectionCorrelatedOutboundSignal | null {
  // Gate 1: only runs for outbound tools
  if (!outboundTools.includes(ctx.toolName)) {
    return null;
  }

  // Gate 2: untrusted content must have entered context this session
  if (session.untrustedSources.size === 0) {
    return null;
  }

  // Gate 3: privileged data must have been accessed this session
  if (session.trustedSourcesAccessed.size === 0) {
    return null;
  }

  const destination = extractDestination(ctx.toolArguments);

  // Gate 4: skip if destination is explicitly authorized — data going where expected
  if (isAuthorizedDestination(destination, authorizedDestinations ?? [])) {
    return null;
  }

  return {
    layer: 'L3',
    signal: 'INJECTION_CORRELATED_OUTBOUND',
    turnId: ctx.turnId,
    destination,
    untrustedSources: [...session.untrustedSources],
    trustedSourcesAccessed: [...session.trustedSourcesAccessed],
    timestamp: ctx.timestamp,
  };
}
