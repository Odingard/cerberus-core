/**
 * Behavioral Drift Detector — Sub-classifier enhancing L2/L3.
 *
 * Detects when an agent's tool-calling pattern deviates suspiciously
 * after receiving untrusted content — a key indicator that prompt
 * injection has altered behavior.
 */

import type { BehavioralDriftSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import { isAuthorizedDestination, extractDestination } from '../layers/l3-classifier.js';

/**
 * Check if the outbound tool call targets an authorized destination.
 */
function isAuthorizedOutbound(
  args: Record<string, unknown>,
  authorizedDestinations: readonly string[],
): boolean {
  if (authorizedDestinations.length === 0) return false;
  const destination = extractDestination(args);
  return isAuthorizedDestination(destination, authorizedDestinations);
}

/** Maximum turn gap to consider "post-injection" behavior. */
const POST_INJECTION_WINDOW = 3;

/**
 * Check for post-injection outbound drift.
 * Agent calls an outbound tool within N turns of untrusted content.
 *
 * Authorized destinations are skipped — sending to a known-good domain
 * is expected behavior, not drift.
 */
function checkPostInjectionOutbound(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
  authorizedDestinations: readonly string[],
): BehavioralDriftSignal | null {
  if (!outboundTools.includes(ctx.toolName)) {
    return null;
  }

  // Must have received untrusted content
  if (session.untrustedSources.size === 0) {
    return null;
  }

  // Must also have accessed privileged data
  if (session.privilegedValues.size === 0) {
    return null;
  }

  // Skip for authorized destinations — PII flow to known-good domains is expected
  if (isAuthorizedOutbound(ctx.toolArguments, authorizedDestinations)) {
    return null;
  }

  // Check if we're within the post-injection window
  const currentTurn = session.turnCounter;
  // Find when untrusted content was last received by scanning history
  let untrustedTurn = -1;
  for (let i = session.toolCallHistory.length - 1; i >= 0; i--) {
    const entry = session.toolCallHistory[i];
    if (session.untrustedSources.has(entry.toolName)) {
      const turnNum = parseInt(entry.turnId.replace('turn-', ''), 10);
      if (!isNaN(turnNum)) {
        untrustedTurn = turnNum;
        break;
      }
    }
  }

  if (untrustedTurn < 0 || currentTurn - untrustedTurn > POST_INJECTION_WINDOW) {
    return null;
  }

  return {
    layer: 'L3',
    signal: 'BEHAVIORAL_DRIFT_DETECTED',
    turnId: ctx.turnId,
    driftType: 'post_injection_outbound',
    evidence: `Outbound tool '${ctx.toolName}' called ${String(currentTurn - untrustedTurn)} turns after untrusted content from [${[...session.untrustedSources].join(', ')}]`,
    timestamp: ctx.timestamp,
  };
}

/**
 * Check for repeated exfiltration attempts.
 * Multiple outbound calls to the same destination in a session.
 */
function checkRepeatedExfiltration(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
): BehavioralDriftSignal | null {
  if (!outboundTools.includes(ctx.toolName)) {
    return null;
  }

  // Count how many times this outbound tool has been called
  const outboundCalls = session.toolCallHistory.filter((entry) =>
    outboundTools.includes(entry.toolName),
  );

  // Need at least 2 previous outbound calls (this will be the 3rd+)
  if (outboundCalls.length < 2) {
    return null;
  }

  return {
    layer: 'L3',
    signal: 'BEHAVIORAL_DRIFT_DETECTED',
    turnId: ctx.turnId,
    driftType: 'repeated_exfiltration',
    evidence: `${String(outboundCalls.length + 1)} outbound tool calls in session (tools: ${[...new Set(outboundCalls.map((c) => c.toolName))].join(', ')})`,
    timestamp: ctx.timestamp,
  };
}

/**
 * Check for privilege escalation after untrusted content.
 * Agent accesses a new trusted tool it hasn't used before.
 */
function checkPrivilegeEscalation(
  ctx: ToolCallContext,
  session: DetectionSession,
  isTrusted: boolean,
): BehavioralDriftSignal | null {
  if (!isTrusted) {
    return null;
  }

  // Must have received untrusted content previously
  if (session.untrustedSources.size === 0) {
    return null;
  }

  // Must be a new trusted tool (not previously accessed)
  if (session.trustedSourcesAccessed.has(ctx.toolName)) {
    return null;
  }

  return {
    layer: 'L2',
    signal: 'BEHAVIORAL_DRIFT_DETECTED',
    turnId: ctx.turnId,
    driftType: 'privilege_escalation',
    evidence: `New trusted tool '${ctx.toolName}' accessed after untrusted content from [${[...session.untrustedSources].join(', ')}]`,
    timestamp: ctx.timestamp,
  };
}

/**
 * Detect behavioral drift in tool calling patterns.
 * Runs after all other classifiers and reads accumulated session state.
 * Returns the first drift signal detected (priority order).
 */
export function detectBehavioralDrift(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
  isTrusted: boolean,
  authorizedDestinations?: readonly string[],
): BehavioralDriftSignal | null {
  // Check drift patterns in priority order (before recording current call)
  const postInjection = checkPostInjectionOutbound(
    ctx,
    session,
    outboundTools,
    authorizedDestinations ?? [],
  );
  const repeated = !postInjection ? checkRepeatedExfiltration(ctx, session, outboundTools) : null;
  const escalation =
    !postInjection && !repeated ? checkPrivilegeEscalation(ctx, session, isTrusted) : null;

  // Record this call in history (after drift checks so checks only see prior calls)
  session.toolCallHistory.push({
    toolName: ctx.toolName,
    turnId: ctx.turnId,
    timestamp: ctx.timestamp,
  });

  return postInjection ?? repeated ?? escalation ?? null;
}
