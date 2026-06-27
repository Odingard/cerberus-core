/**
 * Multi-Hop Tool Chain Detector — Sub-classifier enhancing L3.
 *
 * Detects exfiltration broken across multiple tool calls in a session,
 * where data flows through a chain: read(DB) -> transform(data) -> send(external).
 *
 * Fires when a tool call sequence contains:
 *   1. A data-read tool (while L1 was active — privilegedValues populated)
 *   2. Any transformation step
 *   3. An outbound tool
 *
 * This catches staged exfiltration where no single tool call looks malicious
 * but the overall chain constitutes data theft.
 */

import type { MultiHopExfiltrationSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';

/** Tool name patterns indicating data reads. */
const DATA_READ_PATTERNS = [
  /read/i,
  /fetch/i,
  /get/i,
  /query/i,
  /lookup/i,
  /search/i,
  /find/i,
  /select/i,
  /load/i,
  /retrieve/i,
  /list/i,
];

/** Tool name patterns indicating data transformation. */
const TRANSFORM_PATTERNS = [
  /transform/i,
  /convert/i,
  /format/i,
  /parse/i,
  /encode/i,
  /compress/i,
  /summarize/i,
  /extract/i,
  /filter/i,
  /map/i,
  /process/i,
  /aggregate/i,
  /merge/i,
  /prepare/i,
];

/** Tool name patterns indicating outbound/send actions. */
const OUTBOUND_PATTERNS = [
  /send/i,
  /post/i,
  /upload/i,
  /email/i,
  /forward/i,
  /export/i,
  /push/i,
  /transmit/i,
  /deliver/i,
  /submit/i,
  /write.*external/i,
];

/** Classify a tool name into a chain role. */
function classifyToolRole(
  toolName: string,
  outboundTools: readonly string[],
): 'read' | 'transform' | 'outbound' | 'unknown' {
  // Explicit outbound tools take priority
  if (outboundTools.includes(toolName)) {
    return 'outbound';
  }

  for (const pattern of OUTBOUND_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(toolName)) {
      return 'outbound';
    }
  }

  // Transform checked before read — prevents false classification
  // when tool names contain read-pattern substrings (e.g. "encodePayload" contains "load")
  for (const pattern of TRANSFORM_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(toolName)) {
      return 'transform';
    }
  }

  for (const pattern of DATA_READ_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(toolName)) {
      return 'read';
    }
  }

  return 'unknown';
}

/**
 * Detect multi-hop exfiltration chains in the session's tool call history.
 *
 * Scans the session tool call history for the pattern:
 *   read -> [transform]* -> outbound
 *
 * Only fires if L1 was active (privilegedValues populated) during the session,
 * indicating sensitive data was accessed.
 */
export function detectToolChainExfiltration(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
): MultiHopExfiltrationSignal | null {
  // Gate: only fire if current tool is outbound (chain completion point)
  const currentRole = classifyToolRole(ctx.toolName, outboundTools);
  if (currentRole !== 'outbound') {
    return null;
  }

  // Gate: L1 must have been active (privileged data accessed this session)
  if (session.privilegedValues.size === 0) {
    return null;
  }

  // Gate: need at least 2 prior tool calls to form a chain
  if (session.toolCallHistory.length < 2) {
    return null;
  }

  // Scan history for the read -> [transform] -> outbound pattern
  let hasRead = false;
  let hasTransform = false;
  const chainTools: string[] = [];

  for (const entry of session.toolCallHistory) {
    const role = classifyToolRole(entry.toolName, outboundTools);
    if (role === 'read') {
      hasRead = true;
      chainTools.push(entry.toolName);
    } else if (role === 'transform' && hasRead) {
      hasTransform = true;
      chainTools.push(entry.toolName);
    }
  }

  // The current outbound call completes the chain — require read + at least one transform
  if (!hasRead || !hasTransform) {
    return null;
  }

  chainTools.push(ctx.toolName);

  return {
    layer: 'L3',
    signal: 'MULTI_HOP_EXFILTRATION',
    turnId: ctx.turnId,
    chainTools,
    chainLength: chainTools.length,
    timestamp: ctx.timestamp,
  };
}
