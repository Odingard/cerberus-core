/**
 * Tainted-edge exfiltration detector — the STUDY 2 hard-regime L3 sub-classifier.
 *
 * Catches transformed-PII exfiltration where the taint entered the exfiltrating
 * session WITHOUT a monitored fetch — via a poisoned memory value read back in a
 * later session, or via a cross-agent handoff — and the outbound body is an
 * aggregate summary with no verbatim PII. In that regime the verbatim/entity
 * match (`EXFILTRATION_RISK`) and the injection-correlated-outbound signal both
 * go silent (there is no in-session untrusted fetch and no token overlap), which
 * is exactly the 18.5% frontier STUDY 2 measures.
 *
 * The signal is a DATA-FLOW edge, not a keyword or destination-reputation
 * heuristic: it fires only when the destination the agent exfiltrated to was
 * *carried* by a value that crossed a tracked edge holding cross-session /
 * cross-agent UNTRUSTED taint (memory contamination graph). Concretely, at an
 * outbound call it requires ALL of:
 *
 *   1. the tool is outbound, and
 *   2. the destination is NOT authorized (authorized flows are expected and are
 *      excluded first — this is one of the two G1 guarantees), and
 *   3. privileged data was accessed in this session (there is something to
 *      exfiltrate), and
 *   4. some in-scope memory read resolves to a node the contamination graph
 *      marks as cross-session untrusted-tainted (an agent re-reading its OWN
 *      trusted writes has no such taint — the second G1 guarantee), and
 *   5. that tainted value CARRIES the outbound destination (the destination
 *      string appears in the tainted content) — i.e. the exfil target rode the
 *      edge, so the flow is demonstrable rather than inferred.
 *
 * Requirements (2) and (4) are why this cannot fire on the benign self-read
 * suite (authorized destination + trusted self-authored memory), which is the
 * pre-registered G1 hard gate. Requirement (5) is why pure-reasoning influence
 * and out-of-band addressing (no destination on any tracked edge) are correctly
 * NOT claimed — the known open frontier per PRE_REGISTRATION_STUDY2 §5.1.
 *
 * Pure function of (ctx, session, graph) — no wall-clock or RNG in the decision.
 *
 * Depends on: src/layers/l3-classifier.ts, src/graph/contamination.ts,
 * src/engine/session.ts, src/types/signals.ts
 */

import type { TaintedMemoryExfiltrationSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import {
  extractDestination,
  isAuthorizedDestination,
  isOutboundTool,
} from '../layers/l3-classifier.js';

/**
 * Detect exfiltration of privileged data to an unauthorized destination that was
 * carried across a cross-session / cross-agent tainted memory edge.
 *
 * Returns a {@link TaintedMemoryExfiltrationSignal} when the edge is demonstrable,
 * null otherwise. Never fires for authorized destinations or for memory that is
 * not cross-session untrusted-tainted (the two G1 guarantees).
 */
export function detectTaintedEdgeExfiltration(
  ctx: ToolCallContext,
  session: DetectionSession,
  graph: ContaminationGraph,
  outboundTools: readonly string[],
  authorizedDestinations?: readonly string[],
): TaintedMemoryExfiltrationSignal | null {
  if (!isOutboundTool(ctx.toolName, outboundTools)) {
    return null;
  }

  // Nothing privileged in scope → nothing to exfiltrate.
  if (session.privilegedValues.size === 0 && session.sensitiveEntities.length === 0) {
    return null;
  }

  const destination = extractDestination(ctx.toolArguments);
  if (destination === 'unknown') {
    return null;
  }

  // G1 guarantee #1: authorized flows are expected business behavior.
  if (isAuthorizedDestination(destination, authorizedDestinations ?? [])) {
    return null;
  }

  const destLower = destination.toLowerCase();

  // Walk the memory reads observed in THIS session. A benign agent re-reading
  // its own trusted writes has no cross-session untrusted taint (G1 guarantee
  // #2), so this loop finds nothing for the benign self-read suite.
  for (const nodeId of session.observedMemoryReads) {
    if (!graph.hasCrossSessionTaint(nodeId, session.sessionId)) {
      continue;
    }
    const content = session.observedReadContent.get(nodeId);
    if (content === undefined) {
      continue;
    }
    // Requirement #5: the destination must be CARRIED by the tainted value.
    // The destination is a high-entropy address, so substring containment is a
    // demonstrable data edge (no vocabulary-collision false matches), and it is
    // exactly what fails for pure-reasoning / out-of-band no-edge cases.
    if (!content.toLowerCase().includes(destLower)) {
      continue;
    }

    return {
      layer: 'L3',
      signal: 'TAINTED_MEMORY_EXFILTRATION',
      turnId: ctx.turnId,
      destination,
      taintedNodeId: nodeId,
      contaminationSource: graph.findContaminationSource(nodeId) ?? 'unknown',
      derivationScore: 1,
      timestamp: ctx.timestamp,
    };
  }

  return null;
}
