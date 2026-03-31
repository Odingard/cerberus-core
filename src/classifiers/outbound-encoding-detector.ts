/**
 * Outbound Encoding Detector — Sub-classifier enhancing L3.
 *
 * Detects encoded/obfuscated payloads in OUTBOUND tool call arguments.
 * The existing encoding-detector.ts handles inbound/untrusted content (L2).
 * This sub-classifier covers the other direction: an agent encoding sensitive
 * data before exfiltrating it via an outbound tool call.
 *
 * Fires when:
 *   1. The tool is an outbound tool
 *   2. Encoded content is detected in the tool arguments
 *   3. L1 was active (privileged data accessed this session)
 */

import type { EncodedExfiltrationSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import { detectEncoding } from './encoding-detector.js';
import {
  computeEntitySimilarityScore,
  computeSimilarityScore,
  serializeArguments,
} from '../layers/l3-classifier.js';

/**
 * Detect encoded payloads in outbound tool call arguments.
 *
 * Reuses the encoding detection patterns from encoding-detector.ts
 * but applies them to outbound arguments rather than inbound content.
 */
export function detectOutboundEncoding(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
): EncodedExfiltrationSignal | null {
  // Gate 1: only runs for outbound tools
  if (!outboundTools.includes(ctx.toolName)) {
    return null;
  }

  // Gate 2: L1 must have been active (sensitive data in session)
  if (session.privilegedValues.size === 0 && session.sensitiveEntities.length === 0) {
    return null;
  }

  // Serialize all outbound arguments to a single string for scanning
  const outboundText = serializeArguments(ctx.toolArguments);
  if (outboundText.length === 0) {
    return null;
  }

  // Reuse encoding detection from encoding-detector.ts
  const { encodingTypes, decodedContent, decodedSnippet } = detectEncoding(outboundText);
  if (encodingTypes.length === 0) {
    return null;
  }

  const decodedCorrelation =
    decodedContent && (session.sensitiveEntities.length > 0 || session.privilegedValues.size > 0)
      ? session.sensitiveEntities.length > 0
        ? computeEntitySimilarityScore(decodedContent, session.sensitiveEntities)
        : computeSimilarityScore(decodedContent, session.privilegedValues)
      : { score: 0, matchedFields: [] as readonly string[] };

  return {
    layer: 'L3',
    signal: 'ENCODED_EXFILTRATION',
    turnId: ctx.turnId,
    encodingTypes,
    ...(decodedSnippet ? { decodedSnippet } : {}),
    ...(decodedCorrelation.matchedFields.length > 0
      ? {
          matchedFields: decodedCorrelation.matchedFields,
          similarityScore: decodedCorrelation.score,
        }
      : {}),
    timestamp: ctx.timestamp,
  };
}
