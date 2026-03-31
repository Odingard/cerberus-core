/**
 * Split Exfiltration Detector — Sub-classifier enhancing L3.
 *
 * Detects data exfiltration split across multiple outbound tool calls.
 * Attackers may chunk sensitive data into small pieces sent via separate
 * calls to avoid triggering single-call detection thresholds.
 *
 * Fires when:
 *   1. Cumulative outbound volume exceeds a configurable threshold (default 10KB)
 *   2. At least 3 outbound calls have been made
 *   3. L1 was active (privileged data accessed this session)
 *
 * Also detects repeated calls to the same outbound tool with sequential
 * data patterns (e.g., page=1, page=2, offset=0, offset=100).
 */

import type { SplitExfiltrationSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import { serializeArguments } from '../layers/l3-classifier.js';

/** Default threshold in bytes for cumulative outbound volume. */
const DEFAULT_SPLIT_EXFIL_THRESHOLD_BYTES = 10240;

/** Minimum number of outbound calls to trigger volume-based detection. */
const MIN_OUTBOUND_CALLS = 3;

/** Pattern for sequential/incrementing numeric values in arguments. */
const SEQUENTIAL_PATTERNS = [
  /page/i,
  /offset/i,
  /chunk/i,
  /part/i,
  /segment/i,
  /batch/i,
  /index/i,
  /seq/i,
  /sequence/i,
  /block/i,
];

/** Track outbound call metadata within the session for split detection. */
interface OutboundCallRecord {
  readonly toolName: string;
  readonly byteSize: number;
  readonly numericArgs: readonly number[];
  readonly turnId: string;
}

/**
 * Extract numeric argument values that may indicate sequential data patterns.
 */
function extractSequentialIndicators(args: Record<string, unknown>): number[] {
  const numerics: number[] = [];

  for (const [key, value] of Object.entries(args)) {
    if (typeof value !== 'number') continue;

    for (const pattern of SEQUENTIAL_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(key)) {
        numerics.push(value);
        break;
      }
    }
  }

  return numerics;
}

/**
 * Check if numeric values across calls form a sequential pattern.
 */
function hasSequentialPattern(records: readonly OutboundCallRecord[]): boolean {
  if (records.length < 2) return false;

  // Group by tool name
  const byTool = new Map<string, number[]>();
  for (const rec of records) {
    for (const num of rec.numericArgs) {
      const existing = byTool.get(rec.toolName);
      if (existing) {
        existing.push(num);
      } else {
        byTool.set(rec.toolName, [num]);
      }
    }
  }

  // Check for sequential patterns in any tool group
  for (const nums of byTool.values()) {
    if (nums.length < 2) continue;
    const sorted = [...nums].sort((a, b) => a - b);

    // Check for consistent increments
    let isSequential = true;
    const increment = sorted[1] - sorted[0];
    if (increment <= 0) continue;

    for (let i = 2; i < sorted.length; i++) {
      if (sorted[i] - sorted[i - 1] !== increment) {
        isSequential = false;
        break;
      }
    }
    if (isSequential) return true;
  }

  return false;
}

/**
 * Detect split exfiltration across multiple outbound tool calls.
 *
 * Tracks cumulative outbound volume and call frequency. Fires when
 * the pattern suggests data is being chunked across multiple calls.
 */
export function detectSplitExfiltration(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
  thresholdBytes?: number,
): SplitExfiltrationSignal | null {
  // Gate: only runs for outbound tools
  if (!outboundTools.includes(ctx.toolName)) {
    return null;
  }

  // Gate: L1 must have been active (privileged data in session)
  if (session.privilegedValues.size === 0) {
    return null;
  }

  const threshold = thresholdBytes ?? DEFAULT_SPLIT_EXFIL_THRESHOLD_BYTES;

  // Count prior outbound calls from history and compute cumulative volume
  let outboundCallCount = 0;
  let cumulativeBytes = 0;
  const outboundRecords: OutboundCallRecord[] = [];

  for (const entry of session.toolCallHistory) {
    if (!outboundTools.includes(entry.toolName)) continue;
    outboundCallCount++;

    // Look up the stored outbound bytes for this turn
    const turnBytes = session.outboundBytesByTurn?.get(entry.turnId) ?? 0;
    const turnNumerics = session.outboundNumericArgsByTurn?.get(entry.turnId) ?? [];
    cumulativeBytes += turnBytes;
    outboundRecords.push({
      toolName: entry.toolName,
      byteSize: turnBytes,
      numericArgs: turnNumerics,
      turnId: entry.turnId,
    });
  }

  // Add current call
  const currentArgText = serializeArguments(ctx.toolArguments);
  const currentBytes = Buffer.byteLength(currentArgText, 'utf-8');
  const currentNumerics = extractSequentialIndicators(ctx.toolArguments);
  cumulativeBytes += currentBytes;
  outboundCallCount += 1;

  outboundRecords.push({
    toolName: ctx.toolName,
    byteSize: currentBytes,
    numericArgs: currentNumerics,
    turnId: ctx.turnId,
  });

  // Store current call's outbound data for future turns
  if (session.outboundBytesByTurn) {
    session.outboundBytesByTurn.set(ctx.turnId, currentBytes);
  }
  if (session.outboundNumericArgsByTurn && currentNumerics.length > 0) {
    session.outboundNumericArgsByTurn.set(ctx.turnId, currentNumerics);
  }

  // Detection path 1: volume + frequency threshold
  const volumeExceeded = cumulativeBytes >= threshold && outboundCallCount >= MIN_OUTBOUND_CALLS;

  // Detection path 2: sequential data patterns (lower threshold)
  const sequentialDetected = outboundCallCount >= 2 && hasSequentialPattern(outboundRecords);

  if (!volumeExceeded && !sequentialDetected) {
    return null;
  }

  return {
    layer: 'L3',
    signal: 'SPLIT_EXFILTRATION',
    turnId: ctx.turnId,
    outboundCallCount,
    cumulativeBytes,
    ...(sequentialDetected ? { sequentialPattern: true as const } : {}),
    timestamp: ctx.timestamp,
  };
}
