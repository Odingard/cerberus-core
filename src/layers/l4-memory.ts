/**
 * Layer 4 — Memory Contamination Tracker [NOVEL]
 *
 * Tracks taint through persistent memory across sessions.
 * Emits: CONTAMINATED_MEMORY_ACTIVE signal when a tool reads
 * from memory that was contaminated by an untrusted source
 * in a different session.
 *
 * This layer is the original research contribution.
 * No comparable tool exists in production, open source, or academia.
 *
 * Depends on: src/types/signals.ts, src/graph/contamination.ts, src/graph/ledger.ts
 */

import type { ContaminatedMemorySignal, TrustLevel } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { hashContent } from '../graph/ledger.js';

// ── Types ───────────────────────────────────────────────────────────

/** Configuration for memory tool classification. */
export interface MemoryToolConfig {
  readonly toolName: string;
  readonly operation: 'read' | 'write';
  /** Custom extractor for the memory node ID from tool arguments. */
  readonly extractNodeId?: (args: Record<string, unknown>) => string | undefined;
  /** Custom extractor for content from tool arguments (writes) or result (reads). */
  readonly extractContent?: (args: Record<string, unknown>, result: string) => string;
}

// ── Node ID Extraction ──────────────────────────────────────────────

/** Default field names to check for a memory node ID. */
const NODE_ID_FIELDS = ['key', 'id', 'nodeId', 'memoryKey'] as const;

/**
 * Default node ID extraction: looks for common key fields in tool arguments.
 */
export function defaultExtractNodeId(args: Record<string, unknown>): string | undefined {
  for (const field of NODE_ID_FIELDS) {
    const value = args[field];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

/**
 * Extract a node ID from tool arguments using the configured extractor or default logic.
 */
export function extractNodeId(
  args: Record<string, unknown>,
  config: MemoryToolConfig,
): string | undefined {
  if (config.extractNodeId) {
    return config.extractNodeId(args);
  }
  return defaultExtractNodeId(args);
}

// ── Content Extraction ──────────────────────────────────────────────

/**
 * Default content extraction: for writes uses args 'value'/'content'/'data',
 * for reads uses the tool result.
 */
export function defaultExtractContent(args: Record<string, unknown>, result: string): string {
  // Try to extract from args first (for writes)
  for (const field of ['value', 'content', 'data']) {
    const value = args[field];
    if (typeof value === 'string') {
      return value;
    }
  }
  // Fall back to tool result (for reads)
  return result;
}

// ── L4 Detection ────────────────────────────────────────────────────

/**
 * Process a tool call through L4 memory contamination detection.
 *
 * For write operations: records the write in the graph and ledger.
 * For read operations: checks if the read node is tainted across sessions.
 *
 * Returns a ContaminatedMemorySignal if cross-session taint is detected, null otherwise.
 */
export function checkMemoryContamination(
  ctx: ToolCallContext,
  memoryTools: readonly MemoryToolConfig[],
  graph: ContaminationGraph,
  ledger: ProvenanceLedger,
  trustLevel: TrustLevel,
): ContaminatedMemorySignal | null {
  // Find matching memory tool config
  const toolConfig = memoryTools.find((t) => t.toolName === ctx.toolName);
  if (!toolConfig) {
    return null;
  }

  // Extract node ID
  const nodeId = extractNodeId(ctx.toolArguments, toolConfig);
  if (!nodeId) {
    return null;
  }

  // Extract content
  const contentExtractor = toolConfig.extractContent ?? defaultExtractContent;
  const content = contentExtractor(ctx.toolArguments, ctx.toolResult);
  const contentHash = hashContent(content);

  if (toolConfig.operation === 'write') {
    // Record the write in the graph
    graph.writeNode({
      nodeId,
      trustLevel,
      sourceSessionId: ctx.sessionId,
      source: ctx.toolName,
      contentHash,
      timestamp: ctx.timestamp,
    });

    // Record in the ledger for persistence
    ledger.recordWrite({
      nodeId,
      sessionId: ctx.sessionId,
      trustLevel,
      source: ctx.toolName,
      contentHash,
      timestamp: ctx.timestamp,
    });

    // Writes don't emit signals — only reads do
    return null;
  }

  // Read operation: check for cross-session taint
  if (!graph.hasCrossSessionTaint(nodeId, ctx.sessionId)) {
    return null;
  }

  const contaminationSource = graph.findContaminationSource(nodeId) ?? 'unknown';

  return {
    layer: 'L4',
    signal: 'CONTAMINATED_MEMORY_ACTIVE',
    turnId: ctx.turnId,
    sessionId: ctx.sessionId,
    nodeId,
    contaminationSource,
    timestamp: ctx.timestamp,
  };
}
