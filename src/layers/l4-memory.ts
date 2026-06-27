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

import type { ContaminatedMemorySignal, TrustLevel, SessionId, TurnId } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { MemoryDependencyGateConfig } from '../types/config.js';
import type { DetectionSession } from '../engine/session.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import type { AgentSigner } from '../graph/authorship.js';
import { hashContent, computeCommitment } from '../graph/ledger.js';
import {
  tokenize,
  isDerivationDependency,
  isDerivationDependencyScored,
} from './read-relevance.js';

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

// ── Reusable recording core ─────────────────────────────────────────
//
// The read/write recording logic below is the single implementation of how a
// memory operation feeds the contamination graph + provenance ledger. Both the
// tool-call path (`checkMemoryContamination`, driven by the interceptor) and
// the live framework memory adapters (`src/adapters/memory-store.ts`, which tap
// a framework's native store/checkpointer directly) call these, so the two
// entry points can never drift in how they populate the ledger.

/** A memory READ to feed into the contamination graph + session read scope. */
export interface MemoryReadEvent {
  readonly nodeId: string;
  readonly content: string;
  readonly sessionId: SessionId;
  readonly turnId: TurnId;
  readonly timestamp: number;
}

/** A memory WRITE to record into the contamination graph + provenance ledger. */
export interface MemoryWriteEvent {
  readonly nodeId: string;
  readonly content: string;
  readonly trustLevel: TrustLevel;
  readonly sessionId: SessionId;
  /** The source label (tool name, store name, framework component). */
  readonly source: string;
  readonly timestamp: number;
  /**
   * Optional per-agent signer. When provided, the ledger signs the record's
   * content+deps commitment as `signer.author` (AL3 authorship). The private
   * key is never seen by the ledger.
   */
  readonly signer?: AgentSigner;
  /**
   * Optional self-declared derivation (Item 2). Persisted as a parallel edge
   * set only when the ledger was built with `declaredDerivation: true`.
   */
  readonly declaredDeps?: readonly string[];
}

/** What a recorded write resolved to (the observed-read deps + commitment). */
export interface RecordedWrite {
  readonly nodeId: string;
  readonly deps: readonly string[];
  readonly commitment: string;
}

/**
 * Record a memory WRITE into the contamination graph and provenance ledger.
 *
 * Claims the session's in-scope observed reads as the write's observed-read
 * dependencies (a conservative OVER-APPROXIMATION of true data deps), so the
 * forward blast radius B(p) is a conservative upper bound. The read-set is NOT
 * cleared (no context-eviction model — a prior read may still inform a later
 * write). Empty deps = a root (sensor / externally-attested input).
 *
 * When a read-relevance `gate` is provided (threshold > 0), the deps are
 * filtered to reads the write's content plausibly DERIVES from (containment
 * overlap ≥ threshold). Omitted/threshold 0 = the all-reads baseline.
 */
export function recordMemoryWrite(
  event: MemoryWriteEvent,
  graph: ContaminationGraph,
  ledger: ProvenanceLedger,
  session: DetectionSession,
  gate?: MemoryDependencyGateConfig,
): RecordedWrite {
  const contentHash = hashContent(event.content);

  // Observed-read deps: in-scope reads other than the node being written.
  const candidateDeps = [...session.observedMemoryReads]
    .filter((dep) => dep !== event.nodeId)
    .sort();
  // Read-relevance gate (content-derivation): admit a candidate read as a dep
  // only if the write's content plausibly derives from it. threshold 0 / no
  // gate admits all (the all-reads baseline). A pluggable `relevanceScorer`
  // (Part 2 — the semantic gate) scores raw content; omitted = the zero-dep
  // token-overlap default (write tokenized once).
  const threshold = gate?.threshold ?? 0;
  const scorer = gate?.relevanceScorer;
  let deps: string[];
  if (threshold <= 0) {
    deps = candidateDeps;
  } else if (scorer) {
    deps = candidateDeps.filter((dep) =>
      isDerivationDependencyScored(
        event.content,
        session.observedReadContent.get(dep),
        threshold,
        scorer,
      ),
    );
  } else {
    const writeTokens = tokenize(event.content);
    deps = candidateDeps.filter((dep) =>
      isDerivationDependency(writeTokens, session.observedReadContent.get(dep), threshold),
    );
  }
  const commitment = computeCommitment(contentHash, deps);

  // Record the write in the graph.
  graph.writeNode({
    nodeId: event.nodeId,
    trustLevel: event.trustLevel,
    sourceSessionId: event.sessionId,
    source: event.source,
    contentHash,
    timestamp: event.timestamp,
  });

  // Record dependency edges (dep → this node) for forward reachability.
  for (const dep of deps) {
    graph.addEdge({
      sourceNodeId: dep,
      targetNodeId: event.nodeId,
      sessionId: event.sessionId,
      timestamp: event.timestamp,
    });
  }

  // Record in the ledger for persistence (record row + dependency edges).
  // signer / declaredDeps are conditionally spread so the default path is
  // byte-identical to a write that supplies neither (exactOptionalPropertyTypes).
  ledger.recordWrite({
    nodeId: event.nodeId,
    sessionId: event.sessionId,
    trustLevel: event.trustLevel,
    source: event.source,
    contentHash,
    timestamp: event.timestamp,
    deps,
    commitment,
    ...(event.signer ? { signer: event.signer } : {}),
    ...(event.declaredDeps ? { declaredDeps: event.declaredDeps } : {}),
  });

  return { nodeId: event.nodeId, deps, commitment };
}

/**
 * Record a memory READ: add it to the session's in-scope read-set (so later
 * writes can claim it as an observed-read dependency) and check whether the
 * read node is tainted by an untrusted source in a DIFFERENT session.
 *
 * Returns a {@link ContaminatedMemorySignal} when cross-session taint is
 * detected, null otherwise.
 */
export function recordMemoryRead(
  event: MemoryReadEvent,
  graph: ContaminationGraph,
  session: DetectionSession,
): ContaminatedMemorySignal | null {
  // Record the read so later writes can claim it as an observed-read dep
  // (stays in scope until session reset). Capture content too, so the
  // read-relevance gate can later test write-derivation.
  session.observedMemoryReads.add(event.nodeId);
  session.observedReadContent.set(event.nodeId, event.content);

  if (!graph.hasCrossSessionTaint(event.nodeId, event.sessionId)) {
    return null;
  }

  const contaminationSource = graph.findContaminationSource(event.nodeId) ?? 'unknown';

  return {
    layer: 'L4',
    signal: 'CONTAMINATED_MEMORY_ACTIVE',
    turnId: event.turnId,
    sessionId: event.sessionId,
    nodeId: event.nodeId,
    contaminationSource,
    timestamp: event.timestamp,
  };
}

// ── L4 Detection ────────────────────────────────────────────────────

/**
 * Process a tool call through L4 memory contamination detection.
 *
 * Thin classifier over the reusable recording core: resolves the matching
 * memory-tool config, extracts the node ID + content, then delegates to
 * {@link recordMemoryWrite} (writes) or {@link recordMemoryRead} (reads).
 *
 * Returns a ContaminatedMemorySignal if cross-session taint is detected, null otherwise.
 */
export function checkMemoryContamination(
  ctx: ToolCallContext,
  memoryTools: readonly MemoryToolConfig[],
  graph: ContaminationGraph,
  ledger: ProvenanceLedger,
  trustLevel: TrustLevel,
  session: DetectionSession,
  gate?: MemoryDependencyGateConfig,
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

  if (toolConfig.operation === 'write') {
    recordMemoryWrite(
      {
        nodeId,
        content,
        trustLevel,
        sessionId: ctx.sessionId,
        source: ctx.toolName,
        timestamp: ctx.timestamp,
      },
      graph,
      ledger,
      session,
      gate,
    );
    // Writes don't emit signals — only reads do
    return null;
  }

  return recordMemoryRead(
    {
      nodeId,
      content,
      sessionId: ctx.sessionId,
      turnId: ctx.turnId,
      timestamp: ctx.timestamp,
    },
    graph,
    session,
  );
}
