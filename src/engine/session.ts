/**
 * Detection Session — Per-session state container.
 *
 * Tracks accumulated state across tool calls within a single agent session.
 * L1 writes accessed fields and PII values; L2 writes untrusted sources;
 * L3 reads both to detect exfiltration correlation.
 */

import type { SessionId, DetectionSignal } from '../types/signals.js';
import type { DelegationGraph } from '../graph/delegation.js';
import type { SensitiveEntity } from '../layers/sensitive-entities.js';

/** Monotonic counter to guarantee unique session IDs even within the same millisecond. */
let sessionSeq = 0;

/** Generate a unique session ID. */
function generateSessionId(): SessionId {
  return `session-${Date.now()}-${String(sessionSeq++)}`;
}

/** Per-session state accumulated by detection layers. */
export interface DetectionSession {
  /** Unique session identifier. Rotated on reset() for L4 cross-session detection. */
  sessionId: SessionId;

  /** Field names accessed from privileged/trusted data sources (set by L1). */
  readonly accessedFields: Set<string>;

  /** Raw PII values seen in tool results, lowercased for matching (set by L1). */
  readonly privilegedValues: Set<string>;

  /** Structured sensitive entities captured from trusted tool results. */
  readonly sensitiveEntities: SensitiveEntity[];

  /** Tool names classified as trusted that have been accessed. */
  readonly trustedSourcesAccessed: Set<string>;

  /**
   * Memory nodeIds observed read in this session that remain in scope as
   * dependency candidates for subsequent memory writes (set by L4).
   *
   * NOT cleared on write: Cerberus has no context-eviction model, so any
   * prior read may still inform a later write (read-once-write-many). Each
   * write claims these as its observed-read deps — a conservative
   * OVER-APPROXIMATION of true data dependencies. Cleared only on session
   * reset (a new scope).
   */
  readonly observedMemoryReads: Set<string>;

  /**
   * Content observed for each in-scope memory read (nodeId → content), captured
   * alongside {@link observedMemoryReads} (set by L4). Feeds the read-relevance
   * (content-derivation) gate: at write time the gate compares the write's
   * content against each candidate dependency's read content. Cleared with the
   * read scope on reset and on a frontier checkpoint. Empty/absent when the gate
   * is disabled — capturing it is cheap and keeps the gate framework-observable.
   */
  readonly observedReadContent: Map<string, string>;

  /** Total untrusted token count accumulated (set by L2). */
  untrustedTokenCount: number;

  /** Sources of untrusted content that entered the context (set by L2). */
  readonly untrustedSources: Set<string>;

  /** All signals emitted during this session, indexed by turnId. */
  readonly signalsByTurn: Map<string, DetectionSignal[]>;

  /** Turn counter for generating sequential turn IDs. */
  turnCounter: number;

  /** Secrets/credentials detected in tool results (set by secrets detector). */
  readonly detectedSecrets: Set<string>;

  /** Injection pattern categories found in untrusted content (set by injection scanner). */
  readonly injectionPatternsFound: Set<string>;

  /** Tool call history for behavioral drift detection. */
  readonly toolCallHistory: Array<{ toolName: string; turnId: string; timestamp: number }>;

  /** Outbound argument byte counts per turn (set by split exfiltration detector). */
  readonly outboundBytesByTurn: Map<string, number>;

  /** Outbound numeric args per turn for sequential pattern detection. */
  readonly outboundNumericArgsByTurn: Map<string, readonly number[]>;

  /** Registered tools with their schema fingerprints (for dynamic tool registration). */
  readonly registeredTools: Map<string, RegisteredToolEntry>;

  /** Audit log for late tool registrations. */
  readonly toolRegistrationAudit: Array<ToolRegistrationAuditEntry>;

  /** Multi-agent delegation graph (present when multiAgent is enabled). */
  delegationGraph?: DelegationGraph;

  /** Current agent ID in a multi-agent session. */
  currentAgentId?: string;
}

/** Entry for a registered tool's schema fingerprint. */
export interface RegisteredToolEntry {
  readonly toolName: string;
  readonly schemaHash: string;
  readonly registeredAt: number;
  readonly authorizedBy: string;
}

/** Audit entry for tool registration events. */
export interface ToolRegistrationAuditEntry {
  readonly toolName: string;
  readonly reason: string;
  readonly authorizedBy: string;
  readonly schemaHash: string;
  readonly timestamp: number;
  readonly blocked: boolean;
  readonly blockReason?: string;
}

/** Create a fresh detection session. */
export function createSession(sessionId?: string): DetectionSession {
  return {
    sessionId: sessionId ?? generateSessionId(),
    accessedFields: new Set(),
    privilegedValues: new Set(),
    sensitiveEntities: [],
    trustedSourcesAccessed: new Set(),
    observedMemoryReads: new Set(),
    observedReadContent: new Map(),
    untrustedTokenCount: 0,
    untrustedSources: new Set(),
    signalsByTurn: new Map(),
    turnCounter: 0,
    detectedSecrets: new Set(),
    injectionPatternsFound: new Set(),
    toolCallHistory: [],
    outboundBytesByTurn: new Map(),
    outboundNumericArgsByTurn: new Map(),
    registeredTools: new Map(),
    toolRegistrationAudit: [],
  };
}

/** Record a signal into the session's per-turn signal store. */
export function recordSignal(session: DetectionSession, signal: DetectionSignal): void {
  const turnSignals = session.signalsByTurn.get(signal.turnId);
  if (turnSignals) {
    turnSignals.push(signal);
  } else {
    session.signalsByTurn.set(signal.turnId, [signal]);
  }
}

/**
 * Frontier checkpoint: clear ONLY the observed-read scope, WITHOUT rotating the
 * sessionId or touching any other session state. A "mini-reset" of the L4
 * dependency scope — every later write starts accumulating reads afresh, so an
 * early read can no longer be claimed as a dep by writes past the checkpoint.
 *
 * This is the §5.2 frontier-checkpointing lever, studied as a regime-limited
 * containment-DoS mitigation (NOT a general fix): bounding how long a (possibly
 * poisoned) read lingers in scope caps the over-containment it drives, but only
 * when incidental reads are low — at realistic read-imprecision (ignored >= 0.5)
 * it is flat/useless. Unlike resetSession it preserves the
 * session identity (it is NOT a new cross-session scope) and all non-memory
 * state, so it isolates the scope-window knob. Trade-off: a dependency read
 * before the checkpoint and relied upon afterwards WITHOUT being re-read (the
 * read-once-write-many pattern no-clear was designed to recover) is no longer
 * captured — a real soundness cost that scales with checkpoint frequency.
 */
export function checkpointScope(session: DetectionSession): void {
  session.observedMemoryReads.clear();
  session.observedReadContent.clear();
}

/**
 * Reset all session state for reuse between runs. Rotates sessionId for L4
 * cross-session detection.
 *
 * `carriedReads` — the cross-session carry-channel hand-off (Spec B). A
 * dependency carried across a reset in context (summary injection,
 * orchestrator-passed state) has NO observed read in the new scope, so the L4
 * capture cannot anchor a dependency edge for the later write that relies on
 * it — the carried-but-unread soundness gap (the §5.3a path measured by PR #49).
 * When an instrumented carry channel records that read-set, passing it here
 * SEEDS the rotated scope's `observedMemoryReads`, so post-reset writes claim
 * the carried deps and the cross-session edges are recovered. This is a clean,
 * minimal hand-off behind the existing reset path — the sessionId still rotates
 * first (cross-session detection semantics are unchanged); only the new scope's
 * read-set is pre-seeded. Omitted/empty = the uninstrumented baseline (carried
 * deps stay missed). A genuinely untracked channel (one no instrumentation can
 * observe) hands off nothing here and remains the documented residual.
 */
export function resetSession(session: DetectionSession, carriedReads?: Iterable<string>): void {
  session.sessionId = generateSessionId();
  session.accessedFields.clear();
  session.privilegedValues.clear();
  session.sensitiveEntities.length = 0;
  session.trustedSourcesAccessed.clear();
  session.observedMemoryReads.clear();
  session.observedReadContent.clear();
  session.untrustedTokenCount = 0;
  session.untrustedSources.clear();
  session.signalsByTurn.clear();
  session.turnCounter = 0;
  session.detectedSecrets.clear();
  session.injectionPatternsFound.clear();
  session.toolCallHistory.length = 0;
  session.outboundBytesByTurn.clear();
  session.outboundNumericArgsByTurn.clear();
  session.registeredTools.clear();
  session.toolRegistrationAudit.length = 0;
  delete session.delegationGraph;
  delete session.currentAgentId;

  // Seed the rotated scope with the carried read-set AFTER the clear, so the
  // hand-off survives the reset and anchors post-reset dependency edges.
  if (carriedReads) {
    for (const nodeId of carriedReads) {
      session.observedMemoryReads.add(nodeId);
    }
  }
}
