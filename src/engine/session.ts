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

  /** Serialized outbound argument text per turn for staged/chunked exfil detection. */
  readonly outboundTextByTurn: Map<string, string>;

  /** Extracted outbound destination per turn for destination clustering. */
  readonly outboundDestinationByTurn: Map<string, string>;

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
    untrustedTokenCount: 0,
    untrustedSources: new Set(),
    signalsByTurn: new Map(),
    turnCounter: 0,
    detectedSecrets: new Set(),
    injectionPatternsFound: new Set(),
    toolCallHistory: [],
    outboundBytesByTurn: new Map(),
    outboundNumericArgsByTurn: new Map(),
    outboundTextByTurn: new Map(),
    outboundDestinationByTurn: new Map(),
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

/** Reset all session state for reuse between runs. Rotates sessionId for L4 cross-session detection. */
export function resetSession(session: DetectionSession): void {
  session.sessionId = generateSessionId();
  session.accessedFields.clear();
  session.privilegedValues.clear();
  session.sensitiveEntities.length = 0;
  session.trustedSourcesAccessed.clear();
  session.untrustedTokenCount = 0;
  session.untrustedSources.clear();
  session.signalsByTurn.clear();
  session.turnCounter = 0;
  session.detectedSecrets.clear();
  session.injectionPatternsFound.clear();
  session.toolCallHistory.length = 0;
  session.outboundBytesByTurn.clear();
  session.outboundNumericArgsByTurn.clear();
  session.outboundTextByTurn.clear();
  session.outboundDestinationByTurn.clear();
  session.registeredTools.clear();
  session.toolRegistrationAudit.length = 0;
  delete session.delegationGraph;
  delete session.currentAgentId;
}
