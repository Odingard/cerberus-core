import type { DetectionSignal, RiskAction, RiskVector, SessionId, TurnId } from './signals.js';
import type { ToolExecutionPhase } from './execution.js';

/** Smallest stable incident contract for the first Cerberus Intelligence layer. */
export interface IntelligenceIncidentEnvelope {
  /** Stable identifier derived from the session and turn. */
  readonly incidentId: string;
  /** Session where the incident occurred. */
  readonly sessionId: SessionId;
  /** Turn that produced the risk assessment. */
  readonly turnId: TurnId;
  /** Timestamp of the turn-level assessment. */
  readonly timestamp: number;
  /** Tool invoked on this turn. */
  readonly toolName: string;
  /** Final Cerberus action for the turn. */
  readonly action: RiskAction;
  /** Correlated turn-level risk score. */
  readonly riskScore: number;
  /** Four-layer risk vector. */
  readonly riskVector: RiskVector;
  /** Whether Cerberus blocked the tool result. */
  readonly blocked: boolean;
  /** Whether the underlying executor ran. */
  readonly executorRan: boolean;
  /** Stage where Cerberus made the execution decision. */
  readonly phase: ToolExecutionPhase;
  /** All structured signals on this turn. */
  readonly signals: readonly DetectionSignal[];
  /** Trusted tools/sources accessed so far in the session. */
  readonly trustedSources: readonly string[];
  /** Untrusted sources observed in the session. */
  readonly untrustedSources: readonly string[];
  /** Privileged field names accessed so far in the session. */
  readonly accessedFields: readonly string[];
  /** Outbound destination when present on this turn. */
  readonly outboundDestination?: string;
  /** Fields matched for exfiltration when present on this turn. */
  readonly exfiltrationFields?: readonly string[];
  /** Memory-contamination markers when L4 fired. */
  readonly memoryMarkers?: readonly string[];
  /** Recent tool order for lightweight incident narration. */
  readonly toolSequence: readonly {
    readonly toolName: string;
    readonly turnId: string;
  }[];
}

// ── Intelligence Analysis Output Types ─────────────────────────────

/** Kill-chain step in the attack narrative. */
export interface KillChainStep {
  readonly turnId: string;
  readonly toolName: string;
  readonly layer: string;
  readonly description: string;
}

/** Policy recommendation. */
export interface PolicyRecommendation {
  readonly priority: 'critical' | 'high' | 'medium' | 'low';
  readonly category: string;
  readonly action: string;
  readonly rationale: string;
}

/** Similar incident reference. */
export interface SimilarIncidentRef {
  readonly pattern: string;
  readonly signalOverlap: readonly string[];
  readonly description: string;
}

/** Full Intelligence analysis output for an incident. */
export interface IntelligenceAnalysis {
  /** Human-readable incident explanation. */
  readonly explanation: string;
  /** Severity label derived from risk score and signals. */
  readonly severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Attack kill-chain steps in chronological order. */
  readonly killChain: readonly KillChainStep[];
  /** Policy/config recommendations. */
  readonly recommendations: readonly PolicyRecommendation[];
  /** Matching attack patterns for incident context. */
  readonly relatedPatterns: readonly SimilarIncidentRef[];
}
