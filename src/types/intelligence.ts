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
