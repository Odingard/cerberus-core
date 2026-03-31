/**
 * Core signal and risk vector types for the Cerberus detection platform.
 *
 * Every detection layer emits a typed signal. The correlation engine
 * aggregates these signals into a per-turn risk vector.
 */

/** Trust level assigned to data sources and context tokens. */
export type TrustLevel = 'trusted' | 'untrusted' | 'unknown';

/** Unique identifier for an execution turn within an agent session. */
export type TurnId = string;

/** Unique identifier for a session. */
export type SessionId = string;

/** L1 signal — emitted when a tool accesses a data source. */
export interface PrivilegedDataSignal {
  readonly layer: 'L1';
  readonly signal: 'PRIVILEGED_DATA_ACCESSED';
  readonly turnId: TurnId;
  readonly source: string;
  readonly fields: readonly string[];
  readonly trustLevel: TrustLevel;
  readonly timestamp: number;
}

/** L2 signal — emitted when untrusted tokens enter the LLM context. */
export interface UntrustedTokensSignal {
  readonly layer: 'L2';
  readonly signal: 'UNTRUSTED_TOKENS_IN_CONTEXT';
  readonly turnId: TurnId;
  readonly source: string;
  readonly tokenCount: number;
  readonly trustLevel: TrustLevel;
  readonly timestamp: number;
}

/** L3 signal — emitted when outbound content correlates with untrusted input. */
export interface ExfiltrationRiskSignal {
  readonly layer: 'L3';
  readonly signal: 'EXFILTRATION_RISK';
  readonly turnId: TurnId;
  readonly matchedFields: readonly string[];
  readonly destination: string;
  readonly similarityScore: number;
  readonly timestamp: number;
}

/** L4 signal — emitted when contaminated memory influences an action. */
export interface ContaminatedMemorySignal {
  readonly layer: 'L4';
  readonly signal: 'CONTAMINATED_MEMORY_ACTIVE';
  readonly turnId: TurnId;
  readonly sessionId: SessionId;
  readonly nodeId: string;
  readonly contaminationSource: string;
  readonly timestamp: number;
}

/** Sub-classifier signal — secrets/credentials detected in tool results (enhances L1). */
export interface SecretsDetectedSignal {
  readonly layer: 'L1';
  readonly signal: 'SECRETS_DETECTED';
  readonly turnId: TurnId;
  readonly secretTypes: readonly string[];
  readonly count: number;
  readonly timestamp: number;
}

/** Sub-classifier signal — prompt injection patterns in untrusted content (enhances L2). */
export interface InjectionPatternsSignal {
  readonly layer: 'L2';
  readonly signal: 'INJECTION_PATTERNS_DETECTED';
  readonly turnId: TurnId;
  readonly patternsFound: readonly string[];
  readonly confidence: number;
  readonly timestamp: number;
}

/** Sub-classifier signal — encoded/obfuscated content in untrusted input (enhances L2). */
export interface EncodingDetectedSignal {
  readonly layer: 'L2';
  readonly signal: 'ENCODING_DETECTED';
  readonly turnId: TurnId;
  readonly encodingTypes: readonly string[];
  readonly decodedSnippet?: string;
  readonly timestamp: number;
}

/** Sub-classifier signal — suspicious destination in outbound call (enhances L3). */
export interface SuspiciousDestinationSignal {
  readonly layer: 'L3';
  readonly signal: 'SUSPICIOUS_DESTINATION';
  readonly turnId: TurnId;
  readonly destination: string;
  readonly riskFactors: readonly string[];
  readonly domainRisk: 'low' | 'medium' | 'high';
  readonly timestamp: number;
}

/** Sub-classifier signal — MCP tool description poisoning detected (enhances L2). */
export interface ToolPoisoningSignal {
  readonly layer: 'L2';
  readonly signal: 'TOOL_POISONING_DETECTED';
  readonly turnId: TurnId;
  readonly toolName: string;
  readonly patternsFound: readonly string[];
  readonly severity: 'low' | 'medium' | 'high';
  readonly timestamp: number;
}

/** Sub-classifier signal — behavioral drift after untrusted content (enhances L2/L3). */
export interface BehavioralDriftSignal {
  readonly layer: 'L2' | 'L3';
  readonly signal: 'BEHAVIORAL_DRIFT_DETECTED';
  readonly turnId: TurnId;
  readonly driftType: string;
  readonly evidence: string;
  readonly timestamp: number;
}

/**
 * Sub-classifier signal — outbound call to non-authorized destination after injection and
 * privileged data access (enhances L3). Fires even when PII is not verbatim in the outbound
 * payload, catching summarized/transformed exfiltration that the token-match path misses.
 */
export interface InjectionCorrelatedOutboundSignal {
  readonly layer: 'L3';
  readonly signal: 'INJECTION_CORRELATED_OUTBOUND';
  readonly turnId: TurnId;
  readonly destination: string;
  readonly untrustedSources: readonly string[];
  readonly trustedSourcesAccessed: readonly string[];
  readonly timestamp: number;
}

/** Tool description for MCP scanner. */
export interface ToolDescription {
  readonly name: string;
  readonly description: string;
  readonly parameters?: Readonly<Record<string, unknown>>;
}

/** Result from standalone MCP tool description scan. */
export interface ToolPoisoningResult {
  readonly toolName: string;
  readonly poisoned: boolean;
  readonly patternsFound: readonly string[];
  readonly severity: 'low' | 'medium' | 'high';
}

/** Signal — late tool registration event (audit trail, L2). */
export interface LateToolRegisteredSignal {
  readonly layer: 'L2';
  readonly signal: 'LATE_TOOL_REGISTERED';
  readonly turnId: TurnId;
  readonly toolName: string;
  readonly reason: string;
  readonly authorizedBy: string;
  readonly schemaHash: string;
  readonly timestamp: number;
}

/** Signal — tool registration blocked due to active injection context (L2). */
export interface InjectionAssistedRegistrationSignal {
  readonly layer: 'L2';
  readonly signal: 'INJECTION_ASSISTED_REGISTRATION';
  readonly turnId: TurnId;
  readonly toolName: string;
  readonly injectionPatterns: readonly string[];
  readonly timestamp: number;
}

/** Signal — registered tool's schema changed (scope expansion, L2). */
export interface ScopeExpansionSignal {
  readonly layer: 'L2';
  readonly signal: 'SCOPE_EXPANSION';
  readonly turnId: TurnId;
  readonly toolName: string;
  readonly originalHash: string;
  readonly newHash: string;
  readonly timestamp: number;
}

/** Sub-classifier signal — multi-hop exfiltration chain detected (enhances L3). */
export interface MultiHopExfiltrationSignal {
  readonly layer: 'L3';
  readonly signal: 'MULTI_HOP_EXFILTRATION';
  readonly turnId: TurnId;
  readonly chainTools: readonly string[];
  readonly chainLength: number;
  readonly timestamp: number;
}

/** Sub-classifier signal — encoded payload in outbound arguments (enhances L3). */
export interface EncodedExfiltrationSignal {
  readonly layer: 'L3';
  readonly signal: 'ENCODED_EXFILTRATION';
  readonly turnId: TurnId;
  readonly encodingTypes: readonly string[];
  readonly decodedSnippet?: string;
  readonly matchedFields?: readonly string[];
  readonly similarityScore?: number;
  readonly timestamp: number;
}

/** Sub-classifier signal — split exfiltration across multiple outbound calls (enhances L3). */
export interface SplitExfiltrationSignal {
  readonly layer: 'L3';
  readonly signal: 'SPLIT_EXFILTRATION';
  readonly turnId: TurnId;
  readonly outboundCallCount: number;
  readonly cumulativeBytes: number;
  readonly sequentialPattern?: true;
  readonly timestamp: number;
}

/** Cross-agent signal — Lethal Trifecta satisfied across agent boundaries. */
export interface CrossAgentTrifectaSignal {
  readonly layer: 'CROSS_AGENT';
  readonly signal: 'CROSS_AGENT_TRIFECTA';
  readonly turnId: TurnId;
  readonly contributingAgents: readonly string[];
  readonly riskState: { readonly l1: boolean; readonly l2: boolean; readonly l3: boolean };
  readonly timestamp: number;
}

/** Cross-agent signal — injection contamination propagates through delegation edges. */
export interface ContextContaminationSignal {
  readonly layer: 'CROSS_AGENT';
  readonly signal: 'CONTEXT_CONTAMINATION_PROPAGATION';
  readonly turnId: TurnId;
  readonly sourceAgentId: string;
  readonly contaminatedAgentId: string;
  readonly contaminationChain: readonly string[];
  readonly timestamp: number;
}

/** Cross-agent signal — agent appeared without a delegation edge from a known agent. */
export interface UnauthorizedAgentSpawnSignal {
  readonly layer: 'CROSS_AGENT';
  readonly signal: 'UNAUTHORIZED_AGENT_SPAWN';
  readonly turnId: TurnId;
  readonly agentId: string;
  readonly timestamp: number;
}

/** Signal — context window overflow detected (L1). */
export interface ContextOverflowSignal {
  readonly layer: 'L1';
  readonly signal: 'CONTEXT_OVERFLOW';
  readonly turnId: TurnId;
  readonly totalTokens: number;
  readonly limit: number;
  readonly segmentsInspected: number;
  readonly segmentsDropped: number;
  readonly overflowAction: 'partial-scan' | 'block';
  readonly timestamp: number;
}

/** Union of all detection layer signals. */
export type DetectionSignal =
  | PrivilegedDataSignal
  | UntrustedTokensSignal
  | ExfiltrationRiskSignal
  | ContaminatedMemorySignal
  | SecretsDetectedSignal
  | InjectionPatternsSignal
  | EncodingDetectedSignal
  | SuspiciousDestinationSignal
  | ToolPoisoningSignal
  | BehavioralDriftSignal
  | InjectionCorrelatedOutboundSignal
  | MultiHopExfiltrationSignal
  | EncodedExfiltrationSignal
  | SplitExfiltrationSignal
  | LateToolRegisteredSignal
  | InjectionAssistedRegistrationSignal
  | ScopeExpansionSignal
  | ContextOverflowSignal
  | CrossAgentTrifectaSignal
  | ContextContaminationSignal
  | UnauthorizedAgentSpawnSignal;

/** 4-bit risk vector — one boolean per detection layer. */
export interface RiskVector {
  readonly l1: boolean;
  readonly l2: boolean;
  readonly l3: boolean;
  readonly l4: boolean;
}

/** Computed risk score (0-4) with the action to take. */
export type RiskAction = 'none' | 'log' | 'alert' | 'interrupt';

/** Turn-level risk assessment produced by the correlation engine. */
export interface RiskAssessment {
  readonly turnId: TurnId;
  readonly vector: RiskVector;
  readonly score: number;
  readonly action: RiskAction;
  readonly signals: readonly DetectionSignal[];
  readonly timestamp: number;
}
