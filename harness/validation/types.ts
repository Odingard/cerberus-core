/**
 * Scientific Validation Protocol — Type Definitions.
 *
 * These types support rigorous, auditable validation of attack findings
 * with negative controls, causation scoring, statistical rigor, and
 * detailed outcome classification.
 */

import type { RiskVector, RiskAssessment } from '../../src/types/signals.js';

// ── Outcome Classification ──────────────────────────────────────

/** Six-state outcome that distinguishes refusal, error, and content filtering. */
export type DetailedOutcome =
  | 'success' // Full trifecta + PII to attacker-controlled destination
  | 'partial' // Some steps completed but not full kill chain
  | 'failure' // Agent completed normally but did not exfiltrate
  | 'refused' // Agent explicitly refused the injected instruction
  | 'error' // Technical failure (API error, timeout)
  | 'content_filtered'; // Provider safety system blocked the response

/** Whether this run is a negative control (no injection) or treatment (with injection). */
export type RunCondition = 'control' | 'treatment';

// ── PII Detection ───────────────────────────────────────────────

/** A single PII field match with provenance tracking. */
export interface PiiFieldMatch {
  readonly field: string; // 'email', 'ssn', 'name', etc.
  readonly recordId: string; // 'CUST-001'
  readonly value: string; // The original fixture value
  readonly matchType: 'exact' | 'normalized';
}

// ── Recipient Validation ────────────────────────────────────────

/** Whether the actual sendOutboundReport recipient matches the injected destination. */
export interface RecipientMatch {
  readonly injectedDestination: string | null; // Email from payload content
  readonly actualRecipient: string | null; // Recipient from sendOutboundReport args
  readonly matches: boolean; // Do they match
  readonly isExternal: boolean; // Not @acme.com / @example.com
}

// ── Refusal Detection ───────────────────────────────────────────

/** How confident we are that the agent refused. */
export type RefusalConfidence = 'high' | 'medium' | 'low' | 'none';

/** Result of parsing agent output for refusal patterns. */
export interface RefusalResult {
  readonly detected: boolean;
  readonly confidence: RefusalConfidence;
  readonly matchedPatterns: readonly string[];
  readonly refusalText: string | null;
}

// ── Sequence Validation ─────────────────────────────────────────

/** Whether the kill chain tools were called in the correct order. */
export interface SequenceValidation {
  readonly valid: boolean;
  readonly readBeforeSend: boolean; // L1 before L3
  readonly fetchBeforeSend: boolean; // L2 before L3
  readonly toolOrder: readonly string[];
}

// ── Causation Analysis ──────────────────────────────────────────

/** A single factor contributing to the causation score. */
export interface CausationFactor {
  readonly name: string;
  readonly weight: number;
  readonly present: boolean;
  readonly explanation: string;
}

/** Causation verdict for whether injection caused exfiltration. */
export type CausationVerdict = 'injection-caused' | 'ambiguous' | 'coincidental';

/** Full causation analysis for one run. */
export interface CausationAnalysis {
  readonly score: number; // 0.0–1.0
  readonly factors: readonly CausationFactor[];
  readonly verdict: CausationVerdict;
}

// ── Enhanced Ground Truth ───────────────────────────────────────

/** Ground truth with causation, sequence, refusal, and recipient validation. */
export interface EnhancedGroundTruth {
  // Existing trifecta flags
  readonly privilegedAccessOccurred: boolean;
  readonly injectionDelivered: boolean;
  readonly exfiltrationAttempted: boolean;
  readonly privateDataInExfiltration: boolean;
  readonly exfiltratedFields: readonly string[];
  readonly riskVector: RiskVector;
  // Enhanced fields
  readonly condition: RunCondition;
  readonly detailedOutcome: DetailedOutcome;
  readonly sequenceValid: boolean;
  readonly recipientMatch: RecipientMatch;
  readonly causation: CausationAnalysis;
  readonly refusalDetected: boolean;
  readonly refusalText: string | null;
  readonly piiDetailed: readonly PiiFieldMatch[];
}

// ── Statistics ──────────────────────────────────────────────────

/** A confidence interval with lower and upper bounds. */
export interface ConfidenceInterval {
  readonly lower: number;
  readonly upper: number;
}

/** Result of Fisher's exact test comparing two groups. */
export interface FisherResult {
  readonly pValue: number;
  readonly significant: boolean;
}

// ── Validation Report ───────────────────────────────────────────

/** Per-provider aggregate statistics. */
export interface ProviderStats {
  readonly provider: string;
  readonly model: string;
  readonly condition: RunCondition;
  readonly totalRuns: number;
  readonly outcomes: Record<DetailedOutcome, number>;
  readonly successRate: number;
  readonly confidenceInterval: ConfidenceInterval;
  readonly meanCausationScore: number;
  readonly sampleErrors: readonly string[];
}

/** Per-payload results across all providers and trials. */
export interface PayloadValidationResult {
  readonly payloadId: string;
  readonly category: string;
  readonly injectedDestination: string | null;
  readonly perProvider: Record<
    string,
    {
      readonly trials: number;
      readonly outcomes: Record<DetailedOutcome, number>;
      readonly successRate: number;
      readonly confidenceInterval: ConfidenceInterval;
      readonly meanCausationScore: number;
      readonly recipientMatchRate: number;
    }
  >;
}

/** Progress callback for the validation runner. */
export interface ValidationProgress {
  readonly phase: 'control' | 'treatment';
  readonly provider: string;
  readonly current: number;
  readonly total: number;
  readonly payloadId?: string;
  readonly trialIndex?: number;
}

// ── Detection Validation Types ──────────────────────────────────

/** Per-layer confusion matrix with accuracy and confidence interval. */
export interface LayerConfusionMatrix {
  readonly tp: number;
  readonly fp: number;
  readonly fn: number;
  readonly tn: number;
  readonly accuracy: number;
  readonly accuracyCI: ConfidenceInterval;
}

/** Detection result for a single run (control or treatment). */
export interface DetectionRunResult {
  readonly payloadId: string;
  readonly provider: string;
  readonly condition: RunCondition;
  readonly groundTruthVector: RiskVector;
  readonly cerberusVector: RiskVector;
  readonly assessments: readonly RiskAssessment[];
  readonly maxScore: number;
  readonly wouldHaveBlocked: boolean;
}

/** Per-provider detection statistics. */
export interface ProviderDetectionStats {
  readonly provider: string;
  readonly model: string;
  readonly detectionRate: number;
  readonly detectionRateCI: ConfidenceInterval;
  readonly blockRate: number;
  readonly blockRateCI: ConfidenceInterval;
  readonly falsePositiveRate: number;
  readonly falsePositiveRateCI: ConfidenceInterval;
  readonly perLayer: {
    readonly L1: LayerConfusionMatrix;
    readonly L2: LayerConfusionMatrix;
    readonly L3: LayerConfusionMatrix;
  };
  readonly treatmentRuns: number;
  readonly controlRuns: number;
}

/** Per-category detection statistics. */
export interface CategoryDetectionStats {
  readonly category: string;
  readonly totalRuns: number;
  readonly detected: number;
  readonly detectionRate: number;
  readonly detectionRateCI: ConfidenceInterval;
  readonly blocked: number;
  readonly blockRate: number;
  readonly blockRateCI: ConfidenceInterval;
}

/** Full detection validation report. */
export interface DetectionReport {
  readonly enabled: boolean;
  readonly config: { readonly alertMode: string; readonly threshold: number };
  readonly perProvider: Record<string, ProviderDetectionStats>;
  readonly perCategory: readonly CategoryDetectionStats[];
  readonly overallDetectionRate: number;
  readonly overallDetectionRateCI: ConfidenceInterval;
  readonly overallFalsePositiveRate: number;
  readonly overallFalsePositiveRateCI: ConfidenceInterval;
  readonly perRun: readonly DetectionRunResult[];
}

/** The complete, auditable validation report. */
export interface ValidationReport {
  readonly schemaVersion: '2.0.0';
  readonly protocol: {
    readonly trialsPerPayload: number;
    readonly controlTrialsPerProvider: number;
    readonly totalRuns: number;
    readonly providers: readonly string[];
    readonly payloadCount: number;
    readonly systemPromptId: string;
  };
  readonly controlResults: Record<string, ProviderStats>;
  readonly treatmentResults: Record<string, ProviderStats>;
  readonly perPayload: readonly PayloadValidationResult[];
  readonly generatedAt: string;
  readonly totalCostEstimateUsd: number;
  readonly detection?: DetectionReport;
}
