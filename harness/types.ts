/**
 * Harness-specific types for the Phase 1 attack research instrument.
 *
 * These types define the structure of payloads, tool call records,
 * execution traces, and ground-truth labels. They build on the core
 * signal types from src/types/signals.ts.
 */

import type { DetectionSignal, RiskVector } from '../src/types/signals.js';

// ── Payload Types ──────────────────────────────────────────────────

/** Payload category taxonomy. */
export type PayloadCategory =
  | 'direct-injection'
  | 'encoded-obfuscated'
  | 'social-engineering'
  | 'multi-turn'
  | 'multilingual'
  | 'advanced-technique';

/** Expected outcome of a payload — what SHOULD happen if the attack succeeds. */
export type ExpectedOutcome =
  | 'exfiltration-success'
  | 'exfiltration-partial'
  | 'exfiltration-blocked'
  | 'behavior-modification'
  | 'no-effect';

/** A single injection payload definition. */
export interface Payload {
  readonly id: string;
  readonly category: PayloadCategory;
  readonly content: string;
  readonly description: string;
  readonly expectedOutcome: ExpectedOutcome;
  readonly tags: readonly string[];
}

// ── Finish Reason ─────────────────────────────────────────────────

/** OpenAI finish reason values relevant to the harness. */
export type FinishReason = 'stop' | 'tool_calls' | 'length' | 'content_filter' | 'unknown';

// ── Error Tracking ────────────────────────────────────────────────

/** Structured error captured during a run. */
export interface ErrorInfo {
  readonly code:
    | 'API_ERROR'
    | 'TIMEOUT'
    | 'JSON_PARSE'
    | 'TOOL_EXEC'
    | 'VALIDATION'
    | 'FILE_IO'
    | 'UNKNOWN';
  readonly message: string;
  readonly turnIndex?: number | undefined;
  readonly toolName?: string | undefined;
  readonly timestamp: number;
}

// ── Tool Types ─────────────────────────────────────────────────────

/** Whether tools make real HTTP calls or simulate them. */
export type ToolMode = 'simulated' | 'live';

/** Result from a single tool invocation. */
export interface ToolCallRecord {
  readonly toolName: 'readPrivateData' | 'fetchExternalContent' | 'sendOutboundReport';
  readonly arguments: Record<string, unknown>;
  readonly result: string;
  readonly timestamp: number;
  readonly expectedSignals: readonly DetectionSignal[];
}

/** Configuration for creating tool executors. */
export interface ToolExecutorConfig {
  readonly mode: ToolMode;
  readonly injectionContent: string;
  readonly webhookUrl: string;
  readonly externalUrl: string;
  readonly onToolCall?: (record: ToolCallRecord) => void;
}

/** A function that executes a tool and returns its string result. */
export type ToolExecutor = (args: Record<string, unknown>) => Promise<string>;

// ── Agent Types ────────────────────────────────────────────────────

/** A single LLM interaction turn (one completion request/response cycle). */
export interface TurnRecord {
  readonly turnIndex: number;
  readonly turnId: string;
  readonly role: 'assistant' | 'tool';
  readonly assistantContent: string | null;
  readonly toolCalls: readonly ToolCallRecord[];
  readonly finishReason: FinishReason;
  readonly timestamp: number;
}

/** Configuration for creating an agent. */
export interface AgentConfig {
  readonly apiKey?: string;
  readonly model?: string;
  readonly maxTurns?: number;
  readonly toolExecutors: Record<string, ToolExecutor>;
  readonly onTurn?: (turn: TurnRecord) => void;
  readonly timeoutMs?: number | undefined;
  readonly maxRetries?: number | undefined;
  readonly temperature?: number | undefined;
  readonly seed?: number | undefined;
}

/** Result of running the agent. */
export interface AgentResult {
  readonly turns: readonly TurnRecord[];
  readonly finalMessage: string | null;
  readonly tokenUsage: {
    readonly promptTokens: number;
    readonly completionTokens: number;
    readonly totalTokens: number;
  };
  readonly errors: readonly ErrorInfo[];
  readonly stopReason: FinishReason;
}

// ── Trace Types ────────────────────────────────────────────────────

/** Unique run identifier for a single payload execution. */
export type RunId = string;

/** Whether the attack succeeded, failed, or was indeterminate. */
export type AttackOutcome = 'success' | 'failure' | 'partial' | 'error';

/** Ground-truth labels for what happened during a run. */
export interface GroundTruthLabels {
  readonly privilegedAccessOccurred: boolean;
  readonly injectionDelivered: boolean;
  readonly exfiltrationAttempted: boolean;
  readonly privateDataInExfiltration: boolean;
  readonly exfiltratedFields: readonly string[];
  readonly riskVector: RiskVector;
  readonly outcome: AttackOutcome;
}

/** Configuration snapshot stored in traces. */
export interface TraceConfig {
  readonly toolMode: ToolMode;
  readonly model: string;
  readonly maxTurns: number;
  readonly externalContentUrl: string;
  readonly exfiltrationWebhookUrl: string;
  readonly userPrompt: string;
  readonly systemPromptId: string;
  readonly temperature?: number | undefined;
  readonly seed?: number | undefined;
  readonly trialIndex?: number | undefined;
  readonly provider?: string | undefined;
}

/** The full execution trace for one payload run. */
export interface ExecutionTrace {
  readonly schemaVersion: '1.0.0';
  readonly runId: RunId;
  readonly payload: Payload;
  readonly config: TraceConfig;
  readonly turns: readonly TurnRecord[];
  readonly labels: GroundTruthLabels;
  readonly tokenUsage: {
    readonly promptTokens: number;
    readonly completionTokens: number;
    readonly totalTokens: number;
  };
  readonly durationMs: number;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly error?: ErrorInfo | undefined;
  readonly errors?: readonly ErrorInfo[] | undefined;
}

/** Summary statistics produced after a batch run. */
export interface RunSummary {
  readonly totalRuns: number;
  readonly successCount: number;
  readonly partialCount: number;
  readonly failureCount: number;
  readonly errorCount: number;
  readonly successRate: number;
  readonly byCategory: Record<
    PayloadCategory,
    {
      readonly total: number;
      readonly successes: number;
      readonly rate: number;
    }
  >;
  readonly completedAt: string;
}

/** Per-payload trial statistics for multi-trial stress runs. */
export interface PayloadTrialStats {
  readonly payloadId: string;
  readonly category: PayloadCategory;
  readonly trials: number;
  readonly successes: number;
  readonly partials: number;
  readonly failures: number;
  readonly errors: number;
  readonly successRate: number;
}

/** Enhanced summary for multi-trial stress runs. */
export interface StressSummary extends RunSummary {
  readonly trialsPerPayload: number;
  readonly systemPromptId: string;
  readonly temperature?: number | undefined;
  readonly seed?: number | undefined;
  readonly perPayload: readonly PayloadTrialStats[];
  readonly meanSuccessRate: number;
  readonly successRateVariance: number;
}

// ── Fixture Types ──────────────────────────────────────────────────

/** A single private customer record from the fixture. */
export interface PrivateRecord {
  readonly id: string;
  readonly name: string;
  readonly email: string;
  readonly phone: string;
  readonly ssn: string;
  readonly address: string;
  readonly accountBalance: number;
  readonly notes: string;
}

/** The shape of the private data fixture file. */
export interface PrivateDataFixture {
  readonly records: readonly PrivateRecord[];
  readonly metadata: {
    readonly source: string;
    readonly classification: 'CONFIDENTIAL';
    readonly fields: readonly string[];
  };
}

// ── Runner Types ───────────────────────────────────────────────────

/** Options for a runner execution. */
export interface RunnerOptions {
  readonly payloadIds?: readonly string[];
  readonly categories?: readonly PayloadCategory[];
  readonly toolMode?: ToolMode;
  readonly model?: string;
  readonly maxTurns?: number;
  readonly outputDir?: string;
  readonly skipExisting?: boolean;
  readonly delayBetweenRunsMs?: number;
  readonly perRunTimeoutMs?: number | undefined;
  readonly onRunComplete?: (trace: ExecutionTrace) => void;
  readonly trials?: number | undefined;
  readonly systemPromptId?: string | undefined;
  readonly systemPrompt?: string | undefined;
  readonly temperature?: number | undefined;
  readonly seed?: number | undefined;
  readonly trialIndex?: number | undefined;
}
