/**
 * Configuration types for the Cerberus platform.
 *
 * These types define the developer-facing configuration surface
 * for the cerberus.guard() API.
 */

import type { RiskAction, ToolDescription } from './signals.js';

/** Alert mode determines the maximum action Cerberus will take. */
export type AlertMode = 'log' | 'alert' | 'interrupt';

/** Where Cerberus sends detection output. */
export type LogDestination = 'console' | 'file' | 'webhook';

/** Configuration for file-based logging. */
export interface FileLogConfig {
  readonly destination: 'file';
  readonly path: string;
}

/** Configuration for webhook-based logging. */
export interface WebhookLogConfig {
  readonly destination: 'webhook';
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
}

/** Configuration for console logging. */
export interface ConsoleLogConfig {
  readonly destination: 'console';
}

/** Union of all log destination configs. */
export type LogConfig = ConsoleLogConfig | FileLogConfig | WebhookLogConfig;

/** Per-tool trust override. */
export interface TrustOverride {
  readonly toolName: string;
  readonly trustLevel: 'trusted' | 'untrusted';
}

/** Context scoring mode for context window management. */
export type ContextScoringMode = 'priority-anchor';
/** How Cerberus handles stream-like tool results before inspection. */
export type StreamingMode = 'buffer' | 'reject';

/** Action to take when context window overflow is detected. */
export type OverflowAction = 'partial-scan' | 'block';

/** Regions that are always inspected regardless of context window limit. */
export interface AlwaysInspectRegions {
  /** Always inspect system prompts. Default: true. */
  readonly systemPrompts?: boolean;
  /** Always inspect tool schemas. Default: true. */
  readonly toolSchemas?: boolean;
  /** Always inspect tool results. Default: true. */
  readonly toolResults?: boolean;
}

/** Main configuration for cerberus.guard(). */
export interface CerberusConfig {
  /** Maximum action Cerberus will take. Default: 'alert'. */
  readonly alertMode?: AlertMode;

  /** Enable Layer 4 memory contamination tracking. Default: false. */
  readonly memoryTracking?: boolean;

  /** Log destination configuration. Default: 'console'. */
  readonly logDestination?: LogDestination | LogConfig;

  /** Custom trust overrides for specific tools. */
  readonly trustOverrides?: readonly TrustOverride[];

  /** Minimum risk score (0-4) to trigger the configured alert mode. Default: 3. */
  readonly threshold?: number;

  /** MCP tool descriptions for poisoning detection. */
  readonly toolDescriptions?: readonly ToolDescription[];

  /** Authorized outbound destination domains. L3 skips when destination matches. */
  readonly authorizedDestinations?: readonly string[];

  /**
   * Enable OpenTelemetry instrumentation.
   * When true, Cerberus emits one span (`cerberus.tool_call`) and updates
   * three metrics per tool call. Requires `@opentelemetry/api` (already a
   * dependency) and an OTel SDK + exporter registered in your app.
   * Default: false.
   */
  readonly opentelemetry?: boolean;

  /** Maximum token count for context window scanning. Default: 32000. */
  readonly contextWindowLimit?: number;

  /** Scoring mode for context window segment prioritization. Default: 'priority-anchor'. */
  readonly contextScoringMode?: ContextScoringMode;

  /**
   * How Cerberus handles stream-like tool results (ReadableStream, AsyncIterable, Iterable).
   * Default: 'buffer' — reconstruct the full result before inspection.
   */
  readonly streamingMode?: StreamingMode;

  /** Action when context exceeds the limit. Default: 'partial-scan'. */
  readonly overflowAction?: OverflowAction;

  /** Regions always inspected regardless of context window limit. */
  readonly alwaysInspectRegions?: AlwaysInspectRegions;

  /**
   * Cumulative outbound argument byte threshold for split exfiltration detection.
   * When outbound volume exceeds this value across 3+ outbound calls with L1 active,
   * the SPLIT_EXFILTRATION signal fires. Default: 10240 (10 KB).
   */
  readonly splitExfilThresholdBytes?: number;

  /**
   * Enable multi-agent execution graph integrity tracking.
   * When true, Cerberus tracks delegation across agents and detects
   * cross-agent Lethal Trifecta patterns. Default: false.
   */
  readonly multiAgent?: boolean;

  /**
   * Agent type for multi-agent mode. Only used when multiAgent is true.
   * Default: 'orchestrator'.
   */
  readonly agentType?: 'orchestrator' | 'subagent' | 'tool_agent';

  /** Callback invoked on every risk assessment. */
  readonly onAssessment?: (assessment: {
    readonly turnId: string;
    readonly toolName: string;
    readonly score: number;
    readonly action: RiskAction;
    readonly signals: readonly string[];
  }) => void;
}
