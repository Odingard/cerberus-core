/**
 * Developer-facing API — cerberus.guard() entry point.
 *
 * Wraps tool executors with the Cerberus detection pipeline.
 * Each tool call passes through L1, L2, L3, and the Correlation Engine.
 * The guard function manages session state and assessment collection.
 */

import type { CerberusConfig } from '../types/config.js';
import type { RiskAssessment } from '../types/signals.js';
import type { ToolExecutionOutcome } from '../types/execution.js';
import type { IntelligenceIncidentEnvelope } from '../types/intelligence.js';
import type { DetectionSession } from '../engine/session.js';
import { createSession, resetSession } from '../engine/session.js';
import { interceptToolCall } from '../engine/interceptor.js';
import type { RawToolExecutorFn, ToolExecutorFn } from '../engine/interceptor.js';
import { validateCerberusConfig } from '../engine/config-validation.js';
import { buildIntelligenceIncidentEnvelope } from '../engine/intelligence-envelope.js';
import type { MemoryToolConfig } from '../layers/l4-memory.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import { createContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { createLedger } from '../graph/ledger.js';
import type { ToolSchema, ToolRegistrationResult } from '../engine/tool-registration.js';
import { registerToolLate } from '../engine/tool-registration.js';

/** Options for L4 memory contamination tracking. */
export interface MemoryGuardOptions {
  /** Memory tool configurations (which tools are memory reads/writes). */
  readonly memoryTools?: readonly MemoryToolConfig[];
  /** Path for the SQLite provenance ledger. Default: ':memory:'. */
  readonly dbPath?: string;
}

/** The result of calling guard(): wrapped executors + session handle. */
export interface GuardResult {
  /** Wrapped tool executors with detection middleware. */
  readonly executors: Record<string, ToolExecutorFn>;
  /** Session handle for inspection (reading signals, assessments). */
  readonly session: DetectionSession;
  /** All risk assessments produced during the session. */
  readonly assessments: readonly RiskAssessment[];
  /** Structured metadata for the most recent guarded tool invocation. */
  readonly getLastOutcome: () => ToolExecutionOutcome | undefined;
  /** Structured incident envelope for the most recent guarded invocation. */
  readonly getLastIncident: () => IntelligenceIncidentEnvelope | undefined;
  /** Reset the session state and assessments for reuse between runs. Graph/ledger persist. */
  readonly reset: () => void;
  /** Contamination graph (present when memoryTracking is enabled). */
  readonly graph?: ContaminationGraph;
  /** Provenance ledger (present when memoryTracking is enabled). */
  readonly ledger?: ProvenanceLedger;
  /** Tear down all resources (close DB, clear graph). Call when done. */
  readonly destroy: () => void;
  /**
   * Register a tool at runtime with security checks.
   * Blocks if injection patterns are active in the session.
   * Detects schema expansion if a tool's schema changes after registration.
   */
  readonly registerTool: (
    tool: ToolSchema,
    reason: string,
    authorizedBy: string,
  ) => ToolRegistrationResult;
}

/**
 * Wrap tool executors with Cerberus detection middleware.
 *
 * @param executors - Map of tool name to executor function
 * @param config - Cerberus configuration (alertMode, threshold, trustOverrides, etc.)
 * @param outboundTools - Names of tools that send data externally (for L3 detection)
 * @param memoryOptions - Optional L4 memory contamination tracking configuration
 * @returns GuardResult with wrapped executors and session handle
 *
 * @example
 * ```typescript
 * const guarded = guard(myToolExecutors, {
 *   alertMode: 'interrupt',
 *   memoryTracking: true,
 *   trustOverrides: [
 *     { toolName: 'readDatabase', trustLevel: 'trusted' },
 *     { toolName: 'fetchUrl', trustLevel: 'untrusted' },
 *   ],
 *   threshold: 3,
 * }, ['sendEmail', 'postWebhook'], {
 *   memoryTools: [
 *     { toolName: 'writeMemory', operation: 'write' },
 *     { toolName: 'readMemory', operation: 'read' },
 *   ],
 * });
 * ```
 */
export function guard(
  executors: Record<string, RawToolExecutorFn>,
  config: CerberusConfig,
  outboundTools: readonly string[],
  memoryOptions?: MemoryGuardOptions,
): GuardResult {
  validateCerberusConfig(config, {
    outboundTools,
    memoryTools: memoryOptions?.memoryTools ?? [],
  });

  const session = createSession();
  const assessments: RiskAssessment[] = [];
  let lastOutcome: ToolExecutionOutcome | undefined;
  let lastIncident: IntelligenceIncidentEnvelope | undefined;

  // Initialize L4 resources when memory tracking is enabled
  const memoryTools = memoryOptions?.memoryTools ?? [];
  const useMemory = config.memoryTracking === true && memoryTools.length > 0;

  const graph = useMemory ? createContaminationGraph() : undefined;
  const ledger = useMemory
    ? createLedger({
        ...(memoryOptions?.dbPath ? { dbPath: memoryOptions.dbPath } : {}),
      })
    : undefined;

  const wrappedExecutors: Record<string, ToolExecutorFn> = {};

  for (const [toolName, executor] of Object.entries(executors)) {
    wrappedExecutors[toolName] = interceptToolCall(
      toolName,
      executor,
      session,
      config,
      outboundTools,
      (assessment) => {
        assessments.push(assessment);
      },
      (outcome) => {
        lastOutcome = outcome;
        const latestAssessment = assessments[assessments.length - 1];
        if (latestAssessment) {
          lastIncident = buildIntelligenceIncidentEnvelope(session, latestAssessment, outcome);
        }
      },
      useMemory ? memoryTools : undefined,
      graph,
      ledger,
    );
  }

  // Reset clears session + assessments but preserves graph/ledger (cross-session persistence)
  const reset = (): void => {
    resetSession(session);
    assessments.length = 0;
    lastOutcome = undefined;
    lastIncident = undefined;
  };

  // Destroy tears down everything including DB connection
  const destroy = (): void => {
    ledger?.close();
    graph?.clear();
  };

  // Register a tool at runtime with full security checks
  const registerTool = (
    tool: ToolSchema,
    reason: string,
    authorizedBy: string,
  ): ToolRegistrationResult => {
    return registerToolLate(tool, reason, authorizedBy, session);
  };

  return {
    executors: wrappedExecutors,
    session,
    assessments,
    getLastOutcome: () => lastOutcome,
    getLastIncident: () => lastIncident,
    reset,
    ...(graph ? { graph } : {}),
    ...(ledger ? { ledger } : {}),
    destroy,
    registerTool,
  };
}
