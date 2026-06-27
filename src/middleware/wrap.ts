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
import { createSession, resetSession, checkpointScope } from '../engine/session.js';
import { interceptToolCall } from '../engine/interceptor.js';
import type { RawToolExecutorFn, ToolExecutorFn } from '../engine/interceptor.js';
import { validateCerberusConfig } from '../engine/config-validation.js';
import { buildIntelligenceIncidentEnvelope } from '../engine/intelligence-envelope.js';
import type { MemoryToolConfig } from '../layers/l4-memory.js';
import type { MemoryTraceRecorder } from './trace-capture.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import { createContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { createInMemoryLedger } from '../graph/ledger.js';
import type { ToolSchema, ToolRegistrationResult } from '../engine/tool-registration.js';
import { registerToolLate } from '../engine/tool-registration.js';
import type { CoverageReport } from '../engine/coverage.js';
import { computeCoverageReport, formatCoverageWarning } from '../engine/coverage.js';

/** Options for L4 memory contamination tracking. */
export interface MemoryGuardOptions {
  /** Memory tool configurations (which tools are memory reads/writes). */
  readonly memoryTools?: readonly MemoryToolConfig[];
  /**
   * Path for a durable SQLite provenance ledger. Honored only when a durable
   * ledger is injected via {@link MemoryGuardOptions.ledger}; the basic
   * in-memory open ledger has no persistence and ignores it.
   */
  readonly dbPath?: string;
  /**
   * Inject a provenance ledger implementation (dependency inversion). Omitted ⇒
   * the basic in-memory open ledger (append-only provenance + in-session taint).
   * A paid deployment injects the durable SQLite ledger from
   * `@cerberus-ai/enterprise` (durable persistence, blast-radius B(p),
   * containment, the provenance-summary scale lever, and AL3 authorship).
   */
  readonly ledger?: ProvenanceLedger;
  /**
   * Opt-in trace recorder. When present, the guard captures the ordered
   * read/write/reset memory ops of this session in a replayable format (write
   * content is redacted by the recorder). Independent of `memoryTracking`:
   * capture works even with detection off, and is zero-cost when omitted.
   */
  readonly recorder?: MemoryTraceRecorder;
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
  /**
   * Reset the session state and assessments for reuse between runs. Graph/ledger
   * persist (cross-session). Rotates the sessionId for L4 cross-session
   * detection.
   *
   * `carriedReads` (optional) — the cross-session carry-channel hand-off
   * (Spec B): node IDs carried across the reset in context (summary injection,
   * orchestrator-passed state) that an instrumented channel recorded. They
   * SEED the rotated scope's observed reads so post-reset writes can anchor the
   * carried dependency edges — closing the carried-but-unread recall gap.
   * Omitted = the uninstrumented baseline (carried deps stay missed); a
   * genuinely untracked channel hands off nothing and is the documented
   * residual. The sessionId always rotates regardless.
   */
  readonly reset: (carriedReads?: Iterable<string>) => void;
  /**
   * Frontier checkpoint: clear ONLY the observed-read scope (a mini-reset of
   * the L4 dependency window) without rotating the sessionId or clearing any
   * other state. The §5.2 scope-window lever for bounding containment-DoS
   * blast: writes past the checkpoint can no longer claim reads from before it.
   */
  readonly checkpoint: () => void;
  /** Contamination graph (present when memoryTracking is enabled). */
  readonly graph?: ContaminationGraph;
  /** Provenance ledger (present when memoryTracking is enabled). */
  readonly ledger?: ProvenanceLedger;
  /**
   * Tool coverage report for this guard() invocation: per-tool L1/L3/L4
   * coverage, the tools declared in config but never wrapped (their protection
   * silently never runs), and the wrapped tools left at default `unknown`
   * trust. Assert on `coverage.hasUnwrappedDeclarations` in deployment checks.
   */
  readonly coverage: CoverageReport;
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

  // Surface tool coverage gaps before wrapping: a tool name declared in
  // trustOverrides / outboundTools / memoryTools with no matching executor has
  // its declared protection silently skipped. Never fail open silently — warn
  // loudly (default) or throw (strictCoverage).
  const coverage = computeCoverageReport({
    executorNames: Object.keys(executors),
    config,
    outboundTools,
    memoryTools: memoryOptions?.memoryTools ?? [],
  });
  const coverageWarning = formatCoverageWarning(coverage);
  if (coverageWarning) {
    if (config.strictCoverage === true) {
      throw new Error(coverageWarning);
    }
    // eslint-disable-next-line no-console
    console.warn(coverageWarning);
  }

  const session = createSession();
  const assessments: RiskAssessment[] = [];
  let lastOutcome: ToolExecutionOutcome | undefined;
  let lastIncident: IntelligenceIncidentEnvelope | undefined;

  // Initialize L4 resources when memory tracking is enabled
  const memoryTools = memoryOptions?.memoryTools ?? [];
  const useMemory = config.memoryTracking === true && memoryTools.length > 0;
  const recorder = memoryOptions?.recorder;

  const graph = useMemory ? createContaminationGraph() : undefined;
  // Provenance ledger (dependency inversion): use an injected durable ledger
  // (@cerberus-ai/enterprise) when provided, else the basic in-memory open
  // ledger — append-only provenance + in-session taint, no persistence/B(p)/scale.
  const ledger = useMemory
    ? (memoryOptions?.ledger ??
      createInMemoryLedger(memoryOptions?.dbPath ? { dbPath: memoryOptions.dbPath } : {}))
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
      // Pass the memory-tool list whenever it is configured (not gated on
      // useMemory): trace capture classifies reads/writes from it even when L4
      // detection is off. The L4 block itself stays gated on graph && ledger.
      memoryTools.length > 0 ? memoryTools : undefined,
      graph,
      ledger,
      recorder,
    );
  }

  // Reset clears session + assessments but preserves graph/ledger (cross-session
  // persistence). An optional carried read-set seeds the rotated scope so an
  // instrumented carry channel recovers cross-session deps (Spec B).
  const reset = (carriedReads?: Iterable<string>): void => {
    resetSession(session, carriedReads);
    assessments.length = 0;
    lastOutcome = undefined;
    lastIncident = undefined;
    // Capture the session boundary so a replayed trace rotates its read scope
    // exactly where the real agent did.
    recorder?.recordReset();
  };

  // Checkpoint clears only the observed-read scope (mini-reset), keeping the
  // session identity, assessments, graph and ledger intact.
  const checkpoint = (): void => {
    checkpointScope(session);
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
    checkpoint,
    ...(graph ? { graph } : {}),
    ...(ledger ? { ledger } : {}),
    coverage,
    destroy,
    registerTool,
  };
}
