import type { RiskAction } from './signals.js';

/** Where Cerberus made the execution decision for a tool call. */
export type ToolExecutionPhase = 'preflight' | 'post-execution' | 'context-window';

/** Structured outcome for the most recent guarded tool invocation. */
export interface ToolExecutionOutcome {
  /** Unique turn identifier for this invocation. */
  readonly turnId: string;
  /** Tool that was invoked. */
  readonly toolName: string;
  /** Final Cerberus action for the turn. */
  readonly action: RiskAction;
  /** Correlated risk score for the turn. */
  readonly score: number;
  /** Whether Cerberus blocked the tool result. */
  readonly blocked: boolean;
  /** Whether the underlying executor actually ran. */
  readonly executorRan: boolean;
  /** Stage where Cerberus made the decision. */
  readonly phase: ToolExecutionPhase;
}

/** Format a stable blocked-tool message for string-based integrations. */
export function formatBlockedToolMessage(outcome: ToolExecutionOutcome): string {
  const timing = outcome.executorRan ? 'after execution' : 'before execution';
  return `[Cerberus] Tool call blocked ${timing} — risk score ${String(outcome.score)}/4`;
}
