/**
 * Vercel AI SDK Adapter — guardVercelAI()
 *
 * Wraps Vercel AI SDK tool execute functions with the Cerberus detection
 * pipeline. Returns wrapped tool definitions that can be used directly
 * with generateText() / streamText().
 *
 * Uses structural interfaces (duck typing) — no hard dependency on 'ai'.
 *
 * Depends on: src/middleware/wrap.ts
 */

import type { CerberusConfig } from '../types/config.js';
import type { RiskAssessment } from '../types/signals.js';
import type { ToolExecutorResult } from '../engine/interceptor.js';
import type { DetectionSession } from '../engine/session.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { guard } from '../middleware/wrap.js';
import type { MemoryGuardOptions } from '../middleware/wrap.js';

/**
 * Minimal structural interface for a Vercel AI SDK tool.
 * Matches the shape returned by ai.tool().
 */
export interface VercelAITool {
  readonly description?: string;
  readonly parameters?: unknown;
  readonly execute?: (args: Record<string, unknown>) => Promise<ToolExecutorResult>;
}

/** A named map of Vercel AI tools, as used by generateText(). */
export type VercelAIToolMap = Record<string, VercelAITool>;

/** Configuration for the Vercel AI SDK adapter. */
export interface VercelAIGuardConfig {
  /** Core Cerberus configuration. */
  readonly cerberus: CerberusConfig;
  /** Tool names that send data externally (for L3 detection). */
  readonly outboundTools?: readonly string[];
  /** Optional L4 memory contamination tracking. */
  readonly memoryOptions?: MemoryGuardOptions;
}

/** Result of wrapping Vercel AI tools with Cerberus detection. */
export interface VercelAIGuardResult {
  /** Wrapped tool map — use this in generateText({ tools }) in place of originals. */
  readonly tools: VercelAIToolMap;
  /** Live session state. */
  readonly session: DetectionSession;
  /** All risk assessments produced. */
  readonly assessments: readonly RiskAssessment[];
  /** Reset session state and assessments. */
  readonly reset: () => void;
  /** Tear down resources. */
  readonly destroy: () => void;
  /** Contamination graph (present when memoryTracking is enabled). */
  readonly graph?: ContaminationGraph;
  /** Provenance ledger (present when memoryTracking is enabled). */
  readonly ledger?: ProvenanceLedger;
}

/**
 * Wrap Vercel AI SDK tools with Cerberus detection middleware.
 *
 * @example
 * ```typescript
 * import { guardVercelAI } from '@cerberus-ai/core';
 * import { generateText } from 'ai';
 *
 * const guarded = guardVercelAI(myTools, {
 *   cerberus: { alertMode: 'interrupt', threshold: 3 },
 *   outboundTools: ['sendEmail'],
 * });
 *
 * const result = await generateText({
 *   model: openai('gpt-4o'),
 *   tools: guarded.tools,
 *   prompt: 'Do something',
 * });
 * ```
 */
export function guardVercelAI(
  tools: VercelAIToolMap,
  config: VercelAIGuardConfig,
): VercelAIGuardResult {
  // Build executor map from tools that have execute functions
  const executors: Record<string, (args: Record<string, unknown>) => Promise<ToolExecutorResult>> =
    {};
  for (const [name, tool] of Object.entries(tools)) {
    if (tool.execute) {
      executors[name] = tool.execute;
    }
  }

  // Delegate to core guard()
  const guardResult = guard(
    executors,
    config.cerberus,
    config.outboundTools ?? [],
    config.memoryOptions,
  );

  // Reconstruct tool map with wrapped execute functions
  const wrappedTools: VercelAIToolMap = {};
  for (const [name, tool] of Object.entries(tools)) {
    if (tool.execute && guardResult.executors[name]) {
      wrappedTools[name] = {
        ...(tool.description !== undefined ? { description: tool.description } : {}),
        ...(tool.parameters !== undefined ? { parameters: tool.parameters } : {}),
        execute: (args: Record<string, unknown>): Promise<ToolExecutorResult> =>
          guardResult.executors[name](args),
      };
    } else {
      // Tools without execute are passed through unchanged
      wrappedTools[name] = tool;
    }
  }

  return {
    tools: wrappedTools,
    session: guardResult.session,
    assessments: guardResult.assessments,
    reset: guardResult.reset,
    destroy: guardResult.destroy,
    ...(guardResult.graph ? { graph: guardResult.graph } : {}),
    ...(guardResult.ledger ? { ledger: guardResult.ledger } : {}),
  };
}
