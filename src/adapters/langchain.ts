/**
 * LangChain Adapter — guardLangChain()
 *
 * Wraps LangChain-compatible tool objects with the Cerberus detection pipeline.
 * Uses a structural interface (duck typing) so there is no hard dependency
 * on @langchain/core — any tool with { name, invoke() } works.
 *
 * Depends on: src/middleware/wrap.ts
 */

import type { CerberusConfig } from '../types/config.js';
import type { RiskAssessment } from '../types/signals.js';
import type { DetectionSession } from '../engine/session.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { guard } from '../middleware/wrap.js';
import type { MemoryGuardOptions } from '../middleware/wrap.js';

/**
 * Minimal structural interface a tool must satisfy.
 * Matches LangChain's StructuredTool / DynamicStructuredTool.
 */
export interface LangChainTool {
  readonly name: string;
  invoke(input: Record<string, unknown>): Promise<string>;
}

/** Configuration for the LangChain adapter. */
export interface LangChainGuardConfig {
  /** Core Cerberus configuration (alertMode, threshold, trustOverrides, etc.). */
  readonly cerberus: CerberusConfig;
  /** Tool names that send data externally (for L3 exfiltration detection). */
  readonly outboundTools?: readonly string[];
  /** Optional L4 memory contamination tracking. */
  readonly memoryOptions?: MemoryGuardOptions;
}

/** Result of wrapping LangChain tools with Cerberus detection. */
export interface LangChainGuardResult {
  /** Wrapped tool instances — pass these to AgentExecutor in place of originals. */
  readonly tools: readonly LangChainTool[];
  /** Live session state (readable). */
  readonly session: DetectionSession;
  /** All risk assessments produced during the session. */
  readonly assessments: readonly RiskAssessment[];
  /** Reset session state and assessments. Graph/ledger persist. */
  readonly reset: () => void;
  /** Tear down all resources (close DB, clear graph). */
  readonly destroy: () => void;
  /** Contamination graph (present when memoryTracking is enabled). */
  readonly graph?: ContaminationGraph;
  /** Provenance ledger (present when memoryTracking is enabled). */
  readonly ledger?: ProvenanceLedger;
}

/**
 * Wrap LangChain tool objects with Cerberus detection middleware.
 *
 * @param tools - Array of LangChain-compatible tool objects
 * @param config - Adapter configuration wrapping CerberusConfig
 * @returns LangChainGuardResult with wrapped tools and session handle
 *
 * @example
 * ```typescript
 * import { guardLangChain } from '@cerberus-ai/core';
 *
 * const result = guardLangChain(myLangChainTools, {
 *   cerberus: {
 *     alertMode: 'interrupt',
 *     threshold: 3,
 *     trustOverrides: [
 *       { toolName: 'readDatabase', trustLevel: 'trusted' },
 *       { toolName: 'fetchUrl', trustLevel: 'untrusted' },
 *     ],
 *   },
 *   outboundTools: ['sendEmail'],
 * });
 *
 * // Use result.tools with LangChain AgentExecutor
 * ```
 */
export function guardLangChain(
  tools: readonly LangChainTool[],
  config: LangChainGuardConfig,
): LangChainGuardResult {
  // Build executor map: tool name → (args) => tool.invoke(args)
  const executors: Record<string, (args: Record<string, unknown>) => Promise<string>> = {};
  for (const tool of tools) {
    executors[tool.name] = (args: Record<string, unknown>): Promise<string> => tool.invoke(args);
  }

  // Delegate to core guard()
  const guardResult = guard(
    executors,
    config.cerberus,
    config.outboundTools ?? [],
    config.memoryOptions,
  );

  // Wrap executors back into tool-shaped objects
  const wrappedTools: LangChainTool[] = tools.map((tool) => ({
    name: tool.name,
    invoke: (input: Record<string, unknown>) => guardResult.executors[tool.name](input),
  }));

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
