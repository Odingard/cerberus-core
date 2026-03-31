/**
 * OpenAI Agents SDK Adapter — createCerberusGuardrail()
 *
 * Creates a tool-level guardrail compatible with the OpenAI Agents SDK's
 * ToolInputGuardrailDefinition pattern. The guardrail runs Cerberus
 * detection on tool inputs and returns { tripwireTriggered: true }
 * when the cumulative risk score exceeds the threshold.
 *
 * Uses structural interfaces (duck typing) — no hard dependency on @openai/agents.
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

/** Output shape for an OpenAI Agents SDK guardrail. */
export interface GuardrailFunctionOutput {
  /** Arbitrary info for logging/inspection. */
  readonly outputInfo: {
    readonly turnId: string;
    readonly score: number;
    readonly action: string;
    readonly vector: {
      readonly l1: boolean;
      readonly l2: boolean;
      readonly l3: boolean;
      readonly l4: boolean;
    };
  };
  /** When true, the SDK throws ToolInputGuardrailTripwireTriggered. */
  readonly tripwireTriggered: boolean;
}

/** Configuration for the OpenAI Agents SDK adapter. */
export interface OpenAIAgentsGuardConfig {
  /** Core Cerberus configuration. */
  readonly cerberus: CerberusConfig;
  /** Tool names that send data externally (for L3 detection). */
  readonly outboundTools?: readonly string[];
  /** Tool names and their execute functions. */
  readonly tools: Record<string, (args: Record<string, unknown>) => Promise<ToolExecutorResult>>;
  /** Optional L4 memory contamination tracking. */
  readonly memoryOptions?: MemoryGuardOptions;
}

/** Result of creating the Cerberus guardrail. */
export interface OpenAIAgentsGuardrailResult {
  /** Guardrail name. */
  readonly name: string;
  /** Execute function — call this for each tool invocation. */
  readonly execute: (context: {
    readonly toolName: string;
    readonly toolInput: Record<string, unknown>;
  }) => Promise<GuardrailFunctionOutput>;
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
 * Create an OpenAI Agents SDK guardrail backed by Cerberus detection.
 *
 * @example
 * ```typescript
 * import { createCerberusGuardrail } from '@cerberus-ai/core';
 *
 * const guardrail = createCerberusGuardrail({
 *   cerberus: { alertMode: 'interrupt', threshold: 3 },
 *   outboundTools: ['sendEmail'],
 *   tools: {
 *     readDatabase: async (args) => fetchFromDB(args),
 *     sendEmail: async (args) => sendEmail(args),
 *   },
 * });
 *
 * // Attach to agent's tool guardrails
 * const agent = new Agent({
 *   toolInputGuardrails: [{
 *     name: guardrail.name,
 *     execute: ({ toolName, toolInput }) =>
 *       guardrail.execute({ toolName, toolInput }),
 *   }],
 * });
 * ```
 */
export function createCerberusGuardrail(
  config: OpenAIAgentsGuardConfig,
): OpenAIAgentsGuardrailResult {
  const guardResult = guard(
    config.tools,
    config.cerberus,
    config.outboundTools ?? [],
    config.memoryOptions,
  );

  const execute = async (context: {
    readonly toolName: string;
    readonly toolInput: Record<string, unknown>;
  }): Promise<GuardrailFunctionOutput> => {
    const executor = guardResult.executors[context.toolName];
    if (!executor) {
      // Unknown tool — pass through, no tripwire
      return {
        outputInfo: {
          turnId: 'unknown',
          score: 0,
          action: 'none',
          vector: { l1: false, l2: false, l3: false, l4: false },
        },
        tripwireTriggered: false,
      };
    }

    // Execute the tool through the guarded pipeline
    await executor(context.toolInput);
    const outcome = guardResult.getLastOutcome();

    // Get the latest assessment
    const latestAssessment = guardResult.assessments[guardResult.assessments.length - 1];

    return {
      outputInfo: {
        turnId: latestAssessment?.turnId ?? 'unknown',
        score: latestAssessment?.score ?? 0,
        action: latestAssessment?.action ?? 'none',
        vector: latestAssessment?.vector ?? { l1: false, l2: false, l3: false, l4: false },
      },
      tripwireTriggered: outcome?.blocked === true,
    };
  };

  return {
    name: 'cerberus-runtime-guardrail',
    execute,
    session: guardResult.session,
    assessments: guardResult.assessments,
    reset: guardResult.reset,
    destroy: guardResult.destroy,
    ...(guardResult.graph ? { graph: guardResult.graph } : {}),
    ...(guardResult.ledger ? { ledger: guardResult.ledger } : {}),
  };
}
