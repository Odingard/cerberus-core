/**
 * Multi-Agent Guard API — Developer-facing entry point for multi-agent systems.
 *
 * Extends the standard guard() API with delegation graph tracking,
 * sub-agent spawning, and per-agent risk state inspection.
 */

import type { CerberusConfig } from '../types/config.js';
import type { ToolExecutorFn } from '../engine/interceptor.js';
import type { MemoryGuardOptions } from './wrap.js';
import type { DelegationGraph, AgentType, RiskState } from '../graph/delegation.js';
import {
  createDelegationGraph,
  addAgent,
  verifyGraphIntegrity,
  isAuthorizedAgent,
} from '../graph/delegation.js';
import { guard } from './wrap.js';
import type { GuardResult } from './wrap.js';

/** Result of spawning a sub-agent. */
export interface SpawnAgentResult {
  /** Whether the agent was successfully registered. */
  readonly success: boolean;
  /** Error message if spawn failed. */
  readonly error?: string;
}

/** Extended guard result for multi-agent systems. */
export interface MultiAgentGuardResult extends GuardResult {
  /**
   * Register a sub-agent in the delegation graph.
   * @param agentId - Unique identifier for the sub-agent
   * @param agentType - Type of agent (subagent or tool_agent)
   * @param tools - Tools the sub-agent is authorized to use
   * @param context - Context string passed at handoff (hashed for integrity)
   * @param parentAgentId - ID of the parent agent (defaults to root)
   */
  readonly spawnAgent: (
    agentId: string,
    agentType: AgentType,
    tools: readonly string[],
    context: string,
    parentAgentId?: string,
  ) => SpawnAgentResult;

  /** Get the current delegation graph. */
  readonly getDelegationGraph: () => DelegationGraph;

  /** Get the risk state for a specific agent. */
  readonly getAgentRiskState: (agentId: string) => RiskState | undefined;

  /**
   * Set the active agent for subsequent tool calls.
   * Updates session.currentAgentId so the pipeline knows which agent is executing.
   */
  readonly setActiveAgent: (agentId: string) => boolean;
}

/**
 * Create a multi-agent guard with delegation graph tracking.
 *
 * @param executors - Map of tool name to executor function
 * @param config - Cerberus configuration (must have multiAgent: true)
 * @param outboundTools - Names of tools that send data externally
 * @param rootAgentId - Unique ID for the root/orchestrator agent
 * @param memoryOptions - Optional L4 memory contamination tracking
 * @returns MultiAgentGuardResult with delegation management methods
 *
 * @example
 * ```typescript
 * const guarded = guardMultiAgent(myToolExecutors, {
 *   alertMode: 'interrupt',
 *   multiAgent: true,
 *   agentType: 'orchestrator',
 * }, ['sendEmail'], 'orchestrator-1');
 *
 * guarded.spawnAgent('research-agent', 'subagent', ['search', 'browse'], 'research task');
 * guarded.setActiveAgent('research-agent');
 * ```
 */
export function guardMultiAgent(
  executors: Record<string, ToolExecutorFn>,
  config: CerberusConfig,
  outboundTools: readonly string[],
  rootAgentId: string,
  memoryOptions?: MemoryGuardOptions,
): MultiAgentGuardResult {
  // Force multiAgent: true in the config
  const multiAgentConfig: CerberusConfig = {
    ...config,
    multiAgent: true,
  };

  const baseResult = guard(executors, multiAgentConfig, outboundTools, memoryOptions);
  const { session } = baseResult;

  // Create the delegation graph with the root agent
  const agentType = config.agentType ?? 'orchestrator';
  const declaredTools = Object.keys(executors);

  const delegationGraph = createDelegationGraph(session.sessionId, {
    agentId: rootAgentId,
    agentType,
    declaredTools,
    riskState: { l1: false, l2: false, l3: false },
  });

  // Attach graph to session so the interceptor can access it
  session.delegationGraph = delegationGraph;
  session.currentAgentId = rootAgentId;

  const spawnAgent = (
    agentId: string,
    spawnAgentType: AgentType,
    tools: readonly string[],
    context: string,
    parentAgentId?: string,
  ): SpawnAgentResult => {
    const parentId = parentAgentId ?? rootAgentId;

    // Verify graph integrity before mutation
    if (!verifyGraphIntegrity(delegationGraph)) {
      return { success: false, error: 'Graph integrity check failed' };
    }

    // Check for duplicate agent ID
    if (isAuthorizedAgent(delegationGraph, agentId)) {
      return { success: false, error: `Agent '${agentId}' already exists in the graph` };
    }

    const added = addAgent(
      delegationGraph,
      {
        agentId,
        agentType: spawnAgentType,
        declaredTools: tools,
        riskState: { l1: false, l2: false, l3: false },
      },
      parentId,
      context,
    );

    if (!added) {
      return { success: false, error: `Parent agent '${parentId}' not found in graph` };
    }

    return { success: true };
  };

  const getDelegationGraph = (): DelegationGraph => delegationGraph;

  const getAgentRiskState = (agentId: string): RiskState | undefined => {
    const node = delegationGraph.nodes.get(agentId);
    if (!node) {
      return undefined;
    }
    return node.riskState;
  };

  const setActiveAgent = (agentId: string): boolean => {
    if (!isAuthorizedAgent(delegationGraph, agentId)) {
      return false;
    }
    session.currentAgentId = agentId;
    return true;
  };

  return {
    ...baseResult,
    spawnAgent,
    getDelegationGraph,
    getAgentRiskState,
    setActiveAgent,
  };
}
