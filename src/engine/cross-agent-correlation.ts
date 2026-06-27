/**
 * Cross-Agent Correlation — Detects Lethal Trifecta across agent boundaries.
 *
 * In multi-agent systems, the Lethal Trifecta (L1+L2+L3) may be satisfied
 * across different agents in the delegation chain rather than within a single
 * agent. This module detects:
 *
 * 1. CROSS_AGENT_TRIFECTA — L1+L2+L3 satisfied across any connected agents
 * 2. CONTEXT_CONTAMINATION_PROPAGATION — L2 (injection) propagates through delegation edges
 * 3. UNAUTHORIZED_AGENT_SPAWN — Agent appears without a delegation edge
 *
 * Sub-classifiers are pure functions: (ctx, session) => Signal | null
 * Signals use existing layer tags — no new layers added.
 */

import type {
  CrossAgentTrifectaSignal,
  ContextContaminationSignal,
  UnauthorizedAgentSpawnSignal,
} from '../types/signals.js';
import type { DelegationGraph, RiskState } from '../graph/delegation.js';
import { getAgentChain, isAuthorizedAgent } from '../graph/delegation.js';

/**
 * Detect the Lethal Trifecta (L1+L2+L3) satisfied across agents in the
 * delegation chain. Checks whether ANY combination of agents in the chain
 * from root to currentAgentId collectively satisfies all three risk layers.
 */
export function detectCrossAgentTrifecta(
  graph: DelegationGraph,
  currentAgentId: string,
  currentRiskState: RiskState,
  turnId: string,
): CrossAgentTrifectaSignal | null {
  const chain = getAgentChain(graph, currentAgentId);
  if (chain.length === 0) {
    return null;
  }

  // Accumulate risk across the entire delegation chain
  let l1 = false;
  let l2 = false;
  let l3 = false;

  const contributingAgents: string[] = [];

  for (const node of chain) {
    // Use current risk state for the current agent (most up-to-date)
    const state = node.agentId === currentAgentId ? currentRiskState : node.riskState;

    if (state.l1) {
      l1 = true;
      contributingAgents.push(node.agentId);
    }
    if (state.l2) {
      l2 = true;
      if (!contributingAgents.includes(node.agentId)) {
        contributingAgents.push(node.agentId);
      }
    }
    if (state.l3) {
      l3 = true;
      if (!contributingAgents.includes(node.agentId)) {
        contributingAgents.push(node.agentId);
      }
    }
  }

  // Only fire when trifecta is satisfied AND spans multiple agents
  if (l1 && l2 && l3 && contributingAgents.length > 1) {
    return {
      layer: 'CROSS_AGENT',
      signal: 'CROSS_AGENT_TRIFECTA',
      turnId,
      contributingAgents,
      riskState: { l1, l2, l3 },
      timestamp: Date.now(),
    };
  }

  return null;
}

/**
 * Detect context contamination propagation — when an agent with L2 (injection)
 * delegates to a downstream agent, the contamination propagates along the edge.
 * Returns a signal if the current agent inherited L2 contamination from an
 * upstream agent via delegation.
 */
export function detectContextContamination(
  graph: DelegationGraph,
  currentAgentId: string,
  turnId: string,
): ContextContaminationSignal | null {
  const chain = getAgentChain(graph, currentAgentId);
  if (chain.length < 2) {
    return null;
  }

  // Check if any upstream agent (not the current one) had L2 active
  const currentNode = graph.nodes.get(currentAgentId);
  if (!currentNode) {
    return null;
  }

  const contaminationSources: string[] = [];

  for (const node of chain) {
    if (node.agentId === currentAgentId) {
      continue;
    }
    if (node.riskState.l2) {
      contaminationSources.push(node.agentId);
    }
  }

  // Also check delegation edges for L2 in riskStateAtHandoff
  for (const edge of graph.edges) {
    if (edge.toAgentId === currentAgentId && edge.riskStateAtHandoff.l2) {
      if (!contaminationSources.includes(edge.fromAgentId)) {
        contaminationSources.push(edge.fromAgentId);
      }
    }
  }

  if (contaminationSources.length > 0) {
    return {
      layer: 'CROSS_AGENT',
      signal: 'CONTEXT_CONTAMINATION_PROPAGATION',
      turnId,
      sourceAgentId: contaminationSources[0],
      contaminatedAgentId: currentAgentId,
      contaminationChain: contaminationSources,
      timestamp: Date.now(),
    };
  }

  return null;
}

/**
 * Detect unauthorized agent spawn — an agent that appears without
 * a delegation edge from a known agent in the graph.
 */
export function detectUnauthorizedAgentSpawn(
  graph: DelegationGraph,
  agentId: string,
  turnId: string,
): UnauthorizedAgentSpawnSignal | null {
  if (isAuthorizedAgent(graph, agentId)) {
    return null;
  }

  return {
    layer: 'CROSS_AGENT',
    signal: 'UNAUTHORIZED_AGENT_SPAWN',
    turnId,
    agentId,
    timestamp: Date.now(),
  };
}
