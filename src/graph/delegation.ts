/**
 * Delegation Graph — Multi-agent execution graph integrity.
 *
 * Tracks the delegation tree of agents in a multi-agent system.
 * Each agent node records its type, declared tools, and accumulated
 * risk state. Delegation edges carry the context fingerprint and
 * risk state at the time of handoff. The graph is HMAC-signed at
 * creation and verified before every read.
 *
 * Depends on: src/types/signals.ts
 */

import { createHmac } from 'node:crypto';
import { createHash } from 'node:crypto';

// ── Types ───────────────────────────────────────────────────────────

/** Agent type in a multi-agent system. */
export type AgentType = 'orchestrator' | 'subagent' | 'tool_agent';

/** Per-layer risk state (L1/L2/L3 booleans). */
export interface RiskState {
  readonly l1: boolean;
  readonly l2: boolean;
  readonly l3: boolean;
}

/** A node representing an agent in the delegation graph. */
export interface AgentNode {
  readonly agentId: string;
  readonly agentType: AgentType;
  readonly declaredTools: readonly string[];
  readonly riskState: RiskState;
  readonly parentAgentId?: string;
}

/** A directed edge recording delegation from one agent to another. */
export interface DelegationEdge {
  readonly fromAgentId: string;
  readonly toAgentId: string;
  readonly contextFingerprint: string;
  readonly riskStateAtHandoff: RiskState;
  readonly timestamp: number;
}

/** The delegation graph tracking agent relationships. */
export interface DelegationGraph {
  readonly sessionId: string;
  readonly rootAgentId: string;
  readonly nodes: Map<string, AgentNode>;
  readonly edges: DelegationEdge[];
  readonly signature: string;
}

// ── Internal helpers ────────────────────────────────────────────────

/** Signing key — in production, inject via config. */
const HMAC_KEY = 'cerberus-delegation-graph-key';

/** Compute SHA-256 hash of context passed at handoff. */
export function computeContextFingerprint(context: string): string {
  return createHash('sha256').update(context).digest('hex');
}

/** Compute HMAC-SHA256 signature for the graph. */
function computeSignature(sessionId: string, rootAgentId: string): string {
  return createHmac('sha256', HMAC_KEY).update(`${sessionId}:${rootAgentId}`).digest('hex');
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Create a new delegation graph with a root agent.
 * The graph is HMAC-signed at creation.
 */
export function createDelegationGraph(
  sessionId: string,
  rootAgent: Omit<AgentNode, 'parentAgentId'>,
): DelegationGraph {
  const nodes = new Map<string, AgentNode>();
  nodes.set(rootAgent.agentId, {
    agentId: rootAgent.agentId,
    agentType: rootAgent.agentType,
    declaredTools: rootAgent.declaredTools,
    riskState: rootAgent.riskState,
  });

  const signature = computeSignature(sessionId, rootAgent.agentId);

  return {
    sessionId,
    rootAgentId: rootAgent.agentId,
    nodes,
    edges: [],
    signature,
  };
}

/**
 * Add an agent node to the graph with a delegation edge from its parent.
 * The parent's risk state propagates to the edge as riskStateAtHandoff.
 * Returns true if added successfully, false if parent not found.
 */
export function addAgent(
  graph: DelegationGraph,
  agent: Omit<AgentNode, 'parentAgentId'>,
  parentId: string,
  context: string,
): boolean {
  const parent = graph.nodes.get(parentId);
  if (!parent) {
    return false;
  }

  // Merge risk state: child inherits parent's risk flags
  const mergedRiskState: RiskState = {
    l1: agent.riskState.l1 || parent.riskState.l1,
    l2: agent.riskState.l2 || parent.riskState.l2,
    l3: agent.riskState.l3 || parent.riskState.l3,
  };

  const node: AgentNode = {
    agentId: agent.agentId,
    agentType: agent.agentType,
    declaredTools: agent.declaredTools,
    riskState: mergedRiskState,
    parentAgentId: parentId,
  };

  graph.nodes.set(agent.agentId, node);

  const edge: DelegationEdge = {
    fromAgentId: parentId,
    toAgentId: agent.agentId,
    contextFingerprint: computeContextFingerprint(context),
    riskStateAtHandoff: parent.riskState,
    timestamp: Date.now(),
  };

  graph.edges.push(edge);

  return true;
}

/**
 * Verify the graph's HMAC signature matches its session/root data.
 */
export function verifyGraphIntegrity(graph: DelegationGraph): boolean {
  const expected = computeSignature(graph.sessionId, graph.rootAgentId);
  return graph.signature === expected;
}

/**
 * Get the delegation chain from root to a specific agent.
 * Returns an ordered array of AgentNodes from root to the target.
 * Returns empty array if agentId is not found.
 */
export function getAgentChain(graph: DelegationGraph, agentId: string): readonly AgentNode[] {
  const node = graph.nodes.get(agentId);
  if (!node) {
    return [];
  }

  const chain: AgentNode[] = [];
  let current: AgentNode | undefined = node;

  while (current) {
    chain.unshift(current);
    if (current.parentAgentId) {
      current = graph.nodes.get(current.parentAgentId);
    } else {
      break;
    }
  }

  return chain;
}

/**
 * Check if an agent exists in the delegation graph.
 */
export function isAuthorizedAgent(graph: DelegationGraph, agentId: string): boolean {
  return graph.nodes.has(agentId);
}

/**
 * Update the risk state for a specific agent in the graph.
 * Returns true if agent found and updated, false otherwise.
 */
export function updateAgentRiskState(
  graph: DelegationGraph,
  agentId: string,
  riskState: RiskState,
): boolean {
  const existing = graph.nodes.get(agentId);
  if (!existing) {
    return false;
  }

  const updated: AgentNode = {
    agentId: existing.agentId,
    agentType: existing.agentType,
    declaredTools: existing.declaredTools,
    riskState,
    ...(existing.parentAgentId ? { parentAgentId: existing.parentAgentId } : {}),
  };

  graph.nodes.set(agentId, updated);
  return true;
}
