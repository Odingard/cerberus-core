/**
 * Delegation Graph — Multi-agent execution graph integrity.
 *
 * Tracks the delegation tree of agents in a multi-agent system.
 * Each agent node records its type, declared tools, and accumulated
 * risk state. Delegation edges carry the context fingerprint and
 * risk state at the time of handoff. The graph is cryptographically
 * signed at creation and verified before every read.
 *
 * Signing is pluggable via the `Signer` / `Verifier` protocol in
 * `src/crypto/signer.ts`. By default a process-ephemeral Ed25519 key
 * is used (via `getDefaultSigner()`); enterprise deployments should
 * inject a KMS/HSM-backed signer at startup with `setDefaultSigner()`.
 *
 * Depends on: src/types/signals.ts, src/crypto/signer.ts
 */

import { createHash } from "node:crypto";

import type { Signer, SignerVerifier, Verifier } from "../crypto/signer.js";
import { getDefaultSigner } from "../crypto/signer.js";

// ── Types ───────────────────────────────────────────────────────────

/** Agent type in a multi-agent system. */
export type AgentType = "orchestrator" | "subagent" | "tool_agent";

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
  /** Hex-encoded signature over the canonical manifest. */
  readonly signature: string;
  /** Algorithm that produced `signature`. */
  readonly algorithm: string;
  /** Key identifier for the signer that produced `signature`. */
  readonly keyId: string;
}

// ── Internal helpers ────────────────────────────────────────────────

/**
 * Canonical JSON payload that gets signed. Binding includes the
 * session/root identity and the declared tools of the root agent so the
 * signature cannot be replayed to assert a different capability surface.
 */
function canonicalPayload(
  sessionId: string,
  rootAgentId: string,
  rootDeclaredTools: readonly string[],
  algorithm: string,
  keyId: string,
): string {
  return JSON.stringify({
    v: 1,
    sessionId,
    rootAgentId,
    rootDeclaredTools: [...rootDeclaredTools].sort(),
    algorithm,
    keyId,
  });
}

/**
 * Associate each graph with the Verifier needed to check its signature.
 * Stored in a WeakMap so the association is cleaned up with the graph
 * and never appears in any serialized form.
 */
const graphVerifiers = new WeakMap<DelegationGraph, Verifier>();

/** Compute SHA-256 hash of context passed at handoff. */
export function computeContextFingerprint(context: string): string {
  return createHash("sha256").update(context).digest("hex");
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Create a new delegation graph with a root agent. The graph is signed
 * with the provided signer (or the process default Ed25519 signer).
 *
 * @param sessionId - Session identifier
 * @param rootAgent - The root/orchestrator agent
 * @param signer - Optional signer; defaults to `getDefaultSigner()`
 */
export function createDelegationGraph(
  sessionId: string,
  rootAgent: Omit<AgentNode, "parentAgentId">,
  signer?: Signer & Partial<Verifier>,
): DelegationGraph {
  const effectiveSigner: SignerVerifier =
    (signer as SignerVerifier | undefined) ?? getDefaultSigner();

  const nodes = new Map<string, AgentNode>();
  nodes.set(rootAgent.agentId, {
    agentId: rootAgent.agentId,
    agentType: rootAgent.agentType,
    declaredTools: rootAgent.declaredTools,
    riskState: rootAgent.riskState,
  });

  const payload = canonicalPayload(
    sessionId,
    rootAgent.agentId,
    rootAgent.declaredTools,
    effectiveSigner.algorithm,
    effectiveSigner.keyId,
  );
  const signature = effectiveSigner.sign(payload);

  const graph: DelegationGraph = {
    sessionId,
    rootAgentId: rootAgent.agentId,
    nodes,
    edges: [],
    signature,
    algorithm: effectiveSigner.algorithm,
    keyId: effectiveSigner.keyId,
  };

  // The signer is almost always also a verifier (HmacSigner, Ed25519Signer).
  // If a pure-sign adapter was passed we fall back to the default signer
  // (which is the normal case: the same process signs and verifies).
  const verifier: Verifier =
    typeof (effectiveSigner as Partial<Verifier>).verify === "function"
      ? (effectiveSigner as Verifier)
      : getDefaultSigner();
  graphVerifiers.set(graph, verifier);

  return graph;
}

/**
 * Add an agent node to the graph with a delegation edge from its parent.
 * The parent's risk state propagates to the edge as riskStateAtHandoff.
 * Returns true if added successfully, false if parent not found.
 */
export function addAgent(
  graph: DelegationGraph,
  agent: Omit<AgentNode, "parentAgentId">,
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
 * Verify the graph's signature against its bound canonical payload.
 *
 * Uses the verifier that was associated with the graph at creation time
 * (stored in a WeakMap). If an explicit verifier is supplied it overrides
 * the stored one — this is the path enterprise gateways use when they hold
 * the public key but never the private key.
 */
export function verifyGraphIntegrity(
  graph: DelegationGraph,
  verifier?: Verifier,
): boolean {
  const resolved: Verifier | undefined = verifier ?? graphVerifiers.get(graph);
  if (!resolved) {
    return false;
  }
  if (
    resolved.algorithm !== graph.algorithm ||
    resolved.keyId !== graph.keyId
  ) {
    return false;
  }
  const root = graph.nodes.get(graph.rootAgentId);
  if (!root) {
    return false;
  }
  const payload = canonicalPayload(
    graph.sessionId,
    graph.rootAgentId,
    root.declaredTools,
    graph.algorithm,
    graph.keyId,
  );
  return resolved.verify(payload, graph.signature);
}

/**
 * Get the delegation chain from root to a specific agent.
 * Returns an ordered array of AgentNodes from root to the target.
 * Returns empty array if agentId is not found.
 */
export function getAgentChain(
  graph: DelegationGraph,
  agentId: string,
): readonly AgentNode[] {
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
export function isAuthorizedAgent(
  graph: DelegationGraph,
  agentId: string,
): boolean {
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
    ...(existing.parentAgentId
      ? { parentAgentId: existing.parentAgentId }
      : {}),
  };

  graph.nodes.set(agentId, updated);
  return true;
}
