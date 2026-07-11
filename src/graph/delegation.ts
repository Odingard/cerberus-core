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
 * Depends on: src/crypto/signer.ts
 */

import { createHash } from 'node:crypto';

import type { Signer, SignerVerifier, Verifier } from '../crypto/signer.js';
import { getDefaultSigner } from '../crypto/signer.js';
import type { AuthorityGrant, CanonicalGrant } from './authority-grant.js';
import { canonicalGrant, hasGrant } from './authority-grant.js';

/** Type guard — does `s` expose a `verify()` method? */
function hasVerify(s: Signer | SignerVerifier): s is SignerVerifier {
  return 'verify' in s && typeof s.verify === 'function';
}

// ── Types ───────────────────────────────────────────────────────────

/** Agent type in a multi-agent system. */
export type AgentType = 'orchestrator' | 'subagent' | 'tool_agent';

/**
 * Effective per-layer enforcement mode in force when a manifest was signed.
 * `record-only` observes/logs without interrupting; `flag` alerts without
 * interrupting; `block` interrupts. Derived from the deployment's `AlertMode`
 * plus the always-fail-closed INTEGRITY rule.
 */
export type EnforcementMode = 'record-only' | 'flag' | 'block';

/**
 * Pipeline layer identifiers whose enforcement posture is attested into the
 * signed receipt. `INTEGRITY` is the always-fail-closed manifest/crypto layer.
 */
export type EnforcementLayer = 'L1' | 'L2' | 'L3' | 'L4' | 'INTEGRITY';

/**
 * Per-layer enforcement posture in force when the manifest was signed. Bound
 * into the signed payload (3a) so the receipt attests *what enforcement
 * authority was in force*, not just what was protected. Only the configured
 * posture is bound at signing time — the dynamic per-signal `EnforcementAction`
 * chosen by the gateway at runtime post-dates the receipt and is NOT bound.
 */
export type EnforcementPosture = Readonly<Partial<Record<EnforcementLayer, EnforcementMode>>>;

/**
 * Minimal-but-extensible signed human-acknowledgement evidence (3c). When
 * present it is part of the signed canonical payload, so tampering any field
 * breaks integrity. Attests *who acknowledged, when, and for which incident*,
 * and that the record was not tampered — it does NOT attest the soundness of
 * the human's decision. Extensible with `reason` / `decision` later without a
 * payload version bump being required for the absent-field case.
 */
export interface HumanAck {
  readonly ackBy: string;
  readonly ackAt: number;
  readonly incidentId: string;
}

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
  /**
   * Optional purpose-bound / time-bound authority grant scoping this delegated
   * edge (Track B #3). Enforced at the turn gate against the injected turn
   * context. Absent on legacy/unsigned edges.
   */
  readonly grant?: AuthorityGrant;
  /**
   * Hex-encoded signature over the edge's canonical payload (Track B #4). When
   * present, `verifyGraphIntegrity` verifies it, so the edge's bound grant is
   * covered by cryptography, not only the structural graph check. Absent on
   * legacy edges created via {@link addAgent}, which stay structurally checked.
   */
  readonly signature?: string;
  /** Algorithm that produced {@link signature}. */
  readonly algorithm?: string;
  /** Key identifier for the signer that produced {@link signature}. */
  readonly keyId?: string;
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
  /**
   * Commitment (SHA-256 hex) over the tool-coverage report in force when this
   * manifest was signed — bound into the signed payload so the receipt attests
   * *what was protected*, not just the authorization decision. Empty string
   * when no coverage was bound (a manifest created via the low-level primitive
   * directly, outside `guardMultiAgent`). Recompute with
   * `computeCoverageCommitment(result.coverage)` and compare to verify.
   */
  readonly coverageCommitment: string;
  /**
   * Per-layer enforcement posture in force at signing time, bound into the
   * signed payload (3a). Absent when no posture was supplied (low-level
   * callers). When present, a tampered mode flips `verifyGraphIntegrity` to
   * `false`.
   */
  readonly enforcementPosture?: EnforcementPosture;
  /**
   * Optional signed human-acknowledgement evidence (3c). Absent when no human
   * ack was recorded. When present, it is part of the signed payload, so any
   * tampered field fails integrity.
   */
  readonly humanAck?: HumanAck;
  /**
   * Optional purpose-bound / time-bound authority grant on the root manifest
   * (Track B #3). Bound into the signed payload when present (bumping the
   * payload to v:4); absent leaves the payload byte-identical to the v:3 form,
   * so no-grant manifests are unchanged (pre-reg invariant I5). Enforced at the
   * turn gate against the injected turn context.
   */
  readonly grant?: AuthorityGrant;
}

/** Options bundle for the optional receipt bindings (enforcement posture,
 *  human-ack) and the optional authority grant. */
export interface DelegationGraphOptions {
  readonly enforcementPosture?: EnforcementPosture;
  readonly humanAck?: HumanAck;
  readonly grant?: AuthorityGrant;
}

// ── Internal helpers ────────────────────────────────────────────────

/**
 * Deterministically canonicalize a per-layer enforcement posture as a sorted
 * `[layer, mode]` array, so the signed preimage is order-independent and
 * `exactOptionalPropertyTypes`-safe. An absent posture canonicalizes to `[]`.
 */
function canonicalPosture(posture: EnforcementPosture | undefined): Array<[string, string]> {
  if (!posture) {
    return [];
  }
  return (Object.entries(posture) as Array<[string, EnforcementMode | undefined]>)
    .filter((entry): entry is [string, EnforcementMode] => entry[1] !== undefined)
    .map(([layer, mode]): [string, string] => [layer, mode])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

/**
 * Canonicalize an optional human-ack into a fixed-field-order object (or `null`
 * when absent) for the signed preimage.
 */
function canonicalAck(
  ack: HumanAck | undefined,
): { ackBy: string; ackAt: number; incidentId: string } | null {
  if (!ack) {
    return null;
  }
  return { ackBy: ack.ackBy, ackAt: ack.ackAt, incidentId: ack.incidentId };
}

/**
 * Canonical JSON payload that gets signed. Binding includes the
 * session/root identity, the declared tools of the root agent (the capability
 * surface), the coverage commitment (what protection was actually in force),
 * the per-layer enforcement posture (3a — what authority was in force), and the
 * optional human-ack (3c — who acknowledged), so the signature cannot be
 * replayed to assert a different capability surface, coverage posture,
 * enforcement posture, OR acknowledgement.
 */
function canonicalPayload(
  sessionId: string,
  rootAgentId: string,
  rootDeclaredTools: readonly string[],
  algorithm: string,
  keyId: string,
  coverageCommitment: string,
  enforcementPosture: EnforcementPosture | undefined,
  humanAck: HumanAck | undefined,
  grant: AuthorityGrant | undefined,
): string {
  const base = {
    v: 3,
    sessionId,
    rootAgentId,
    rootDeclaredTools: [...rootDeclaredTools].sort(),
    algorithm,
    keyId,
    coverageCommitment,
    enforcementPosture: canonicalPosture(enforcementPosture),
    humanAck: canonicalAck(humanAck),
  };
  const g: CanonicalGrant | null = canonicalGrant(grant);
  if (g === null) {
    // No grant → byte-identical to the pre-grant v:3 payload (invariant I5).
    return JSON.stringify(base);
  }
  // Present grant → v:4 payload; `v` keeps its leading position, grant appended.
  return JSON.stringify({ ...base, v: 4, grant: g });
}

/**
 * Canonical JSON payload signed per delegation edge (Track B #4). Binds the
 * session, the from/to agents, the handoff context fingerprint, the edge's
 * authority grant, and the signer identity, so the edge — and its grant —
 * cannot be tampered or replayed without breaking the edge signature.
 */
function canonicalEdgePayload(
  sessionId: string,
  fromAgentId: string,
  toAgentId: string,
  contextFingerprint: string,
  algorithm: string,
  keyId: string,
  grant: AuthorityGrant | undefined,
): string {
  return JSON.stringify({
    v: 1,
    kind: 'edge',
    sessionId,
    fromAgentId,
    toAgentId,
    contextFingerprint,
    algorithm,
    keyId,
    grant: canonicalGrant(grant),
  });
}

/**
 * Associate each graph with the Verifier needed to check its signature.
 * Stored in a WeakMap so the association is cleaned up with the graph
 * and never appears in any serialized form.
 */
const graphVerifiers = new WeakMap<DelegationGraph, Verifier>();

/**
 * Look up the Verifier associated with a graph, if any. Returns `undefined`
 * when the graph was constructed outside of {@link createDelegationGraph}
 * (e.g. deserialized across a process boundary) or when no verifier was
 * registered at creation time.
 *
 * Used by the per-turn manifest gate to distinguish "no verifier available"
 * from "verifier rejected the signature" for diagnostic purposes.
 */
export function getGraphVerifier(graph: DelegationGraph): Verifier | undefined {
  return graphVerifiers.get(graph);
}

/** Compute SHA-256 hash of context passed at handoff. */
export function computeContextFingerprint(context: string): string {
  return createHash('sha256').update(context).digest('hex');
}

// ── Public API ──────────────────────────────────────────────────────

/**
 * Create a new delegation graph with a root agent. The graph is signed
 * with the provided signer (or the process default Ed25519 signer).
 *
 * @param sessionId - Session identifier
 * @param rootAgent - The root/orchestrator agent
 * @param signer - Optional signer; defaults to `getDefaultSigner()`
 * @param coverageCommitment - Optional commitment over the tool-coverage report
 *   in force (see `computeCoverageCommitment`). Bound into the signed payload so
 *   the manifest attests what was protected. Defaults to `''` (no coverage
 *   bound) for low-level callers; `guardMultiAgent` always supplies the real
 *   commitment.
 * @param options - Optional v:3 receipt bindings: `enforcementPosture` (3a,
 *   per-layer enforcement mode in force) and `humanAck` (3c, signed human
 *   acknowledgement). Both are bound into the signed payload when present.
 */
export function createDelegationGraph(
  sessionId: string,
  rootAgent: Omit<AgentNode, 'parentAgentId'>,
  signer?: Signer | SignerVerifier,
  coverageCommitment = '',
  options: DelegationGraphOptions = {},
): DelegationGraph {
  const effectiveSigner: Signer | SignerVerifier = signer ?? getDefaultSigner();

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
    coverageCommitment,
    options.enforcementPosture,
    options.humanAck,
    options.grant,
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
    coverageCommitment,
    ...(options.enforcementPosture ? { enforcementPosture: options.enforcementPosture } : {}),
    ...(options.humanAck ? { humanAck: options.humanAck } : {}),
    ...(hasGrant(options.grant) ? { grant: options.grant } : {}),
  };

  // Register a verifier ONLY when the signer can also verify (HmacSigner,
  // Ed25519Signer — the same-process sign-and-verify case). A sign-only
  // adapter (e.g. a KMS/HSM that holds the private key and exposes no
  // verify()) has a different key identity than getDefaultSigner(), so
  // falling back to the default would store a verifier whose algorithm/keyId
  // can never match this graph — silently blocking every subsequent turn.
  // Instead we register nothing, so the manifest gate reports the diagnosable
  // VERIFIER_MISSING and the caller must supply an explicit Verifier
  // (e.g. an Ed25519Verifier built from the KMS public key).
  if (hasVerify(effectiveSigner)) {
    graphVerifiers.set(graph, effectiveSigner);
  }

  return graph;
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
 * Add an agent node with a *cryptographically signed* delegation edge (Track B
 * #4). Behaves like {@link addAgent} but signs the edge's canonical payload
 * (including its optional authority grant) with the supplied signer (or the
 * process default). The edge signature is then covered by
 * {@link verifyGraphIntegrity}, so a delegated-edge grant is protected by
 * cryptography, not only the structural graph check.
 *
 * @param edgeGrant - Optional purpose-/time-bound grant scoping this edge.
 * @param signer - Optional signer; defaults to `getDefaultSigner()`. Should be
 *   the same key identity used for the manifest so the graph verifier can check
 *   both.
 */
export function addSignedAgent(
  graph: DelegationGraph,
  agent: Omit<AgentNode, 'parentAgentId'>,
  parentId: string,
  context: string,
  edgeGrant?: AuthorityGrant,
  signer?: Signer | SignerVerifier,
): boolean {
  const parent = graph.nodes.get(parentId);
  if (!parent) {
    return false;
  }
  const effectiveSigner: Signer | SignerVerifier = signer ?? getDefaultSigner();

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

  const contextFingerprint = computeContextFingerprint(context);
  const edgePayload = canonicalEdgePayload(
    graph.sessionId,
    parentId,
    agent.agentId,
    contextFingerprint,
    effectiveSigner.algorithm,
    effectiveSigner.keyId,
    edgeGrant,
  );
  const edge: DelegationEdge = {
    fromAgentId: parentId,
    toAgentId: agent.agentId,
    contextFingerprint,
    riskStateAtHandoff: parent.riskState,
    timestamp: Date.now(),
    ...(hasGrant(edgeGrant) ? { grant: edgeGrant } : {}),
    signature: effectiveSigner.sign(edgePayload),
    algorithm: effectiveSigner.algorithm,
    keyId: effectiveSigner.keyId,
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
export function verifyGraphIntegrity(graph: DelegationGraph, verifier?: Verifier): boolean {
  const resolved: Verifier | undefined = verifier ?? graphVerifiers.get(graph);
  if (!resolved) {
    return false;
  }
  if (resolved.algorithm !== graph.algorithm || resolved.keyId !== graph.keyId) {
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
    graph.coverageCommitment,
    graph.enforcementPosture,
    graph.humanAck,
    graph.grant,
  );
  if (!resolved.verify(payload, graph.signature)) {
    return false;
  }

  // Per-edge signing (Track B #4). Only edges that carry a signature are
  // verified — legacy edges from `addAgent` have none and stay structurally
  // checked, so existing behaviour is unchanged (invariant I5). A signed edge
  // with a mismatched key/algorithm or a tampered bound field fails closed.
  for (const edge of graph.edges) {
    if (edge.signature === undefined) {
      continue;
    }
    if (edge.algorithm !== resolved.algorithm || edge.keyId !== resolved.keyId) {
      return false;
    }
    const edgePayload = canonicalEdgePayload(
      graph.sessionId,
      edge.fromAgentId,
      edge.toAgentId,
      edge.contextFingerprint,
      edge.algorithm,
      edge.keyId,
      edge.grant,
    );
    if (!resolved.verify(edgePayload, edge.signature)) {
      return false;
    }
  }

  return true;
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
