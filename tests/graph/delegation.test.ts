/**
 * Tests for the Delegation Graph — multi-agent execution graph integrity.
 */

import { describe, it, expect } from 'vitest';
import {
  createDelegationGraph,
  addAgent,
  verifyGraphIntegrity,
  getAgentChain,
  isAuthorizedAgent,
  computeContextFingerprint,
  updateAgentRiskState,
  getGraphVerifier,
} from '../../src/graph/delegation.js';
import type { DelegationGraph } from '../../src/graph/delegation.js';
import { Ed25519Signer, HmacSigner, getDefaultSigner } from '../../src/crypto/signer.js';
import type { Signer } from '../../src/crypto/signer.js';
import { computeCoverageReport, computeCoverageCommitment } from '../../src/engine/coverage.js';

/** A sign-only adapter (e.g. a KMS/HSM that never exposes verify()). */
class SignOnlySigner implements Signer {
  readonly algorithm = 'Ed25519';
  readonly keyId = 'kms:sign-only-key';
  private readonly inner = new Ed25519Signer();
  sign(payload: string): string {
    return this.inner.sign(payload);
  }
}

describe('createDelegationGraph', () => {
  it('should create a graph with a root agent node', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'orchestrator',
      agentType: 'orchestrator',
      declaredTools: ['search', 'email'],
      riskState: { l1: false, l2: false, l3: false },
    });

    expect(graph.sessionId).toBe('session-1');
    expect(graph.rootAgentId).toBe('orchestrator');
    expect(graph.nodes.size).toBe(1);
    expect(graph.edges).toHaveLength(0);
    expect(graph.signature).toBeTruthy();
  });

  it('should store the root agent with correct properties', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: ['tool-a'],
      riskState: { l1: true, l2: false, l3: false },
    });

    const root = graph.nodes.get('root');
    expect(root).toBeDefined();
    expect(root!.agentType).toBe('orchestrator');
    expect(root!.declaredTools).toEqual(['tool-a']);
    expect(root!.riskState).toEqual({ l1: true, l2: false, l3: false });
    expect(root!.parentAgentId).toBeUndefined();
  });

  it('should produce a valid HMAC signature at creation', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    expect(verifyGraphIntegrity(graph)).toBe(true);
  });
});

describe('addAgent', () => {
  it('should add a sub-agent with delegation edge from parent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: ['search'],
      riskState: { l1: false, l2: false, l3: false },
    });

    const result = addAgent(
      graph,
      {
        agentId: 'sub-1',
        agentType: 'subagent',
        declaredTools: ['browse'],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'research task context',
    );

    expect(result).toBe(true);
    expect(graph.nodes.size).toBe(2);
    expect(graph.edges).toHaveLength(1);

    const sub = graph.nodes.get('sub-1');
    expect(sub).toBeDefined();
    expect(sub!.parentAgentId).toBe('root');
    expect(sub!.agentType).toBe('subagent');
  });

  it('should carry risk state from parent to child via inheritance', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: true, l2: true, l3: false },
    });

    addAgent(
      graph,
      {
        agentId: 'child',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: true },
      },
      'root',
      'handoff context',
    );

    const child = graph.nodes.get('child');
    expect(child!.riskState).toEqual({ l1: true, l2: true, l3: true });
  });

  it('should record the context fingerprint on the delegation edge', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    addAgent(
      graph,
      {
        agentId: 'sub-1',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'my context',
    );

    const edge = graph.edges[0];
    expect(edge.fromAgentId).toBe('root');
    expect(edge.toAgentId).toBe('sub-1');
    expect(edge.contextFingerprint).toBe(computeContextFingerprint('my context'));
    expect(edge.riskStateAtHandoff).toEqual({
      l1: false,
      l2: false,
      l3: false,
    });
  });

  it('should return false when parent does not exist', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    const result = addAgent(
      graph,
      {
        agentId: 'orphan',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'nonexistent-parent',
      'context',
    );

    expect(result).toBe(false);
    expect(graph.nodes.size).toBe(1);
  });

  it('should record parent risk state at handoff on the edge', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: true, l2: false, l3: true },
    });

    addAgent(
      graph,
      {
        agentId: 'sub-1',
        agentType: 'tool_agent',
        declaredTools: ['sendEmail'],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'delegate email',
    );

    expect(graph.edges[0].riskStateAtHandoff).toEqual({
      l1: true,
      l2: false,
      l3: true,
    });
  });
});

describe('verifyGraphIntegrity', () => {
  it('should return true for an unmodified graph', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    expect(verifyGraphIntegrity(graph)).toBe(true);
  });

  it('should return false when signature is tampered', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    // Tamper with signature by creating a new object — the verifier
    // association is held via WeakMap on the original, so a fresh graph
    // object exercises the explicit-verifier path.
    const tamperedGraph: DelegationGraph = {
      sessionId: graph.sessionId,
      rootAgentId: graph.rootAgentId,
      nodes: graph.nodes,
      edges: graph.edges,
      signature: 'deadbeef',
      algorithm: graph.algorithm,
      keyId: graph.keyId,
      coverageCommitment: graph.coverageCommitment,
    };

    expect(verifyGraphIntegrity(tamperedGraph, getDefaultSigner())).toBe(false);
  });

  it('should default to Ed25519 and emit algorithm + keyId on the graph', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    expect(graph.algorithm).toBe('Ed25519');
    expect(graph.keyId).toHaveLength(16);
    expect(graph.signature).toMatch(/^[0-9a-f]+$/);
  });

  it('should honour an injected signer', () => {
    const signer = new HmacSigner();
    const graph = createDelegationGraph(
      'session-1',
      {
        agentId: 'root',
        agentType: 'orchestrator',
        declaredTools: ['search'],
        riskState: { l1: false, l2: false, l3: false },
      },
      signer,
    );

    expect(graph.algorithm).toBe('HMAC-SHA256');
    expect(graph.keyId).toBe(signer.keyId);
    expect(verifyGraphIntegrity(graph)).toBe(true);
  });

  it('should reject verification when a wrong-key verifier is supplied', () => {
    const signer = new Ed25519Signer();
    const graph = createDelegationGraph(
      'session-1',
      {
        agentId: 'root',
        agentType: 'orchestrator',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      signer,
    );

    const wrongVerifier = new Ed25519Signer();
    expect(verifyGraphIntegrity(graph, wrongVerifier)).toBe(false);
  });

  it('should detect root capability-surface tampering', () => {
    const signer = new Ed25519Signer();
    const graph = createDelegationGraph(
      'session-1',
      {
        agentId: 'root',
        agentType: 'orchestrator',
        declaredTools: ['search'],
        riskState: { l1: false, l2: false, l3: false },
      },
      signer,
    );

    // Swap the root's declaredTools in place to simulate runtime mutation.
    const root = graph.nodes.get('root');
    if (!root) throw new Error('root missing');
    graph.nodes.set('root', {
      ...root,
      declaredTools: ['search', 'sendEmail'],
    });

    expect(verifyGraphIntegrity(graph)).toBe(false);
  });

  it('should NOT register a mismatched fallback verifier for a sign-only adapter', () => {
    // Regression: previously a pure Signer fell back to getDefaultSigner() as
    // the stored verifier, whose keyId never matches the graph, silently
    // blocking every turn. Now no verifier is registered, so the manifest gate
    // reports the diagnosable VERIFIER_MISSING and the caller must supply one.
    const graph = createDelegationGraph(
      'session-1',
      {
        agentId: 'root',
        agentType: 'orchestrator',
        declaredTools: ['search'],
        riskState: { l1: false, l2: false, l3: false },
      },
      new SignOnlySigner(),
    );

    // No verifier was stored (so the gate can distinguish missing-verifier
    // from bad-signature), and verification without an explicit verifier fails
    // closed rather than silently against a mismatched fallback key.
    expect(getGraphVerifier(graph)).toBeUndefined();
    expect(verifyGraphIntegrity(graph)).toBe(false);

    // A non-matching verifier (different key) also fails closed — the caller
    // must supply the Verifier built from THIS signer's public key.
    const wrongKeyVerifier = new Ed25519Signer();
    expect(verifyGraphIntegrity(graph, wrongKeyVerifier)).toBe(false);
  });
});

describe('getAgentChain', () => {
  it('should return the chain from root to a deep sub-agent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    addAgent(
      graph,
      {
        agentId: 'mid',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'mid context',
    );

    addAgent(
      graph,
      {
        agentId: 'leaf',
        agentType: 'tool_agent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'mid',
      'leaf context',
    );

    const chain = getAgentChain(graph, 'leaf');
    expect(chain).toHaveLength(3);
    expect(chain[0].agentId).toBe('root');
    expect(chain[1].agentId).toBe('mid');
    expect(chain[2].agentId).toBe('leaf');
  });

  it('should return a single-element chain for the root agent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    const chain = getAgentChain(graph, 'root');
    expect(chain).toHaveLength(1);
    expect(chain[0].agentId).toBe('root');
  });

  it('should return empty array for a nonexistent agent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    const chain = getAgentChain(graph, 'ghost');
    expect(chain).toHaveLength(0);
  });
});

describe('isAuthorizedAgent', () => {
  it('should return true for an agent in the graph', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    expect(isAuthorizedAgent(graph, 'root')).toBe(true);
  });

  it('should return false for an agent not in the graph', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    expect(isAuthorizedAgent(graph, 'unknown-agent')).toBe(false);
  });
});

describe('updateAgentRiskState', () => {
  it('should update risk state for an existing agent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    const result = updateAgentRiskState(graph, 'root', {
      l1: true,
      l2: true,
      l3: false,
    });
    expect(result).toBe(true);
    expect(graph.nodes.get('root')!.riskState).toEqual({
      l1: true,
      l2: true,
      l3: false,
    });
  });

  it('should return false for a nonexistent agent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    const result = updateAgentRiskState(graph, 'ghost', {
      l1: true,
      l2: true,
      l3: true,
    });
    expect(result).toBe(false);
  });
});

describe('coverage commitment binding (the receipt attests what was protected)', () => {
  const COMMITMENT = () =>
    computeCoverageCommitment(
      computeCoverageReport({
        executorNames: ['sendEmail'],
        config: { trustOverrides: [{ toolName: 'sendEmail', trustLevel: 'untrusted' }] },
        outboundTools: ['sendEmail'],
        memoryTools: [],
      }),
    );

  it('defaults to an empty commitment when none is supplied (low-level caller)', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: ['sendEmail'],
      riskState: { l1: false, l2: false, l3: false },
    });
    expect(graph.coverageCommitment).toBe('');
    expect(verifyGraphIntegrity(graph)).toBe(true);
  });

  it('binds the commitment into the signed payload and verifies round-trip', () => {
    const commitment = COMMITMENT();
    const graph = createDelegationGraph(
      'session-1',
      {
        agentId: 'root',
        agentType: 'orchestrator',
        declaredTools: ['sendEmail'],
        riskState: { l1: false, l2: false, l3: false },
      },
      undefined,
      commitment,
    );
    expect(graph.coverageCommitment).toBe(commitment);
    expect(verifyGraphIntegrity(graph)).toBe(true);
  });

  it('detects coverage-commitment tampering (a receipt claiming different protection)', () => {
    const graph = createDelegationGraph(
      'session-1',
      {
        agentId: 'root',
        agentType: 'orchestrator',
        declaredTools: ['sendEmail'],
        riskState: { l1: false, l2: false, l3: false },
      },
      undefined,
      COMMITMENT(),
    );

    // Swap the bound commitment to assert a different coverage posture than was
    // signed. The signature must no longer verify.
    const tampered: DelegationGraph = {
      ...graph,
      coverageCommitment: 'f'.repeat(64),
    };
    expect(verifyGraphIntegrity(tampered, getDefaultSigner())).toBe(false);
  });
});

describe('computeContextFingerprint', () => {
  it('should produce a deterministic SHA-256 hash', () => {
    const fp1 = computeContextFingerprint('hello world');
    const fp2 = computeContextFingerprint('hello world');
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64); // SHA-256 hex
  });

  it('should produce different hashes for different contexts', () => {
    const fp1 = computeContextFingerprint('context-a');
    const fp2 = computeContextFingerprint('context-b');
    expect(fp1).not.toBe(fp2);
  });
});
