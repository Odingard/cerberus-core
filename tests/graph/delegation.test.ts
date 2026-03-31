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
} from '../../src/graph/delegation.js';
import type { DelegationGraph } from '../../src/graph/delegation.js';

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
    expect(edge.riskStateAtHandoff).toEqual({ l1: false, l2: false, l3: false });
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

    expect(graph.edges[0].riskStateAtHandoff).toEqual({ l1: true, l2: false, l3: true });
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

    // Tamper with signature by casting to mutable
    const tampered = { ...graph, signature: 'tampered-signature' } as DelegationGraph;
    // Use a new object so the original's Map is preserved
    const tamperedGraph: DelegationGraph = {
      sessionId: tampered.sessionId,
      rootAgentId: tampered.rootAgentId,
      nodes: tampered.nodes,
      edges: tampered.edges,
      signature: 'tampered-signature',
    };

    expect(verifyGraphIntegrity(tamperedGraph)).toBe(false);
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

    const result = updateAgentRiskState(graph, 'root', { l1: true, l2: true, l3: false });
    expect(result).toBe(true);
    expect(graph.nodes.get('root')!.riskState).toEqual({ l1: true, l2: true, l3: false });
  });

  it('should return false for a nonexistent agent', () => {
    const graph = createDelegationGraph('session-1', {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: [],
      riskState: { l1: false, l2: false, l3: false },
    });

    const result = updateAgentRiskState(graph, 'ghost', { l1: true, l2: true, l3: true });
    expect(result).toBe(false);
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
