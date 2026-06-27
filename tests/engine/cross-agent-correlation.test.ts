/**
 * Tests for Cross-Agent Correlation — cross-agent Lethal Trifecta detection.
 */

import { describe, it, expect } from 'vitest';
import {
  detectCrossAgentTrifecta,
  detectContextContamination,
  detectUnauthorizedAgentSpawn,
} from '../../src/engine/cross-agent-correlation.js';
import {
  createDelegationGraph,
  addAgent,
  updateAgentRiskState,
} from '../../src/graph/delegation.js';
import type { DelegationGraph } from '../../src/graph/delegation.js';

function buildTestGraph(): DelegationGraph {
  const graph = createDelegationGraph('session-test', {
    agentId: 'root',
    agentType: 'orchestrator',
    declaredTools: ['search'],
    riskState: { l1: false, l2: false, l3: false },
  });
  return graph;
}

describe('detectCrossAgentTrifecta', () => {
  it('should detect trifecta when L1+L2+L3 span across agents in the chain', () => {
    const graph = buildTestGraph();

    // Root has L1
    updateAgentRiskState(graph, 'root', { l1: true, l2: false, l3: false });

    // Sub-agent A has L2
    addAgent(
      graph,
      {
        agentId: 'agent-a',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: true, l3: false },
      },
      'root',
      'delegate to A',
    );

    // Sub-agent B (downstream of A) has L3
    addAgent(
      graph,
      {
        agentId: 'agent-b',
        agentType: 'tool_agent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'agent-a',
      'delegate to B',
    );

    const signal = detectCrossAgentTrifecta(
      graph,
      'agent-b',
      { l1: false, l2: false, l3: true },
      'turn-001',
    );

    expect(signal).not.toBeNull();
    expect(signal!.signal).toBe('CROSS_AGENT_TRIFECTA');
    expect(signal!.layer).toBe('CROSS_AGENT');
    expect(signal!.riskState).toEqual({ l1: true, l2: true, l3: true });
    expect(signal!.contributingAgents.length).toBeGreaterThan(1);
  });

  it('should not fire when trifecta is incomplete across the chain', () => {
    const graph = buildTestGraph();

    // Root has L1 only
    updateAgentRiskState(graph, 'root', { l1: true, l2: false, l3: false });

    addAgent(
      graph,
      {
        agentId: 'agent-a',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'context',
    );

    const signal = detectCrossAgentTrifecta(
      graph,
      'agent-a',
      { l1: false, l2: true, l3: false },
      'turn-001',
    );

    // L1 + L2 only — no L3, so no trifecta
    expect(signal).toBeNull();
  });

  it('should not fire when all layers satisfied by a single agent', () => {
    const graph = buildTestGraph();

    // Root has nothing
    // Agent-a has all three by itself
    addAgent(
      graph,
      {
        agentId: 'agent-a',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'context',
    );

    const signal = detectCrossAgentTrifecta(
      graph,
      'agent-a',
      { l1: true, l2: true, l3: true },
      'turn-001',
    );

    // Only agent-a contributes — single agent, not cross-agent
    // Root contributes nothing, so contributingAgents would only have agent-a
    // The signal should NOT fire because it's a single-agent trifecta
    expect(signal).toBeNull();
  });

  it('should return null for an unknown agent', () => {
    const graph = buildTestGraph();

    const signal = detectCrossAgentTrifecta(
      graph,
      'nonexistent',
      { l1: true, l2: true, l3: true },
      'turn-001',
    );

    expect(signal).toBeNull();
  });

  it('should detect trifecta in a multi-hop chain', () => {
    const graph = buildTestGraph();

    // root → A → B → C
    updateAgentRiskState(graph, 'root', { l1: true, l2: false, l3: false });

    addAgent(
      graph,
      {
        agentId: 'A',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'to A',
    );

    addAgent(
      graph,
      {
        agentId: 'B',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: true, l3: false },
      },
      'A',
      'to B',
    );

    addAgent(
      graph,
      {
        agentId: 'C',
        agentType: 'tool_agent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'B',
      'to C',
    );

    // C gets L3 at runtime
    const signal = detectCrossAgentTrifecta(
      graph,
      'C',
      { l1: false, l2: false, l3: true },
      'turn-005',
    );

    expect(signal).not.toBeNull();
    expect(signal!.signal).toBe('CROSS_AGENT_TRIFECTA');
    // root has L1, B has L2 (inherited from addAgent), C has L3
    expect(signal!.contributingAgents.length).toBeGreaterThanOrEqual(2);
  });

  it('should use currentRiskState for the current agent instead of stored state', () => {
    const graph = buildTestGraph();

    // Root has L1
    updateAgentRiskState(graph, 'root', { l1: true, l2: false, l3: false });

    addAgent(
      graph,
      {
        agentId: 'child',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'context',
    );

    // Pass L2+L3 as current risk state (not yet stored in graph)
    const signal = detectCrossAgentTrifecta(
      graph,
      'child',
      { l1: false, l2: true, l3: true },
      'turn-001',
    );

    expect(signal).not.toBeNull();
    expect(signal!.riskState).toEqual({ l1: true, l2: true, l3: true });
  });
});

describe('detectContextContamination', () => {
  it('should detect contamination when upstream agent has L2', () => {
    const graph = buildTestGraph();

    // Root has L2 (injection)
    updateAgentRiskState(graph, 'root', { l1: false, l2: true, l3: false });

    addAgent(
      graph,
      {
        agentId: 'child',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'tainted context',
    );

    const signal = detectContextContamination(graph, 'child', 'turn-001');

    expect(signal).not.toBeNull();
    expect(signal!.signal).toBe('CONTEXT_CONTAMINATION_PROPAGATION');
    expect(signal!.layer).toBe('CROSS_AGENT');
    expect(signal!.sourceAgentId).toBe('root');
    expect(signal!.contaminatedAgentId).toBe('child');
  });

  it('should not fire when no upstream agent has L2', () => {
    const graph = buildTestGraph();

    addAgent(
      graph,
      {
        agentId: 'child',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'clean context',
    );

    const signal = detectContextContamination(graph, 'child', 'turn-001');
    expect(signal).toBeNull();
  });

  it('should not fire for the root agent (no upstream)', () => {
    const graph = buildTestGraph();
    updateAgentRiskState(graph, 'root', { l1: false, l2: true, l3: false });

    const signal = detectContextContamination(graph, 'root', 'turn-001');
    expect(signal).toBeNull();
  });

  it('should detect contamination from delegation edge riskStateAtHandoff', () => {
    const graph = buildTestGraph();

    // Root has L2 at handoff time
    updateAgentRiskState(graph, 'root', { l1: false, l2: true, l3: false });

    addAgent(
      graph,
      {
        agentId: 'child',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'context with injection',
    );

    // Even if root's risk state gets cleared later, the edge preserves the handoff state
    updateAgentRiskState(graph, 'root', { l1: false, l2: false, l3: false });

    const signal = detectContextContamination(graph, 'child', 'turn-002');

    // Should still detect because the edge's riskStateAtHandoff had L2=true
    expect(signal).not.toBeNull();
    expect(signal!.sourceAgentId).toBe('root');
  });
});

describe('detectUnauthorizedAgentSpawn', () => {
  it('should detect an unauthorized agent not in the graph', () => {
    const graph = buildTestGraph();

    const signal = detectUnauthorizedAgentSpawn(graph, 'rogue-agent', 'turn-001');

    expect(signal).not.toBeNull();
    expect(signal!.signal).toBe('UNAUTHORIZED_AGENT_SPAWN');
    expect(signal!.layer).toBe('CROSS_AGENT');
    expect(signal!.agentId).toBe('rogue-agent');
  });

  it('should not fire for an authorized agent in the graph', () => {
    const graph = buildTestGraph();

    const signal = detectUnauthorizedAgentSpawn(graph, 'root', 'turn-001');
    expect(signal).toBeNull();
  });

  it('should not fire for a properly spawned sub-agent', () => {
    const graph = buildTestGraph();

    addAgent(
      graph,
      {
        agentId: 'sub-1',
        agentType: 'subagent',
        declaredTools: [],
        riskState: { l1: false, l2: false, l3: false },
      },
      'root',
      'context',
    );

    const signal = detectUnauthorizedAgentSpawn(graph, 'sub-1', 'turn-001');
    expect(signal).toBeNull();
  });
});
