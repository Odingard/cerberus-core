/**
 * Tests for the in-memory Contamination Graph.
 */

import { describe, it, expect } from 'vitest';
import { createContaminationGraph } from '../../src/graph/contamination.js';
import type { GraphNode } from '../../src/graph/contamination.js';

// ── Helpers ─────────────────────────────────────────────────────────

function makeNode(overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    nodeId: 'node-1',
    trustLevel: 'trusted',
    sourceSessionId: 'session-A',
    source: 'readDb',
    contentHash: 'aabbccdd',
    timestamp: 1000,
    ...overrides,
  };
}

// ── createContaminationGraph ────────────────────────────────────────

describe('createContaminationGraph', () => {
  it('should create an empty graph', () => {
    const graph = createContaminationGraph();
    expect(graph.size()).toBe(0);
    expect(graph.getNodes()).toHaveLength(0);
    expect(graph.getEdges()).toHaveLength(0);
  });

  // ── writeNode / getNode ───────────────────────────────────────────

  describe('writeNode / getNode', () => {
    it('should store and retrieve a node', () => {
      const graph = createContaminationGraph();
      const node = makeNode();

      graph.writeNode(node);

      expect(graph.size()).toBe(1);
      expect(graph.getNode('node-1')).toEqual(node);
    });

    it('should overwrite a node with the same ID', () => {
      const graph = createContaminationGraph();

      graph.writeNode(makeNode({ contentHash: 'first' }));
      graph.writeNode(makeNode({ contentHash: 'second' }));

      expect(graph.size()).toBe(1);
      expect(graph.getNode('node-1')!.contentHash).toBe('second');
    });

    it('should return undefined for nonexistent node', () => {
      const graph = createContaminationGraph();
      expect(graph.getNode('nonexistent')).toBeUndefined();
    });
  });

  // ── addEdge / getEdges ────────────────────────────────────────────

  describe('addEdge / getEdges', () => {
    it('should record directed edges', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a' }));
      graph.writeNode(makeNode({ nodeId: 'b' }));

      graph.addEdge({
        sourceNodeId: 'a',
        targetNodeId: 'b',
        sessionId: 'session-A',
        timestamp: 1000,
      });

      expect(graph.getEdges()).toHaveLength(1);
      expect(graph.getEdges()[0].sourceNodeId).toBe('a');
      expect(graph.getEdges()[0].targetNodeId).toBe('b');
    });
  });

  // ── getAncestors ──────────────────────────────────────────────────

  describe('getAncestors', () => {
    it('should return empty array for node with no parents', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a' }));

      expect(graph.getAncestors('a')).toHaveLength(0);
    });

    it('should return direct ancestors', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'parent' }));
      graph.writeNode(makeNode({ nodeId: 'child' }));
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 's',
        timestamp: 1,
      });

      const ancestors = graph.getAncestors('child');
      expect(ancestors).toHaveLength(1);
      expect(ancestors[0].nodeId).toBe('parent');
    });

    it('should return transitive ancestors (grandparent)', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'gp' }));
      graph.writeNode(makeNode({ nodeId: 'parent' }));
      graph.writeNode(makeNode({ nodeId: 'child' }));
      graph.addEdge({ sourceNodeId: 'gp', targetNodeId: 'parent', sessionId: 's', timestamp: 1 });
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 's',
        timestamp: 2,
      });

      const ancestors = graph.getAncestors('child');
      expect(ancestors).toHaveLength(2);
      const ids = ancestors.map((a) => a.nodeId);
      expect(ids).toContain('parent');
      expect(ids).toContain('gp');
    });

    it('should handle cycles without infinite loop', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a' }));
      graph.writeNode(makeNode({ nodeId: 'b' }));
      graph.addEdge({ sourceNodeId: 'a', targetNodeId: 'b', sessionId: 's', timestamp: 1 });
      graph.addEdge({ sourceNodeId: 'b', targetNodeId: 'a', sessionId: 's', timestamp: 2 });

      // Should terminate despite cycle — BFS finds b (parent of a),
      // then a (parent of b) but stops because a is already visited
      const ancestors = graph.getAncestors('a');
      expect(ancestors).toHaveLength(2);
      const ids = ancestors.map((n) => n.nodeId);
      expect(ids).toContain('b');
      expect(ids).toContain('a');
    });

    it('should handle diamond-shaped graph', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'root' }));
      graph.writeNode(makeNode({ nodeId: 'left' }));
      graph.writeNode(makeNode({ nodeId: 'right' }));
      graph.writeNode(makeNode({ nodeId: 'bottom' }));

      graph.addEdge({ sourceNodeId: 'root', targetNodeId: 'left', sessionId: 's', timestamp: 1 });
      graph.addEdge({ sourceNodeId: 'root', targetNodeId: 'right', sessionId: 's', timestamp: 2 });
      graph.addEdge({ sourceNodeId: 'left', targetNodeId: 'bottom', sessionId: 's', timestamp: 3 });
      graph.addEdge({
        sourceNodeId: 'right',
        targetNodeId: 'bottom',
        sessionId: 's',
        timestamp: 4,
      });

      const ancestors = graph.getAncestors('bottom');
      expect(ancestors).toHaveLength(3);
      const ids = ancestors.map((a) => a.nodeId);
      expect(ids).toContain('left');
      expect(ids).toContain('right');
      expect(ids).toContain('root');
    });
  });

  // ── isTainted ─────────────────────────────────────────────────────

  describe('isTainted', () => {
    it('should return false for nonexistent node', () => {
      const graph = createContaminationGraph();
      expect(graph.isTainted('nonexistent')).toBe(false);
    });

    it('should return true for untrusted node', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a', trustLevel: 'untrusted' }));

      expect(graph.isTainted('a')).toBe(true);
    });

    it('should return false for trusted node with no ancestors', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a', trustLevel: 'trusted' }));

      expect(graph.isTainted('a')).toBe(false);
    });

    it('should return true when ancestor is untrusted', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'parent', trustLevel: 'untrusted' }));
      graph.writeNode(makeNode({ nodeId: 'child', trustLevel: 'trusted' }));
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 's',
        timestamp: 1,
      });

      expect(graph.isTainted('child')).toBe(true);
    });

    it('should return false when all ancestors are trusted', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'parent', trustLevel: 'trusted' }));
      graph.writeNode(makeNode({ nodeId: 'child', trustLevel: 'trusted' }));
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 's',
        timestamp: 1,
      });

      expect(graph.isTainted('child')).toBe(false);
    });
  });

  // ── hasCrossSessionTaint ──────────────────────────────────────────

  describe('hasCrossSessionTaint', () => {
    it('should return false for nonexistent node', () => {
      const graph = createContaminationGraph();
      expect(graph.hasCrossSessionTaint('x', 'session-B')).toBe(false);
    });

    it('should return true when node is untrusted from a different session', () => {
      const graph = createContaminationGraph();
      graph.writeNode(
        makeNode({
          nodeId: 'a',
          trustLevel: 'untrusted',
          sourceSessionId: 'session-A',
        }),
      );

      expect(graph.hasCrossSessionTaint('a', 'session-B')).toBe(true);
    });

    it('should return false when node is untrusted from the same session', () => {
      const graph = createContaminationGraph();
      graph.writeNode(
        makeNode({
          nodeId: 'a',
          trustLevel: 'untrusted',
          sourceSessionId: 'session-A',
        }),
      );

      expect(graph.hasCrossSessionTaint('a', 'session-A')).toBe(false);
    });

    it('should return true when ancestor is untrusted from a different session', () => {
      const graph = createContaminationGraph();
      graph.writeNode(
        makeNode({
          nodeId: 'parent',
          trustLevel: 'untrusted',
          sourceSessionId: 'session-A',
        }),
      );
      graph.writeNode(
        makeNode({
          nodeId: 'child',
          trustLevel: 'trusted',
          sourceSessionId: 'session-B',
        }),
      );
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 'session-B',
        timestamp: 1,
      });

      expect(graph.hasCrossSessionTaint('child', 'session-B')).toBe(true);
    });

    it('should return false when ancestor is untrusted from the same session', () => {
      const graph = createContaminationGraph();
      graph.writeNode(
        makeNode({
          nodeId: 'parent',
          trustLevel: 'untrusted',
          sourceSessionId: 'session-A',
        }),
      );
      graph.writeNode(
        makeNode({
          nodeId: 'child',
          trustLevel: 'trusted',
          sourceSessionId: 'session-A',
        }),
      );
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 'session-A',
        timestamp: 1,
      });

      expect(graph.hasCrossSessionTaint('child', 'session-A')).toBe(false);
    });
  });

  // ── findContaminationSource ───────────────────────────────────────

  describe('findContaminationSource', () => {
    it('should return undefined for nonexistent node', () => {
      const graph = createContaminationGraph();
      expect(graph.findContaminationSource('x')).toBeUndefined();
    });

    it('should return the source of a directly untrusted node', () => {
      const graph = createContaminationGraph();
      graph.writeNode(
        makeNode({
          nodeId: 'a',
          trustLevel: 'untrusted',
          source: 'fetchExternalContent',
        }),
      );

      expect(graph.findContaminationSource('a')).toBe('fetchExternalContent');
    });

    it('should return the source of the first untrusted ancestor', () => {
      const graph = createContaminationGraph();
      graph.writeNode(
        makeNode({
          nodeId: 'gp',
          trustLevel: 'untrusted',
          source: 'evilFetch',
        }),
      );
      graph.writeNode(makeNode({ nodeId: 'parent', trustLevel: 'trusted' }));
      graph.writeNode(makeNode({ nodeId: 'child', trustLevel: 'trusted' }));
      graph.addEdge({ sourceNodeId: 'gp', targetNodeId: 'parent', sessionId: 's', timestamp: 1 });
      graph.addEdge({
        sourceNodeId: 'parent',
        targetNodeId: 'child',
        sessionId: 's',
        timestamp: 2,
      });

      expect(graph.findContaminationSource('child')).toBe('evilFetch');
    });

    it('should return undefined for fully trusted chain', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a', trustLevel: 'trusted' }));
      graph.writeNode(makeNode({ nodeId: 'b', trustLevel: 'trusted' }));
      graph.addEdge({ sourceNodeId: 'a', targetNodeId: 'b', sessionId: 's', timestamp: 1 });

      expect(graph.findContaminationSource('b')).toBeUndefined();
    });
  });

  // ── clear ─────────────────────────────────────────────────────────

  describe('clear', () => {
    it('should remove all nodes and edges', () => {
      const graph = createContaminationGraph();
      graph.writeNode(makeNode({ nodeId: 'a' }));
      graph.writeNode(makeNode({ nodeId: 'b' }));
      graph.addEdge({ sourceNodeId: 'a', targetNodeId: 'b', sessionId: 's', timestamp: 1 });

      graph.clear();

      expect(graph.size()).toBe(0);
      expect(graph.getNodes()).toHaveLength(0);
      expect(graph.getEdges()).toHaveLength(0);
      expect(graph.getNode('a')).toBeUndefined();
    });
  });
});
