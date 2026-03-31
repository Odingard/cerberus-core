/**
 * Contamination Graph — Directed taint propagation graph.
 *
 * Tracks how contaminated data flows through memory writes
 * and reads across sessions. In-memory graph with BFS-based
 * ancestor traversal for taint detection.
 *
 * Depends on: src/types/signals.ts
 */

import type { TrustLevel, SessionId } from '../types/signals.js';

// ── Types ───────────────────────────────────────────────────────────

/** A node in the contamination graph. */
export interface GraphNode {
  readonly nodeId: string;
  readonly trustLevel: TrustLevel;
  readonly sourceSessionId: SessionId;
  readonly source: string;
  readonly contentHash: string;
  readonly timestamp: number;
}

/** A directed edge in the contamination graph (data flowed from source to target). */
export interface GraphEdge {
  readonly sourceNodeId: string;
  readonly targetNodeId: string;
  readonly sessionId: SessionId;
  readonly timestamp: number;
}

/** The contamination graph tracks taint propagation across memory nodes. */
export interface ContaminationGraph {
  /** Add or update a node (memory write). */
  readonly writeNode: (node: GraphNode) => void;
  /** Record that data from sourceNode flowed into targetNode. */
  readonly addEdge: (edge: GraphEdge) => void;
  /** Get a node by ID. */
  readonly getNode: (nodeId: string) => GraphNode | undefined;
  /** Get all nodes. */
  readonly getNodes: () => readonly GraphNode[];
  /** Get all edges. */
  readonly getEdges: () => readonly GraphEdge[];
  /** Get upstream (ancestor) nodes that feed into a given node. */
  readonly getAncestors: (nodeId: string) => readonly GraphNode[];
  /** Check if a node is tainted (written by untrusted source OR has tainted ancestor). */
  readonly isTainted: (nodeId: string) => boolean;
  /** Check if taint crosses a session boundary relative to currentSessionId. */
  readonly hasCrossSessionTaint: (nodeId: string, currentSessionId: SessionId) => boolean;
  /** Find the contamination source (first untrusted ancestor) for a tainted node. */
  readonly findContaminationSource: (nodeId: string) => string | undefined;
  /** Get the count of nodes. */
  readonly size: () => number;
  /** Clear all nodes and edges. */
  readonly clear: () => void;
}

// ── Factory ─────────────────────────────────────────────────────────

/** Create a new contamination graph. */
export function createContaminationGraph(): ContaminationGraph {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  // Reverse adjacency: targetNodeId → Set of sourceNodeIds (for ancestor lookups)
  const reverseAdj = new Map<string, Set<string>>();

  const writeNode = (node: GraphNode): void => {
    nodes.set(node.nodeId, node);
  };

  const addEdge = (edge: GraphEdge): void => {
    edges.push(edge);
    let sources = reverseAdj.get(edge.targetNodeId);
    if (!sources) {
      sources = new Set();
      reverseAdj.set(edge.targetNodeId, sources);
    }
    sources.add(edge.sourceNodeId);
  };

  const getNode = (nodeId: string): GraphNode | undefined => {
    return nodes.get(nodeId);
  };

  const getNodes = (): readonly GraphNode[] => {
    return [...nodes.values()];
  };

  const getEdges = (): readonly GraphEdge[] => {
    return [...edges];
  };

  /**
   * BFS traversal up the reverse adjacency list to find all ancestors.
   * Uses a visited set for cycle detection.
   */
  const getAncestors = (nodeId: string): readonly GraphNode[] => {
    const visited = new Set<string>();
    const queue: string[] = [];
    const ancestors: GraphNode[] = [];

    // Seed the queue with direct parents
    const directParents = reverseAdj.get(nodeId);
    if (directParents) {
      for (const parentId of directParents) {
        if (!visited.has(parentId)) {
          visited.add(parentId);
          queue.push(parentId);
        }
      }
    }

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const node = nodes.get(currentId);
      if (node) {
        ancestors.push(node);
      }

      const parents = reverseAdj.get(currentId);
      if (parents) {
        for (const parentId of parents) {
          if (!visited.has(parentId)) {
            visited.add(parentId);
            queue.push(parentId);
          }
        }
      }
    }

    return ancestors;
  };

  const isTainted = (nodeId: string): boolean => {
    // Check the node itself
    const node = nodes.get(nodeId);
    if (!node) return false;
    if (node.trustLevel === 'untrusted') return true;

    // Check ancestors
    const ancestors = getAncestors(nodeId);
    return ancestors.some((a) => a.trustLevel === 'untrusted');
  };

  const hasCrossSessionTaint = (nodeId: string, currentSessionId: SessionId): boolean => {
    const node = nodes.get(nodeId);
    if (!node) return false;

    // Check the node itself: untrusted AND from a different session
    if (node.trustLevel === 'untrusted' && node.sourceSessionId !== currentSessionId) {
      return true;
    }

    // Check ancestors for cross-session taint
    const ancestors = getAncestors(nodeId);
    return ancestors.some(
      (a) => a.trustLevel === 'untrusted' && a.sourceSessionId !== currentSessionId,
    );
  };

  const findContaminationSource = (nodeId: string): string | undefined => {
    const node = nodes.get(nodeId);
    if (!node) return undefined;

    // If the node itself is untrusted, return its source
    if (node.trustLevel === 'untrusted') {
      return node.source;
    }

    // BFS for the first untrusted ancestor
    const visited = new Set<string>();
    const queue: string[] = [];

    const directParents = reverseAdj.get(nodeId);
    if (directParents) {
      for (const parentId of directParents) {
        if (!visited.has(parentId)) {
          visited.add(parentId);
          queue.push(parentId);
        }
      }
    }

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      const current = nodes.get(currentId);
      if (current?.trustLevel === 'untrusted') {
        return current.source;
      }

      const parents = reverseAdj.get(currentId);
      if (parents) {
        for (const parentId of parents) {
          if (!visited.has(parentId)) {
            visited.add(parentId);
            queue.push(parentId);
          }
        }
      }
    }

    return undefined;
  };

  const size = (): number => nodes.size;

  const clear = (): void => {
    nodes.clear();
    edges.length = 0;
    reverseAdj.clear();
  };

  return {
    writeNode,
    addEdge,
    getNode,
    getNodes,
    getEdges,
    getAncestors,
    isTainted,
    hasCrossSessionTaint,
    findContaminationSource,
    size,
    clear,
  };
}
