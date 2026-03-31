/**
 * Tests for L4 Memory Contamination detection layer.
 */

import { describe, it, expect } from 'vitest';
import {
  checkMemoryContamination,
  defaultExtractNodeId,
  defaultExtractContent,
  extractNodeId,
} from '../../src/layers/l4-memory.js';
import type { MemoryToolConfig } from '../../src/layers/l4-memory.js';
import { createContaminationGraph } from '../../src/graph/contamination.js';
import { createLedger, hashContent } from '../../src/graph/ledger.js';
import type { ToolCallContext } from '../../src/types/context.js';

// ── Helpers ─────────────────────────────────────────────────────────

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-000',
    sessionId: 'session-B',
    toolName: 'readMemory',
    toolArguments: { key: 'user-prefs' },
    toolResult: 'stored value',
    timestamp: Date.now(),
    ...overrides,
  };
}

const MEMORY_TOOLS: readonly MemoryToolConfig[] = [
  { toolName: 'writeMemory', operation: 'write' },
  { toolName: 'readMemory', operation: 'read' },
];

// ── defaultExtractNodeId ────────────────────────────────────────────

describe('defaultExtractNodeId', () => {
  it('should extract from "key" field', () => {
    expect(defaultExtractNodeId({ key: 'my-key' })).toBe('my-key');
  });

  it('should extract from "id" field', () => {
    expect(defaultExtractNodeId({ id: 'my-id' })).toBe('my-id');
  });

  it('should extract from "nodeId" field', () => {
    expect(defaultExtractNodeId({ nodeId: 'my-node' })).toBe('my-node');
  });

  it('should extract from "memoryKey" field', () => {
    expect(defaultExtractNodeId({ memoryKey: 'mem-key' })).toBe('mem-key');
  });

  it('should prefer "key" over "id"', () => {
    expect(defaultExtractNodeId({ key: 'first', id: 'second' })).toBe('first');
  });

  it('should return undefined when no matching field', () => {
    expect(defaultExtractNodeId({ other: 'value' })).toBeUndefined();
  });

  it('should skip empty strings', () => {
    expect(defaultExtractNodeId({ key: '' })).toBeUndefined();
  });

  it('should skip non-string values', () => {
    expect(defaultExtractNodeId({ key: 123 })).toBeUndefined();
  });
});

// ── extractNodeId ───────────────────────────────────────────────────

describe('extractNodeId', () => {
  it('should use custom extractor when provided', () => {
    const config: MemoryToolConfig = {
      toolName: 'writeMemory',
      operation: 'write',
      extractNodeId: (args) => args['path'] as string | undefined,
    };

    expect(extractNodeId({ path: '/data/file.txt' }, config)).toBe('/data/file.txt');
  });

  it('should fall back to default when no custom extractor', () => {
    const config: MemoryToolConfig = {
      toolName: 'writeMemory',
      operation: 'write',
    };

    expect(extractNodeId({ key: 'my-key' }, config)).toBe('my-key');
  });
});

// ── defaultExtractContent ───────────────────────────────────────────

describe('defaultExtractContent', () => {
  it('should extract from "value" field', () => {
    expect(defaultExtractContent({ value: 'val' }, 'result')).toBe('val');
  });

  it('should extract from "content" field', () => {
    expect(defaultExtractContent({ content: 'cont' }, 'result')).toBe('cont');
  });

  it('should extract from "data" field', () => {
    expect(defaultExtractContent({ data: 'dat' }, 'result')).toBe('dat');
  });

  it('should fall back to result when no matching args field', () => {
    expect(defaultExtractContent({ other: 'x' }, 'the result')).toBe('the result');
  });
});

// ── checkMemoryContamination ────────────────────────────────────────

describe('checkMemoryContamination', () => {
  it('should return null for non-memory tool', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    const ctx = makeCtx({ toolName: 'unknownTool' });
    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'trusted');

    expect(result).toBeNull();
    ledger.close();
  });

  it('should return null when node ID cannot be extracted', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    const ctx = makeCtx({
      toolName: 'readMemory',
      toolArguments: { unrelated: 'no-key-field' },
    });
    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'trusted');

    expect(result).toBeNull();
    ledger.close();
  });

  it('should record write in graph and ledger without emitting signal', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    const ctx = makeCtx({
      toolName: 'writeMemory',
      sessionId: 'session-A',
      toolArguments: { key: 'prefs', value: 'injected data' },
      toolResult: 'ok',
    });

    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'untrusted');

    expect(result).toBeNull(); // Writes never emit signals
    expect(graph.size()).toBe(1);
    expect(graph.getNode('prefs')).toBeDefined();
    expect(graph.getNode('prefs')!.trustLevel).toBe('untrusted');
    expect(ledger.getNodeHistory('prefs')).toHaveLength(1);

    ledger.close();
  });

  it('should return null for clean read (no taint)', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    // Write trusted data in same session
    graph.writeNode({
      nodeId: 'prefs',
      trustLevel: 'trusted',
      sourceSessionId: 'session-B',
      source: 'writeMemory',
      contentHash: hashContent('safe data'),
      timestamp: 1000,
    });

    const ctx = makeCtx({
      toolName: 'readMemory',
      sessionId: 'session-B',
      toolArguments: { key: 'prefs' },
    });

    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'trusted');
    expect(result).toBeNull();

    ledger.close();
  });

  it('should emit CONTAMINATED_MEMORY_ACTIVE for cross-session tainted read', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    // Session A: untrusted write
    graph.writeNode({
      nodeId: 'prefs',
      trustLevel: 'untrusted',
      sourceSessionId: 'session-A',
      source: 'fetchExternalContent',
      contentHash: hashContent('injected payload'),
      timestamp: 1000,
    });

    // Session B: read the tainted node
    const ctx = makeCtx({
      toolName: 'readMemory',
      sessionId: 'session-B',
      toolArguments: { key: 'prefs' },
      timestamp: 2000,
    });

    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'trusted');

    expect(result).not.toBeNull();
    expect(result!.layer).toBe('L4');
    expect(result!.signal).toBe('CONTAMINATED_MEMORY_ACTIVE');
    expect(result!.nodeId).toBe('prefs');
    expect(result!.contaminationSource).toBe('fetchExternalContent');
    expect(result!.sessionId).toBe('session-B');

    ledger.close();
  });

  it('should NOT emit signal when taint is from same session', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    // Same session: untrusted write
    graph.writeNode({
      nodeId: 'prefs',
      trustLevel: 'untrusted',
      sourceSessionId: 'session-A',
      source: 'fetchExternalContent',
      contentHash: hashContent('data'),
      timestamp: 1000,
    });

    // Same session read
    const ctx = makeCtx({
      toolName: 'readMemory',
      sessionId: 'session-A',
      toolArguments: { key: 'prefs' },
    });

    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'trusted');
    expect(result).toBeNull();

    ledger.close();
  });

  it('should detect transitive cross-session taint', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    // Session A writes untrusted data to node-a
    graph.writeNode({
      nodeId: 'node-a',
      trustLevel: 'untrusted',
      sourceSessionId: 'session-A',
      source: 'evilFetch',
      contentHash: 'aabb',
      timestamp: 1000,
    });
    // Node-b is trusted but has edge from node-a
    graph.writeNode({
      nodeId: 'node-b',
      trustLevel: 'trusted',
      sourceSessionId: 'session-A',
      source: 'transform',
      contentHash: 'ccdd',
      timestamp: 2000,
    });
    graph.addEdge({
      sourceNodeId: 'node-a',
      targetNodeId: 'node-b',
      sessionId: 'session-A',
      timestamp: 2000,
    });

    // Session B reads node-b
    const ctx = makeCtx({
      toolName: 'readMemory',
      sessionId: 'session-B',
      toolArguments: { key: 'node-b' },
    });

    const result = checkMemoryContamination(ctx, MEMORY_TOOLS, graph, ledger, 'trusted');

    expect(result).not.toBeNull();
    expect(result!.signal).toBe('CONTAMINATED_MEMORY_ACTIVE');
    expect(result!.contaminationSource).toBe('evilFetch');

    ledger.close();
  });

  it('should use custom extractors when provided', () => {
    const graph = createContaminationGraph();
    const ledger = createLedger();

    const customTools: readonly MemoryToolConfig[] = [
      {
        toolName: 'customWrite',
        operation: 'write',
        extractNodeId: (args) => args['path'] as string | undefined,
        extractContent: (args) => args['payload'] as string,
      },
    ];

    const ctx = makeCtx({
      toolName: 'customWrite',
      toolArguments: { path: '/data/file', payload: 'custom content' },
      toolResult: 'ok',
    });

    const result = checkMemoryContamination(ctx, customTools, graph, ledger, 'untrusted');

    expect(result).toBeNull(); // Write → no signal
    expect(graph.getNode('/data/file')).toBeDefined();

    ledger.close();
  });
});
