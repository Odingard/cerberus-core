/**
 * Live framework memory adapter — feed a framework's NATIVE memory store into
 * the TTP provenance ledger, with no guarded tool executors and no hand-declared
 * `memoryTools`.
 *
 * The `guard()` path only feeds the L4 contamination graph + provenance ledger
 * when memory operations flow through a wrapped tool executor that the developer
 * has explicitly tagged as a memory read/write (`memoryOptions.memoryTools`).
 * But real agent frameworks keep memory in their OWN subsystems — a LangGraph
 * `BaseStore` / checkpointer, a LangChain retriever / vector store — which never
 * pass through a Cerberus-wrapped tool executor. Those reads/writes are
 * therefore invisible to the ledger.
 *
 * This adapter closes that gap. Wrap the store once:
 *
 * ```typescript
 * const tracker = createMemoryProvenanceTracker();
 * const store = guardMemoryStore(myStore, tracker);   // drop-in replacement
 * // …use `store` exactly as before. Every put → a traced ledger write,
 * // every get/search → a traced read that checks cross-session taint.
 * // tracker.ledger.getDescendants(poisonedNodeId) — blast radius B(p): a
 * // production capability of the durable ledger (@cerberus-ai/enterprise).
 * // The basic open ledger captures provenance and detects in-session taint.
 * ```
 *
 * The recording goes through the SAME core the interceptor uses
 * (`recordMemoryWrite` / `recordMemoryRead` in `src/layers/l4-memory.ts`), so a
 * store-fed write and a tool-fed write produce identical ledger rows.
 *
 * Depends on: src/layers/l4-memory.ts, src/graph/contamination.ts,
 * src/graph/ledger.ts, src/engine/session.ts
 */

import type { ContaminatedMemorySignal, TrustLevel, TurnId } from '../types/signals.js';
import type { MemoryDependencyGateConfig } from '../types/config.js';
import type { DetectionSession } from '../engine/session.js';
import { createSession, resetSession, checkpointScope } from '../engine/session.js';
import type { ContaminationGraph } from '../graph/contamination.js';
import { createContaminationGraph } from '../graph/contamination.js';
import type { ProvenanceLedger } from '../graph/ledger.js';
import { createInMemoryLedger } from '../graph/ledger.js';
import type { AgentSigner } from '../graph/authorship.js';
import { recordMemoryRead, recordMemoryWrite } from '../layers/l4-memory.js';

// ── Tracker ─────────────────────────────────────────────────────────

/** Options for {@link createMemoryProvenanceTracker}. */
export interface MemoryProvenanceTrackerOptions {
  /**
   * An existing detection session to share (e.g. from a `guard()` result, so a
   * store-fed read can be claimed as a dependency by a tool-fed write and vice
   * versa). Omitted = the tracker creates its own session.
   */
  readonly session?: DetectionSession;
  /** An existing contamination graph to share. Omitted = create one. */
  readonly graph?: ContaminationGraph;
  /** An existing provenance ledger to share. Omitted = create one. */
  readonly ledger?: ProvenanceLedger;
  /**
   * SQLite path for the ledger when the tracker creates its own. Default
   * `:memory:`. Ignored when an existing `ledger` is supplied.
   */
  readonly dbPath?: string;
  /** Read-relevance (content-derivation) gate applied to write dependencies. */
  readonly gate?: MemoryDependencyGateConfig;
  /**
   * Trust level recorded for writes that don't specify one. Default `unknown`.
   * Set `untrusted` when the wrapped store holds content sourced from outside
   * the trust boundary (retrieved documents, tool output, user uploads), so a
   * later cross-session read of that content trips L4.
   */
  readonly defaultTrustLevel?: TrustLevel;
  /** Source label for writes that don't specify one. Default `memory-store`. */
  readonly defaultSource?: string;
  /**
   * Invoked whenever a read detects cross-session contamination. Use it to
   * interrupt the agent, quarantine the blast radius, alert, etc. The read
   * itself still returns its value — enforcement is the caller's policy.
   */
  readonly onContamination?: (signal: ContaminatedMemorySignal) => void;
}

/** Per-write overrides for {@link MemoryProvenanceTracker.write}. */
export interface MemoryWriteOptions {
  readonly trustLevel?: TrustLevel;
  readonly source?: string;
  readonly timestamp?: number;
  readonly signer?: AgentSigner;
  readonly declaredDeps?: readonly string[];
}

/** Per-read overrides for {@link MemoryProvenanceTracker.read}. */
export interface MemoryReadOptions {
  readonly timestamp?: number;
}

/**
 * A live binding between a framework's memory operations and the TTP ledger.
 * Drives the same recording core the interceptor uses.
 */
export interface MemoryProvenanceTracker {
  /**
   * Record a memory READ. Adds it to the session's in-scope read-set and checks
   * for cross-session taint; returns the L4 signal (also passed to
   * `onContamination`) or null.
   */
  readonly read: (
    nodeId: string,
    content: string,
    options?: MemoryReadOptions,
  ) => ContaminatedMemorySignal | null;
  /** Record a memory WRITE (node + dependency edges + ledger row). */
  readonly write: (nodeId: string, content: string, options?: MemoryWriteOptions) => void;
  /** Rotate the session (cross-session boundary). See `guard().reset`. */
  readonly reset: (carriedReads?: Iterable<string>) => void;
  /** Clear only the observed-read scope (frontier checkpoint). */
  readonly checkpoint: () => void;
  /** The shared detection session. */
  readonly session: DetectionSession;
  /** The contamination graph being fed. */
  readonly graph: ContaminationGraph;
  /** The provenance ledger being fed (blast radius, history, containment). */
  readonly ledger: ProvenanceLedger;
  /**
   * Close resources the tracker OWNS (the ledger/graph it created). A no-op for
   * graph/ledger passed in by the caller — those are owned by the caller.
   */
  readonly destroy: () => void;
}

/**
 * Create a {@link MemoryProvenanceTracker}. With no options it owns a fresh
 * in-memory graph + ledger + session; pass an existing `session`/`graph`/
 * `ledger` (e.g. from a `guard()` result) to share state with the tool path.
 */
export function createMemoryProvenanceTracker(
  options: MemoryProvenanceTrackerOptions = {},
): MemoryProvenanceTracker {
  const session = options.session ?? createSession();
  const graph = options.graph ?? createContaminationGraph();
  // Track ownership so destroy() only tears down what this tracker created.
  const ownsGraph = options.graph === undefined;
  const ownsLedger = options.ledger === undefined;
  const ledger =
    options.ledger ?? createInMemoryLedger(options.dbPath ? { dbPath: options.dbPath } : {});
  const gate = options.gate;
  const defaultTrustLevel = options.defaultTrustLevel ?? 'unknown';
  const defaultSource = options.defaultSource ?? 'memory-store';
  const onContamination = options.onContamination;

  // Local turn counter so the tracker never perturbs the detection pipeline's
  // own `session.turnCounter` when a guard() session is shared.
  let turnSeq = 0;
  const nextTurnId = (): TurnId => `memory-store-turn-${String(turnSeq++)}`;

  const read = (
    nodeId: string,
    content: string,
    readOptions?: MemoryReadOptions,
  ): ContaminatedMemorySignal | null => {
    const signal = recordMemoryRead(
      {
        nodeId,
        content,
        sessionId: session.sessionId,
        turnId: nextTurnId(),
        timestamp: readOptions?.timestamp ?? Date.now(),
      },
      graph,
      session,
    );
    if (signal && onContamination) {
      onContamination(signal);
    }
    return signal;
  };

  const write = (nodeId: string, content: string, writeOptions?: MemoryWriteOptions): void => {
    recordMemoryWrite(
      {
        nodeId,
        content,
        trustLevel: writeOptions?.trustLevel ?? defaultTrustLevel,
        sessionId: session.sessionId,
        source: writeOptions?.source ?? defaultSource,
        timestamp: writeOptions?.timestamp ?? Date.now(),
        ...(writeOptions?.signer ? { signer: writeOptions.signer } : {}),
        ...(writeOptions?.declaredDeps ? { declaredDeps: writeOptions.declaredDeps } : {}),
      },
      graph,
      ledger,
      session,
      gate,
    );
  };

  const reset = (carriedReads?: Iterable<string>): void => {
    resetSession(session, carriedReads);
  };

  const checkpoint = (): void => {
    checkpointScope(session);
  };

  const destroy = (): void => {
    if (ownsLedger) {
      ledger.close();
    }
    if (ownsGraph) {
      graph.clear();
    }
  };

  return { read, write, reset, checkpoint, session, graph, ledger, destroy };
}

// ── Generic store wrapper ───────────────────────────────────────────

/**
 * The minimal duck-typed key/value store this adapter understands. The wrapper
 * targets **async** memory subsystems — a LangChain `BaseStore`-style store, a
 * Redis/KV cache wrapper, or any object whose `get(key)` / `put(key, value)`
 * return a value or a Promise of one. The wrapped accessors always return
 * Promises (the adapter awaits the underlying op), so a purely synchronous
 * store that relies on `get`/`put` returning a non-Promise value is NOT a
 * drop-in target. Extra methods (`delete`, etc.) are preserved untouched on the
 * returned proxy.
 */
export interface GuardableKVStore {
  get(key: string): unknown;
  put(key: string, value: unknown): unknown;
}

/** How to derive a ledger node ID + content string from a store key/value. */
export interface StoreMapping {
  /** Node ID for a key. Default: the key verbatim. */
  readonly nodeId?: (key: string) => string;
  /** Content string for a stored/retrieved value. Default: JSON / String(). */
  readonly content?: (value: unknown) => string;
  /** Per-key write overrides (trust level, source, …). */
  readonly writeOptions?: (key: string, value: unknown) => MemoryWriteOptions | undefined;
}

/** Default content stringifier: JSON for objects, `String()` otherwise. */
export function defaultStoreContent(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    // Unserializable (circular ref, BigInt, …) — store a stable placeholder
    // rather than risk an exception or an unhelpful '[object Object]'.
    return '[unserializable]';
  }
}

/**
 * Wrap an **async** duck-typed key/value store so every `put` is recorded as a
 * traced ledger WRITE and every `get` (that returns a value) as a traced READ.
 * Returns a proxy that preserves the original object's other methods; the
 * wrapped `get`/`put` always return Promises (see {@link GuardableKVStore}).
 *
 * The ledger write is recorded only AFTER the underlying `store.put` resolves,
 * matching the `guard()` interceptor (which records after the executor
 * succeeds) — a rejected store write therefore never leaves a phantom
 * provenance record.
 *
 * This is the turnkey "deploy → memory auto-traced" path for a KV-shaped store.
 * For a LangGraph namespaced `BaseStore`, use {@link guardLangGraphStore}.
 */
export function guardMemoryStore<S extends GuardableKVStore>(
  store: S,
  tracker: MemoryProvenanceTracker,
  mapping: StoreMapping = {},
): S {
  const toNodeId = mapping.nodeId ?? ((key: string): string => key);
  const toContent = mapping.content ?? defaultStoreContent;

  const wrappedGet = async (key: string): Promise<unknown> => {
    const value = await store.get(key);
    if (value !== null && value !== undefined) {
      tracker.read(toNodeId(key), toContent(value));
    }
    return value;
  };

  const wrappedPut = async (key: string, value: unknown): Promise<unknown> => {
    const result = await store.put(key, value);
    const options = mapping.writeOptions?.(key, value);
    tracker.write(toNodeId(key), toContent(value), options);
    return result;
  };

  // Return a proxy that overrides get/put but forwards everything else (and
  // keeps `this` bound to the original store for forwarded methods).
  return new Proxy(store, {
    get(target, prop, receiver): unknown {
      if (prop === 'get') {
        return wrappedGet;
      }
      if (prop === 'put') {
        return wrappedPut;
      }
      const value: unknown = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}

// ── LangGraph BaseStore wrapper ─────────────────────────────────────

/**
 * The duck-typed shape of a LangGraph `BaseStore` (the long-term memory store
 * passed to a compiled graph). Namespaces are string arrays; items carry a
 * `.value` record.
 */
export interface LangGraphStoreItem {
  readonly value: Record<string, unknown>;
  readonly key?: string;
  readonly namespace?: readonly string[];
}

/** The duck-typed shape of a LangGraph `BaseStore` that can be wrapped by {@link guardLangGraphStore}. */
export interface GuardableLangGraphStore {
  get(namespace: string[], key: string): Promise<LangGraphStoreItem | null>;
  put(namespace: string[], key: string, value: Record<string, unknown>): Promise<void>;
  search?(
    namespacePrefix: string[],
    options?: Record<string, unknown>,
  ): Promise<readonly LangGraphStoreItem[]>;
}

/** Flatten a LangGraph (namespace, key) pair into a stable ledger node ID. */
export function langGraphNodeId(namespace: readonly string[], key: string): string {
  return [...namespace, key].join('/');
}

/**
 * Wrap a LangGraph `BaseStore` so its long-term memory operations feed the TTP
 * ledger live: each `put(namespace, key, value)` is a traced write, each `get`
 * / `search` result is a traced read (checking cross-session taint). Returns a
 * drop-in proxy; non-instrumented methods (`delete`, `batch`, `listNamespaces`,
 * …) are forwarded unchanged.
 *
 * ```typescript
 * const tracker = createMemoryProvenanceTracker({ defaultTrustLevel: 'untrusted' });
 * const graph = workflow.compile({ store: guardLangGraphStore(baseStore, tracker) });
 * ```
 */
export function guardLangGraphStore<S extends GuardableLangGraphStore>(
  store: S,
  tracker: MemoryProvenanceTracker,
): S {
  // A search result carries its own (namespace, key); unlike `get` there is no
  // caller-supplied fallback. A standard BaseStore always populates both, but a
  // non-standard store could return a bare `{ value }` item whose read we cannot
  // attribute to a stable node ID. Rather than drop it silently (silent data
  // loss in a provenance ledger is exactly what a reviewer flags), warn once.
  let warnedUnidentifiableSearchItem = false;

  const recordItemRead = (item: LangGraphStoreItem | null, fallbackNodeId?: string): void => {
    if (!item) {
      return;
    }
    const nodeId =
      item.namespace && item.key
        ? langGraphNodeId(item.namespace, item.key)
        : (fallbackNodeId ?? '');
    if (nodeId) {
      tracker.read(nodeId, defaultStoreContent(item.value));
    } else if (!warnedUnidentifiableSearchItem) {
      warnedUnidentifiableSearchItem = true;
      // eslint-disable-next-line no-console
      console.warn(
        '[cerberus] guardLangGraphStore: a search result without namespace+key ' +
          'cannot be attributed to a ledger node and is not traced. ' +
          '(This warning fires once.)',
      );
    }
  };

  const wrappedGet = async (
    namespace: string[],
    key: string,
  ): Promise<LangGraphStoreItem | null> => {
    const item = await store.get(namespace, key);
    recordItemRead(item, langGraphNodeId(namespace, key));
    return item;
  };

  const wrappedPut = async (
    namespace: string[],
    key: string,
    value: Record<string, unknown>,
  ): Promise<void> => {
    await store.put(namespace, key, value);
    tracker.write(langGraphNodeId(namespace, key), defaultStoreContent(value));
  };

  const wrappedSearch = store.search
    ? async (
        namespacePrefix: string[],
        searchOptions?: Record<string, unknown>,
      ): Promise<readonly LangGraphStoreItem[]> => {
        const items = await store.search!(namespacePrefix, searchOptions);
        for (const item of items) {
          recordItemRead(item);
        }
        return items;
      }
    : undefined;

  return new Proxy(store, {
    get(target, prop, receiver): unknown {
      if (prop === 'get') {
        return wrappedGet;
      }
      if (prop === 'put') {
        return wrappedPut;
      }
      if (prop === 'search' && wrappedSearch) {
        return wrappedSearch;
      }
      const value: unknown = Reflect.get(target, prop, receiver);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
