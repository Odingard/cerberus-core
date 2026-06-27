/**
 * Inter-component channel observation adapter — record a value crossing a
 * component / agent boundary as a real dependency edge in the TTP ledger.
 *
 * TTP's data-dependency model observes a value moving through a shared node
 * (read → write). It does NOT, by itself, see a value cross a component boundary
 * via an out-of-band channel: an Android Intent (`putExtra`/`getExtra`,
 * `startActivity`/`startService`/`sendBroadcast`), a static-field mailbox, or an
 * inter-agent message bus. That hop is invisible, so the receiver's downstream
 * writes are NOT linked back to the sender's tainted value and the sink escapes
 * the blast radius. (The TaintBench tranche measured this as the dominant
 * containment boundary — see `docs/taintbench/RESULTS.md`.)
 *
 * This adapter closes that gap with the SAME pattern as the live memory-store
 * adapter (`src/adapters/memory-store.ts`): it taps the send/receive of a named
 * channel and feeds the shared `MemoryProvenanceTracker`, so a cross-component
 * hop becomes an ordinary ledger edge through the one recording core. A *send*
 * writes a **channel node** (keyed by the channel identity) carrying the
 * sender's in-scope reads as its dependencies; a *receive* reads that channel
 * node, bringing it into the receiver's read scope so the receiver's next write
 * depends on it. Sender → channel → receiver is then a normal traced chain.
 *
 * ```typescript
 * const tracker = createMemoryProvenanceTracker();
 * const ipc = createIpcChannelTracker(tracker);
 * // component A puts the tainted value on an explicit-target Intent:
 * ipc.send('SmsListenerService', payload);
 * // component B reads it back:
 * ipc.receive('SmsListenerService', payload);   // now downstream writes are linked
 * ```
 *
 * **Channel identity is the host's responsibility, and the honest boundary lives
 * here.** The caller resolves a stable channel identity from the runtime
 * mechanics (an explicit Intent component class, a literal `putExtra` key, a
 * named static field). When the identity is NOT statically resolvable — an
 * implicit Intent resolved at runtime, a dynamically-constructed key, reflective
 * dispatch — the caller passes `null`, the adapter records nothing observable
 * (the hop stays severed), and increments `unresolved`. Nothing is contained by
 * fiat: an unresolved channel is a measured miss, not a silent pass.
 *
 * Depends on: src/adapters/memory-store.ts (the shared tracker + recording core).
 */

import type { ContaminatedMemorySignal, TrustLevel } from '../types/signals.js';
import type { MemoryProvenanceTracker } from './memory-store.js';

/** Stable ledger node ID for a channel identity (namespaced so it never collides with a memory key). */
export function ipcChannelNodeId(channelId: string): string {
  return `ipc:${channelId}`;
}

/** Options for {@link createIpcChannelTracker}. */
export interface IpcChannelTrackerOptions {
  /**
   * Trust level recorded for a channel send that doesn't specify one. Default
   * `unknown`. Set `untrusted` when the channel carries data from outside the
   * trust boundary so a later cross-session read of it trips L4.
   */
  readonly defaultTrustLevel?: TrustLevel;
  /** Source label for channel sends that don't specify one. Default `ipc-channel`. */
  readonly defaultSource?: string;
}

/** Per-send overrides. */
export interface IpcSendOptions {
  readonly trustLevel?: TrustLevel;
  readonly source?: string;
  readonly timestamp?: number;
}

/** Per-receive overrides. */
export interface IpcReceiveOptions {
  readonly timestamp?: number;
}

/** Running count of hops that could not be observed because the channel identity was unresolvable. */
export interface IpcUnresolvedCounts {
  sends: number;
  receives: number;
}

/**
 * A live binding between a component/agent communication channel and the TTP
 * ledger. Drives the same recording core the interceptor and the memory-store
 * adapter use, via the supplied {@link MemoryProvenanceTracker}.
 */
export interface IpcChannelTracker {
  /**
   * Record a channel SEND. Writes the channel node (claiming the sender's
   * in-scope reads as dependencies). Returns `true` if the send was observed,
   * `false` when `channelId` is unresolvable (`null`/empty) — in which case the
   * hop is left severed and {@link IpcChannelTracker.unresolved}.sends is bumped.
   */
  readonly send: (channelId: string | null, payload: string, options?: IpcSendOptions) => boolean;
  /**
   * Record a channel RECEIVE. Reads the channel node into the receiver's scope
   * and checks cross-session taint (returns the L4 signal or null). A `null`/
   * empty `channelId` is an unresolvable receive: nothing is read and
   * {@link IpcChannelTracker.unresolved}.receives is bumped.
   */
  readonly receive: (
    channelId: string | null,
    payload: string,
    options?: IpcReceiveOptions,
  ) => ContaminatedMemorySignal | null;
  /** Hops not observed because their channel identity was unresolvable (the disclosed residual). */
  readonly unresolved: IpcUnresolvedCounts;
  /** The shared tracker being fed (its graph / ledger / session). */
  readonly tracker: MemoryProvenanceTracker;
}

/**
 * Create an {@link IpcChannelTracker} over an existing
 * {@link MemoryProvenanceTracker}. Share the tracker with a `guard()` result or
 * a memory-store adapter so a channel hop and a memory/tool hop populate the
 * same ledger and link end-to-end.
 */
export function createIpcChannelTracker(
  tracker: MemoryProvenanceTracker,
  options: IpcChannelTrackerOptions = {},
): IpcChannelTracker {
  const defaultTrustLevel = options.defaultTrustLevel ?? 'unknown';
  const defaultSource = options.defaultSource ?? 'ipc-channel';
  const unresolved: IpcUnresolvedCounts = { sends: 0, receives: 0 };

  const send = (
    channelId: string | null,
    payload: string,
    sendOptions?: IpcSendOptions,
  ): boolean => {
    if (channelId === null || channelId.length === 0) {
      unresolved.sends++;
      return false;
    }
    tracker.write(ipcChannelNodeId(channelId), payload, {
      trustLevel: sendOptions?.trustLevel ?? defaultTrustLevel,
      source: sendOptions?.source ?? defaultSource,
      ...(sendOptions?.timestamp !== undefined ? { timestamp: sendOptions.timestamp } : {}),
    });
    return true;
  };

  const receive = (
    channelId: string | null,
    payload: string,
    receiveOptions?: IpcReceiveOptions,
  ): ContaminatedMemorySignal | null => {
    if (channelId === null || channelId.length === 0) {
      unresolved.receives++;
      return null;
    }
    return tracker.read(
      ipcChannelNodeId(channelId),
      payload,
      receiveOptions?.timestamp !== undefined ? { timestamp: receiveOptions.timestamp } : undefined,
    );
  };

  return { send, receive, unresolved, tracker };
}
