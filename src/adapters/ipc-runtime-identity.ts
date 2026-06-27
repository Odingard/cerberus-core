/**
 * Runtime channel-identity resolution — the live counterpart to the static
 * TaintBench resolver (`harness/taintbench/channel.ts`).
 *
 * The static resolver keys a cross-component hop off statement **text**: an
 * explicit `new Intent(ctx, X.class)`, a literal `putExtra("k", …)`, a named
 * static field. That is all a static analysis can see, so an *implicit* Intent
 * (target resolved by the OS at runtime) and a *dynamically-built* key (computed
 * at runtime) are unresolvable by construction — they carry no literal identity
 * in the source.
 *
 * At **runtime** those identities exist as concrete values: the OS dispatches an
 * implicit Intent to a concrete component, and a dynamic key evaluates to a
 * concrete string. A host's instrumentation (an Android Intent hook, an
 * inter-agent message-bus tap) observes those delivered values and reports them
 * as a {@link RuntimeChannelEvent}. This module turns such an event into the
 * SAME stable channel identity namespace the static resolver and the
 * `ipc-channel` adapter use (`class:` / `extra:` / `field:`), so a runtime hop
 * becomes an ordinary ledger edge through the one recording core.
 *
 * **This does NOT improve the static number.** It is a separate, live surface:
 * static text has no runtime values, so the static residual is permanent. Where
 * even a runtime surfaces no stable identity (an anonymous broadcast, a per-call
 * ephemeral target), this resolver returns `null` and the hop stays a measured
 * miss — never a silent pass.
 *
 * ```typescript
 * const ipc = createRuntimeIpcChannelTracker(createMemoryProvenanceTracker());
 * // implicit Intent the OS dispatched to a concrete component:
 * ipc.send({ resolvedComponent: 'com.app.SmsListenerService' }, payload);
 * ipc.receive({ resolvedComponent: 'com.app.SmsListenerService' }, payload);
 * ```
 *
 * Depends on: src/adapters/ipc-channel.ts (the channel observation adapter).
 */

import type {
  IpcChannelTracker,
  IpcChannelTrackerOptions,
  IpcReceiveOptions,
  IpcSendOptions,
  IpcUnresolvedCounts,
} from './ipc-channel.js';
import { createIpcChannelTracker } from './ipc-channel.js';
import type { MemoryProvenanceTracker } from './memory-store.js';
import type { ContaminatedMemorySignal } from '../types/signals.js';

/**
 * The runtime-delivered identity fields a host's instrumentation observed for a
 * single channel send or receive. All fields are optional/nullable: the host
 * reports only what its runtime actually surfaced. A field is "present" only
 * when it is a non-empty string after trimming.
 */
export interface RuntimeChannelEvent {
  /**
   * The concrete component the runtime dispatched this hop to — an explicit
   * target, or the component an *implicit* Intent resolved to at runtime.
   * `null`/absent when the runtime did not surface a stable component (e.g. an
   * anonymous broadcast with a dynamic receiver set).
   */
  readonly resolvedComponent?: string | null;
  /**
   * The concrete extra-key string evaluated at runtime — a literal key, or the
   * runtime *value* of a dynamically-built key. `null`/absent when no key
   * identifies the hop, or when the key is a per-call nonce that does not agree
   * across send and receive.
   */
  readonly resolvedKey?: string | null;
  /**
   * A named static-field / mailbox identity the runtime used. `null`/absent when
   * none applies.
   */
  readonly mailbox?: string | null;
}

function present(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Resolve a stable channel identity from a runtime channel event, or `null` when
 * the runtime surfaced none (the disclosed residual). Pure and mechanics-keyed:
 * it reads ONLY the delivered identity fields, in a fixed priority order
 * (component → extra key → mailbox), identically for every hop. It never reads a
 * "should-resolve" label.
 *
 * A hop is observed end-to-end only when BOTH its send and its receive resolve to
 * the SAME identity (the runtime analog of the static rule: match send↔receive
 * only on an identity that agrees; residual stays severed by construction).
 */
export function resolveRuntimeChannelIdentity(event: RuntimeChannelEvent): string | null {
  const cls = present(event.resolvedComponent);
  if (cls !== null) return `class:${cls}`;
  const key = present(event.resolvedKey);
  if (key !== null) return `extra:${key}`;
  const field = present(event.mailbox);
  if (field !== null) return `field:${field}`;
  return null;
}

/**
 * A live binding that drives the {@link IpcChannelTracker} from runtime channel
 * events: it resolves each event's identity with
 * {@link resolveRuntimeChannelIdentity} and forwards to the underlying adapter.
 * An event that resolves to `null` is an unresolvable hop — the adapter leaves it
 * severed and bumps `unresolved`.
 */
export interface RuntimeIpcChannelTracker {
  /** Record a SEND from a runtime channel event. Returns `false` when unresolvable. */
  readonly send: (event: RuntimeChannelEvent, payload: string, options?: IpcSendOptions) => boolean;
  /** Record a RECEIVE from a runtime channel event. Returns the L4 signal or `null`. */
  readonly receive: (
    event: RuntimeChannelEvent,
    payload: string,
    options?: IpcReceiveOptions,
  ) => ContaminatedMemorySignal | null;
  /** Hops not observed because their runtime identity was unresolvable (the disclosed residual). */
  readonly unresolved: IpcUnresolvedCounts;
  /** The underlying channel tracker (and its shared ledger). */
  readonly channel: IpcChannelTracker;
}

/**
 * Create a {@link RuntimeIpcChannelTracker} over an existing
 * {@link MemoryProvenanceTracker}, wiring the runtime resolver to a fresh
 * {@link IpcChannelTracker}. Share the tracker with a `guard()` result so a
 * runtime channel hop and a memory/tool hop populate the same ledger.
 */
export function createRuntimeIpcChannelTracker(
  tracker: MemoryProvenanceTracker,
  options: IpcChannelTrackerOptions = {},
): RuntimeIpcChannelTracker {
  const channel = createIpcChannelTracker(tracker, options);
  return {
    send: (event, payload, sendOptions): boolean =>
      channel.send(resolveRuntimeChannelIdentity(event), payload, sendOptions),
    receive: (event, payload, receiveOptions): ContaminatedMemorySignal | null =>
      channel.receive(resolveRuntimeChannelIdentity(event), payload, receiveOptions),
    unresolved: channel.unresolved,
    channel,
  };
}
