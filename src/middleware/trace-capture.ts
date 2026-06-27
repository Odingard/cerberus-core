/**
 * Memory trace-capture — opt-in recorder for REAL agent memory access patterns.
 *
 * Records the ordered `readMemory` / `writeMemory` sequence (and the session
 * boundaries) of a real agent session in a REPLAYABLE format, so the same
 * read/write structure can later be driven back through the harness for
 * behavioral measurement (latency, per-write overhead, observed read fan-in,
 * blast-radius distribution) and a synthetic-vs-real realism comparison.
 *
 * Design goals (Spec D, Part 1):
 *   - OPT-IN: capture only happens when a recorder is passed to `guard()` via
 *     `memoryOptions.recorder`. No recorder → no capture work at all.
 *   - ZERO-IMPACT WHEN DISABLED: the interceptor's only added cost when no
 *     recorder is configured is a single `if (recorder)` falsy check. No
 *     allocation, no extraction, no detection-pipeline change.
 *   - REPLAYABLE: the captured ops are the same `reset | read | write` shape the
 *     synthetic generator emits, so they replay through the existing driver
 *     path verbatim and reconstruct the observed-read dependency structure.
 *   - NO RAW SECRET/PII CONTENT: write content is NEVER stored verbatim. The
 *     default `hash` redaction stores `sha256:<hex>` of the content (a one-way
 *     reference that preserves write-equality for dedup but reveals nothing);
 *     `sanitized` stores the output of a caller-supplied sanitizer. Node IDs
 *     (memory keys) are stored as-is — keep keys non-sensitive, or pass a
 *     `keyRedactor` to hash/alias them too.
 *
 * Depends on: node:crypto (hashing only — no SQLite, kept lightweight).
 */

import { createHash } from 'node:crypto';

/** Current on-disk format version for a {@link CapturedTrace}. */
export const TRACE_FORMAT_VERSION = 1;

/**
 * How a captured write's content is redacted before it is stored.
 * - `hash` (default): store `sha256:<hex>` of the content — a one-way reference
 *   that never reveals the content but preserves equality (identical content →
 *   identical reference), so write dedup is observable in replay.
 * - `sanitized`: store the output of a caller-supplied `sanitize(content)`. The
 *   caller is responsible for ensuring the result contains no secret/PII.
 */
export type CaptureRedactionMode = 'hash' | 'sanitized';

/**
 * A single captured memory op, in replay order. Structurally identical to the
 * harness `DriveStep` so a captured trace replays through the existing driver
 * without translation:
 * - `reset`  — a session boundary (the agent's `guard().reset()` was called).
 * - `read`   — a `readMemory` of `nodeId` (the memory key).
 * - `write`  — a `writeMemory` of `nodeId`, carrying the REDACTED content
 *   reference (never raw content).
 */
export type CapturedMemoryOp =
  | { readonly op: 'reset' }
  | { readonly op: 'read'; readonly nodeId: string }
  | {
      readonly op: 'write';
      readonly nodeId: string;
      readonly content: string;
      /**
       * Item 2 (instrumented real-workload capture) — the agent's SELF-DECLARED
       * derivation for this write: the prior memory keys it says it actually
       * used. Present ONLY on instrumented traces (`meta.instrumented`); absent
       * on the behavior-only capture path, which is unchanged. These are the
       * ground truth the real-workload accuracy numbers are scored against.
       * Node IDs are passed through the same `keyRedactor` as reads/writes.
       */
      readonly declaredDeps?: readonly string[];
      /**
       * Item 2 cross-check — the memory keys that were AVAILABLE to the agent at
       * write time (e.g. the LangGraph node's input channels). `available \
       * declared` bounds possible UNDER-declaration: the gap an honest-but-
       * incomplete declaration could be hiding. Present only when the framework
       * cheaply exposes it; absent otherwise (fast-follow, never blocks v1).
       */
      readonly availableDeps?: readonly string[];
    };

/** Provenance + redaction metadata carried with every captured trace. */
export interface CapturedTraceMeta {
  /** On-disk format version. */
  readonly formatVersion: number;
  /** Free-form source label (e.g. `live`, the agent/app name, or `fixture`). */
  readonly source: string;
  /**
   * TRUE when this trace is a synthetic/example fixture, NOT real production
   * data. Replay + comparison tooling surfaces this so fixture-derived realism
   * numbers are never mistaken for measurements over real agent traffic.
   */
  readonly fixture: boolean;
  /** Which redaction mode produced the stored write-content references. */
  readonly redaction: CaptureRedactionMode;
  /** Whether node IDs (memory keys) were passed through a redactor. */
  readonly keysRedacted: boolean;
  /** ISO-8601 timestamp the trace snapshot was taken. */
  readonly capturedAt: string;
  /** Optional human note (e.g. the ingestion/plug-in point for real traces). */
  readonly note?: string;
  /**
   * Item 2 — TRUE when this trace carries SELF-DECLARED derivation on its write
   * ops (so it has ground truth by construction and accuracy can be scored).
   * Absent/false = the behavior-only capture (no oracle; precision/recall stay
   * undefined, as before). The declaration is the agent's stated usage, NOT
   * constructed truth — an incomplete declaration is the documented residual.
   */
  readonly instrumented?: boolean;
}

/** A replayable capture of a real (or fixture) agent memory session. */
export interface CapturedTrace {
  readonly meta: CapturedTraceMeta;
  /** The ordered read/write/reset ops, ready to replay through the harness. */
  readonly ops: readonly CapturedMemoryOp[];
}

/**
 * The capture handle threaded into `guard()`. The interceptor calls
 * `recordRead` / `recordWrite` as memory tools fire, and `guard().reset()`
 * calls `recordReset` at session boundaries. `snapshot()` returns the
 * accumulated replayable trace at any point.
 */
export interface MemoryTraceRecorder {
  /** Record a memory read of `nodeId` (the memory key). */
  readonly recordRead: (nodeId: string) => void;
  /**
   * Record a memory write of `nodeId`; `content` is redacted before storage.
   * On an instrumented recorder, pass the agent's `declaration` (self-declared
   * derivation + available keys) — its node IDs are redacted like reads/writes.
   * Omitting `declaration` on an instrumented recorder records an undeclared
   * write (a declared root). Ignored when the recorder is not instrumented.
   */
  readonly recordWrite: (nodeId: string, content: string, declaration?: WriteDerivation) => void;
  /** Record a session boundary (a `reset()` rotated the read scope). */
  readonly recordReset: () => void;
  /** Number of ops recorded so far (reads + writes + resets). */
  readonly size: () => number;
  /** Return the accumulated, replayable trace (a defensive copy). */
  readonly snapshot: () => CapturedTrace;
}

/** Options controlling how a {@link MemoryTraceRecorder} redacts and labels. */
export interface TraceRecorderOptions {
  /** Source label stored on the trace. Default `live`. */
  readonly source?: string;
  /** Mark the trace as a fixture (NOT real data). Default `false`. */
  readonly fixture?: boolean;
  /** Write-content redaction mode. Default `hash`. */
  readonly redaction?: CaptureRedactionMode;
  /**
   * Required when `redaction` is `sanitized`: maps raw content → a stored
   * reference guaranteed free of secret/PII. Ignored in `hash` mode.
   */
  readonly sanitize?: (content: string) => string;
  /**
   * Optional node-ID (memory key) redactor — apply when keys themselves may be
   * sensitive (e.g. embed a user id). Applied to BOTH reads and writes so the
   * dependency structure stays consistent. Omitted = keys stored verbatim.
   */
  readonly keyRedactor?: (nodeId: string) => string;
  /** Optional human note stored on the trace. */
  readonly note?: string;
  /**
   * Item 2 — mark this trace as INSTRUMENTED: its write ops will carry the
   * agent's self-declared derivation (passed to `recordWrite`'s `declaration`),
   * and `meta.instrumented` is set so downstream scoring treats the declaration
   * as ground truth. Omitted/false = behavior-only capture (unchanged).
   */
  readonly instrumented?: boolean;
}

/** Item 2 — the agent's self-declared derivation for a single write. */
export interface WriteDerivation {
  /** Prior memory keys the agent says this write actually used (ground truth). */
  readonly declaredDeps?: readonly string[];
  /** Memory keys that were AVAILABLE at write time (the under-declaration bound). */
  readonly availableDeps?: readonly string[];
}

/** SHA-256 hex of `content`, prefixed `sha256:` — the default content reference. */
function hashRef(content: string): string {
  return `sha256:${createHash('sha256').update(content, 'utf8').digest('hex')}`;
}

/**
 * Create an in-memory {@link MemoryTraceRecorder}. Pass it to `guard()` via
 * `memoryOptions.recorder` to capture a session, then `snapshot()` the result.
 *
 * @throws if `redaction` is `sanitized` but no `sanitize` function is provided.
 */
export function createTraceRecorder(options: TraceRecorderOptions = {}): MemoryTraceRecorder {
  const redaction: CaptureRedactionMode = options.redaction ?? 'hash';
  const sanitize = options.sanitize;
  if (redaction === 'sanitized' && !sanitize) {
    throw new Error(
      "createTraceRecorder: redaction 'sanitized' requires a sanitize(content) function",
    );
  }
  const keyRedactor = options.keyRedactor;
  const redactKey = (nodeId: string): string => (keyRedactor ? keyRedactor(nodeId) : nodeId);
  const redactContent = (content: string): string =>
    redaction === 'sanitized' ? sanitize!(content) : hashRef(content);
  const instrumented = options.instrumented ?? false;

  const ops: CapturedMemoryOp[] = [];

  const recordRead = (nodeId: string): void => {
    ops.push({ op: 'read', nodeId: redactKey(nodeId) });
  };

  const recordWrite = (nodeId: string, content: string, declaration?: WriteDerivation): void => {
    // Behavior-only path: a plain write op, byte-identical to before. The
    // declared-derivation fields are added ONLY on an instrumented recorder,
    // and only when the caller actually passes a declaration.
    const declared =
      instrumented && declaration?.declaredDeps
        ? { declaredDeps: declaration.declaredDeps.map(redactKey) }
        : {};
    const available =
      instrumented && declaration?.availableDeps
        ? { availableDeps: declaration.availableDeps.map(redactKey) }
        : {};
    ops.push({
      op: 'write',
      nodeId: redactKey(nodeId),
      content: redactContent(content),
      ...declared,
      ...available,
    });
  };

  const recordReset = (): void => {
    ops.push({ op: 'reset' });
  };

  const snapshot = (): CapturedTrace => ({
    meta: {
      formatVersion: TRACE_FORMAT_VERSION,
      source: options.source ?? 'live',
      fixture: options.fixture ?? false,
      redaction,
      keysRedacted: keyRedactor !== undefined,
      capturedAt: new Date().toISOString(),
      ...(options.note !== undefined ? { note: options.note } : {}),
      ...(instrumented ? { instrumented: true } : {}),
    },
    ops: ops.map((o) => ({ ...o })),
  });

  return { recordRead, recordWrite, recordReset, size: () => ops.length, snapshot };
}

/** Serialize a captured trace to the canonical JSON form (trailing newline). */
export function serializeTrace(trace: CapturedTrace): string {
  return `${JSON.stringify(trace, null, 2)}\n`;
}
