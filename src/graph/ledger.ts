/**
 * Provenance Ledger — type contracts, integrity utilities, and the basic
 * in-memory ledger (open tier).
 *
 * The open tier ships an append-only, in-memory provenance ledger: it captures
 * every memory write (source, trust level, timestamp, session, content hash,
 * observed-read deps) and the dependency edges between them, and answers
 * in-session taint queries (`isNodeTainted` / `isCrossSessionTainted`). That is
 * enough to PROVE the mechanism — a developer can see provenance tracking and
 * contamination detection run.
 *
 * The PRODUCTION ledger — durable SQLite persistence, the forward blast-radius
 * B(p) (`getDescendants`), containment (`quarantine*`), the provenance-summary
 * scale lever, and AL3 authorship verification — is the licensed engine and
 * lives in `@cerberus-ai/enterprise` (`graph/durable-ledger.ts`). It implements
 * this same `ProvenanceLedger` contract, so a paid deployment injects it wherever
 * the open tier would use the basic in-memory ledger (dependency inversion).
 *
 * The basic ledger throws a clear upgrade error from the production-only methods
 * rather than silently returning a partial answer — a containment / blast-radius
 * call must never quietly misrepresent that it did nothing.
 *
 * Depends on: node:crypto, src/types/signals.ts
 */

import { createHash } from 'node:crypto';
import type { TrustLevel } from '../types/signals.js';
import type { AgentSigner, AgentKeyRegistry } from './authorship.js';
import type { ProvenanceSummaryParams } from './provenance-summary.js';

// ── Types ───────────────────────────────────────────────────────────

/** A single provenance record from the ledger. */
export interface ProvenanceRecord {
  readonly nodeId: string;
  readonly sessionId: string;
  readonly trustLevel: TrustLevel;
  readonly source: string;
  readonly contentHash: string;
  readonly timestamp: number;
  /**
   * Observed-read dependencies: nodeIds observed read before this write.
   * A conservative OVER-APPROXIMATION of true data dependencies (the framework
   * cannot know which reads actually informed the write), so the forward
   * reachable set B(p) is a conservative UPPER BOUND on contamination.
   * Empty = a root (sensor / externally-attested input).
   */
  readonly deps: readonly string[];
  /** Tamper-evident commitment binding content + deps: SHA-256(contentHash ‖ sorted(deps)). */
  readonly commitment: string;
  /**
   * Claimed author (agent/writer) of this record. Empty/absent = an unsigned
   * record (AL2 integrity only — no authenticated authorship).
   */
  readonly author?: string;
  /**
   * Ed25519 signature (base64) by the author over (commitment ‖ author),
   * proving WHO wrote the record (AL3). Absent on unsigned records.
   */
  readonly signature?: string;
}

/**
 * Input shape for {@link ProvenanceLedger.recordWrite}.
 *
 * `deps` defaults to `[]` (root) and `commitment` is computed from
 * `contentHash` + `deps` when omitted. `deps` are observed-read deps (a
 * conservative over-approximation), not an exact dependency set.
 */
export type ProvenanceWriteInput = Omit<ProvenanceRecord, 'deps' | 'commitment'> & {
  readonly deps?: readonly string[];
  readonly commitment?: string;
  /**
   * Optional per-agent signer. When provided, the write path signs the record's
   * content+deps commitment as `signer.author` and persists both `author` and
   * `signature` (AL3). The signer's private key is never seen by the ledger.
   * A `signer` takes precedence over any explicit `author`/`signature`.
   */
  readonly signer?: AgentSigner;
  /**
   * Item 2 (instrumented real-workload capture) — the agent's SELF-DECLARED
   * derivation: the prior node IDs the agent says this write actually used. A
   * SEPARATE, additive channel persisted alongside the observed-read `deps` by
   * the production ledger; ignored by the basic in-memory ledger.
   */
  readonly declaredDeps?: readonly string[];
};

/** A directed dependency edge persisted in the ledger (data flowed source → target). */
export interface ProvenanceEdge {
  readonly sourceNodeId: string;
  readonly targetNodeId: string;
  readonly sessionId: string;
  readonly timestamp: number;
}

/** Disposition applied to a record by a containment action. */
export type TaintDisposition = 'quarantine';

/** An append-only containment annotation. Never mutates the original record. */
export interface TaintAnnotation {
  readonly nodeId: string;
  /** The poisoned record that triggered this containment. */
  readonly sourcePoisonId: string;
  readonly disposition: TaintDisposition;
  readonly reason: string;
  readonly timestamp: number;
}

/** Options for creating a ledger instance. */
export interface LedgerOptions {
  /**
   * Durable SQLite path. Honored only by the licensed production ledger
   * (`@cerberus-ai/enterprise`). The basic in-memory ledger has no persistence;
   * passing a `dbPath` to it is a no-op (it warns once).
   */
  readonly dbPath?: string;
  /**
   * Public-key registry used by `verifyAuthorship`/`verifyNodeAuthorship` to
   * resolve a record's *claimed* author to a verification key (AL3). Honored
   * only by the licensed production ledger.
   */
  readonly keyRegistry?: AgentKeyRegistry;
  /**
   * Provenance-summary scale lever (§5.3f). Honored only by the licensed
   * production ledger.
   */
  readonly summary?: ProvenanceSummaryParams;
  /**
   * Item 2 declared-derivation channel. Honored only by the licensed production
   * ledger.
   */
  readonly declaredDerivation?: boolean;
}

/** Provenance ledger contract — implemented by the basic in-memory ledger
 * (open) and the durable SQLite ledger (`@cerberus-ai/enterprise`). */
export interface ProvenanceLedger {
  /** Record a memory write, persisting the record and its dependency edges. */
  readonly recordWrite: (record: ProvenanceWriteInput) => void;
  /** Query all writes to a node, ordered by timestamp desc. */
  readonly getNodeHistory: (nodeId: string) => readonly ProvenanceRecord[];
  /** Query the latest write to a node. */
  readonly getLatestWrite: (nodeId: string) => ProvenanceRecord | undefined;
  /** Query all writes from a specific session. */
  readonly getSessionWrites: (sessionId: string) => readonly ProvenanceRecord[];
  /** Check if a node was ever written by an untrusted source. */
  readonly isNodeTainted: (nodeId: string) => boolean;
  /** Check if a node was written by an untrusted source in a different session. */
  readonly isCrossSessionTainted: (nodeId: string, currentSessionId: string) => boolean;
  /** All persisted dependency edges. */
  readonly getEdges: () => readonly ProvenanceEdge[];
  /** Direct dependencies of a node (the prior nodes it read). */
  readonly getDeps: (nodeId: string) => readonly string[];
  /** Direct (one-hop) descendants of a node. */
  readonly getDirectDescendants: (nodeId: string) => readonly string[];
  /**
   * Forward reachability — the contamination blast radius B(p). PRODUCTION-only
   * (the exact blast radius is the measured, licensed claim); the basic
   * in-memory ledger throws. See `@cerberus-ai/enterprise`.
   */
  readonly getDescendants: (nodeId: string, maxDepth?: number) => readonly string[];
  /** Recompute a record's commitment from its contentHash + deps and compare. */
  readonly verifyRecord: (record: ProvenanceRecord) => boolean;
  /** Verify the latest write to a node is integrity-intact (commitment matches). */
  readonly verifyNode: (nodeId: string) => boolean;
  /** Verify a record's per-agent authorship signature (AL3). PRODUCTION-only. */
  readonly verifyAuthorship: (record: ProvenanceRecord) => boolean;
  /** Verify the per-agent authorship signature of the latest write (AL3). PRODUCTION-only. */
  readonly verifyNodeAuthorship: (nodeId: string) => boolean;
  /** Append a containment annotation for a single node. PRODUCTION-only. */
  readonly quarantine: (
    nodeId: string,
    sourcePoisonId: string,
    reason: string,
    timestamp?: number,
  ) => void;
  /** Append a quarantine annotation for each node atomically. PRODUCTION-only. */
  readonly quarantineNodes: (
    nodeIds: readonly string[],
    sourcePoisonId: string,
    reason: string,
    timestamp?: number,
  ) => void;
  /** Contain a poisoned record and its entire forward blast radius. PRODUCTION-only. */
  readonly quarantineSubgraph: (
    poisonId: string,
    reason: string,
    timestamp?: number,
  ) => readonly string[];
  /** Summary-based forward reachability (the scale lever's B(p)). PRODUCTION-only. */
  readonly getSummarizedDescendants: (nodeId: string) => readonly string[];
  /** Total bytes of persisted ancestor summaries. `0` on the basic ledger. */
  readonly summaryBytes: () => number;
  /** Whether the provenance-summary lever is enabled. `false` on the basic ledger. */
  readonly summaryEnabled: boolean;
  /** The agent's SELF-DECLARED derivation deps. Empty on the basic ledger. */
  readonly getDeclaredDeps: (nodeId: string) => readonly string[];
  /** Forward reachability over the DECLARED-derivation edges. PRODUCTION-only. */
  readonly getDeclaredDescendants: (nodeId: string) => readonly string[];
  /** Whether the declared-derivation channel is enabled. `false` on the basic ledger. */
  readonly declaredDerivationEnabled: boolean;
  /** Whether a node currently carries a quarantine annotation. `false` on the basic ledger. */
  readonly isQuarantined: (nodeId: string) => boolean;
  /** All containment annotations for a node. Empty on the basic ledger. */
  readonly getAnnotations: (nodeId: string) => readonly TaintAnnotation[];
  /** Close the ledger (releases any backing resources). */
  readonly close: () => void;
}

// ── Hashing & commitments ───────────────────────────────────────────

/**
 * SHA-256 content hash (hex). Cryptographic — suitable for the integrity
 * requirement of the TTP spec. Replaces the prior non-cryptographic djb2.
 */
export function hashContent(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

/** Canonicalize a dependency set: de-duplicated, lexicographically sorted. */
export function canonicalDeps(deps: readonly string[]): string[] {
  return [...new Set(deps)].sort();
}

/**
 * Compute the tamper-evident commitment binding content + deps:
 * `SHA-256(contentHash ‖ sorted(deps))`. A record cannot later alter the
 * deps it claimed without invalidating this commitment.
 *
 * Note: this is a commitment (tamper-evident, AL2). On its own it proves a
 * record is untampered, not WHO wrote it. Per-agent authorship (AL3) is layered
 * on top by signing THIS commitment in `@cerberus-ai/enterprise`.
 */
export function computeCommitment(contentHash: string, deps: readonly string[]): string {
  const payload = `${contentHash}\n${canonicalDeps(deps).join('\n')}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Parse a persisted deps payload. Defensive against malformed rows: returns
 * an empty deps list on invalid JSON, non-arrays, or non-string elements.
 * Exported for unit testing and for the durable ledger's row mapping.
 */
export function parseDeps(raw: string): readonly string[] {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.every((d): d is string => typeof d === 'string')) {
      return parsed;
    }
  } catch {
    // fall through to empty deps on malformed payloads
  }
  return [];
}

// ── Basic in-memory ledger (open tier) ──────────────────────────────

/**
 * Error thrown when a PRODUCTION-only ledger capability (blast radius,
 * containment, scale lever, or AL3 authorship verification) is invoked on the
 * basic in-memory ledger. Never silently no-op a containment/blast-radius call.
 */
function productionOnly(method: string): Error {
  return new Error(
    `[Cerberus Ledger] ${method}() is a production capability of the durable ledger ` +
      `(@cerberus-ai/enterprise). The open in-memory ledger captures provenance and ` +
      `detects in-session taint, but does not compute the blast radius, contain it, ` +
      `persist, scale, or verify AL3 authorship. Inject a durable ledger to enable it.`,
  );
}

let warnedDurableOption = false;

/**
 * Create a basic in-memory provenance ledger (the open tier).
 *
 * Append-only provenance capture + in-session taint queries, held entirely in
 * memory. Honors the same {@link ProvenanceLedger} contract as the durable
 * ledger; the production-only methods throw {@link productionOnly}. Durable
 * options (`dbPath`, `summary`, `declaredDerivation`, `keyRegistry`) are ignored
 * (a single one-time warning) — they are honored only by the durable ledger.
 */
export function createInMemoryLedger(options?: LedgerOptions): ProvenanceLedger {
  if (
    !warnedDurableOption &&
    options &&
    (options.dbPath !== undefined ||
      options.summary !== undefined ||
      options.declaredDerivation === true ||
      options.keyRegistry !== undefined)
  ) {
    warnedDurableOption = true;
    // eslint-disable-next-line no-console
    console.warn(
      '[Cerberus Ledger] dbPath / summary / declaredDerivation / keyRegistry are ' +
        'production options honored only by the durable ledger (@cerberus-ai/enterprise). ' +
        'The basic in-memory ledger ignores them.',
    );
  }

  // Records keyed by `${nodeId}\u0000${timestamp}` (mirrors the durable ledger's
  // INSERT OR REPLACE on its (node_id, timestamp) primary key).
  const records = new Map<string, ProvenanceRecord>();
  // Dependency edges, de-duplicated by `${source}\u0000${target}` (mirrors the
  // durable ledger's INSERT OR IGNORE on its (source, target) primary key).
  const edges = new Map<string, ProvenanceEdge>();

  const allRecords = (): ProvenanceRecord[] => [...records.values()];

  const recordWrite = (record: ProvenanceWriteInput): void => {
    const deps = canonicalDeps(record.deps ?? []);
    const commitment = record.commitment ?? computeCommitment(record.contentHash, deps);
    // AL3: a signer signs THIS commitment (bound to its author) — it takes
    // precedence over any explicit author/signature. The private key stays in
    // the signer closure. No signer ⇒ unsigned (AL2).
    const author = record.signer ? record.signer.author : (record.author ?? '');
    const signature = record.signer ? record.signer.sign(commitment) : (record.signature ?? '');
    const full: ProvenanceRecord = {
      nodeId: record.nodeId,
      sessionId: record.sessionId,
      trustLevel: record.trustLevel,
      source: record.source,
      contentHash: record.contentHash,
      timestamp: record.timestamp,
      deps,
      commitment,
      ...(author ? { author } : {}),
      ...(signature ? { signature } : {}),
    };
    records.set(`${record.nodeId}\u0000${String(record.timestamp)}`, full);
    for (const dep of deps) {
      const key = `${dep}\u0000${record.nodeId}`;
      if (!edges.has(key)) {
        edges.set(key, {
          sourceNodeId: dep,
          targetNodeId: record.nodeId,
          sessionId: record.sessionId,
          timestamp: record.timestamp,
        });
      }
    }
  };

  const getNodeHistory = (nodeId: string): readonly ProvenanceRecord[] =>
    allRecords()
      .filter((r) => r.nodeId === nodeId)
      .sort((a, b) => b.timestamp - a.timestamp);

  const getLatestWrite = (nodeId: string): ProvenanceRecord | undefined =>
    getNodeHistory(nodeId)[0];

  const getSessionWrites = (sessionId: string): readonly ProvenanceRecord[] =>
    allRecords()
      .filter((r) => r.sessionId === sessionId)
      .sort((a, b) => a.timestamp - b.timestamp);

  const isNodeTainted = (nodeId: string): boolean =>
    allRecords().some((r) => r.nodeId === nodeId && r.trustLevel === 'untrusted');

  const isCrossSessionTainted = (nodeId: string, currentSessionId: string): boolean =>
    allRecords().some(
      (r) =>
        r.nodeId === nodeId && r.trustLevel === 'untrusted' && r.sessionId !== currentSessionId,
    );

  const getEdges = (): readonly ProvenanceEdge[] => [...edges.values()];

  const getDeps = (nodeId: string): readonly string[] =>
    getEdges()
      .filter((e) => e.targetNodeId === nodeId)
      .map((e) => e.sourceNodeId);

  const getDirectDescendants = (nodeId: string): readonly string[] =>
    getEdges()
      .filter((e) => e.sourceNodeId === nodeId)
      .map((e) => e.targetNodeId);

  const verifyRecord = (record: ProvenanceRecord): boolean =>
    record.commitment === computeCommitment(record.contentHash, record.deps);

  const verifyNode = (nodeId: string): boolean => {
    const latest = getLatestWrite(nodeId);
    return latest ? verifyRecord(latest) : false;
  };

  return {
    recordWrite,
    getNodeHistory,
    getLatestWrite,
    getSessionWrites,
    isNodeTainted,
    isCrossSessionTainted,
    getEdges,
    getDeps,
    getDirectDescendants,
    verifyRecord,
    verifyNode,
    // ── Production-only capabilities (durable ledger / @cerberus-ai/enterprise) ──
    getDescendants: (): readonly string[] => {
      throw productionOnly('getDescendants');
    },
    verifyAuthorship: (): boolean => {
      throw productionOnly('verifyAuthorship');
    },
    verifyNodeAuthorship: (): boolean => {
      throw productionOnly('verifyNodeAuthorship');
    },
    quarantine: (): void => {
      throw productionOnly('quarantine');
    },
    quarantineNodes: (): void => {
      throw productionOnly('quarantineNodes');
    },
    quarantineSubgraph: (): readonly string[] => {
      throw productionOnly('quarantineSubgraph');
    },
    getSummarizedDescendants: (): readonly string[] => {
      throw productionOnly('getSummarizedDescendants');
    },
    getDeclaredDescendants: (): readonly string[] => {
      throw productionOnly('getDeclaredDescendants');
    },
    // ── Inert in the basic tier (no data, safe to answer) ──
    summaryBytes: (): number => 0,
    summaryEnabled: false,
    getDeclaredDeps: (): readonly string[] => [],
    declaredDerivationEnabled: false,
    isQuarantined: (): boolean => false,
    getAnnotations: (): readonly TaintAnnotation[] => [],
    close: (): void => {},
  };
}
