/**
 * DSA-PEAS conformance validator — standalone reference implementation.
 *
 * DSA-PEAS (Dependency-Signed, Authorship-Provable Evidence of Storage) is the
 * public wire format Cerberus emits for each memory-provenance record. This
 * module verifies a record — or a stream of records — against the spec WITHOUT
 * any dependency on the Cerberus internals (no `src/`, no SQLite, no project
 * packages): it re-derives the same bytes the reference implementation hashes
 * and signs using only Node's built-in `node:crypto`. That independence is the
 * point — anyone can drop this file into their own toolchain and self-check
 * conformance against the canonical byte formats below.
 *
 * Assurance levels (see spec/dsa-peas/schema.md):
 *   - AL2 (tamper-EVIDENT): the commitment binds content + deps; mutating either
 *     invalidates it, and a record's blast radius B(p) is computable from the
 *     stream as a SUPERSET of the true descendant set (no false negatives).
 *   - AL3 (authorship-PROVABLE): a per-author Ed25519 signature over the
 *     commitment proves WHO wrote the record; an altered author or a signature
 *     minted by any other key is rejected.
 *
 * Canonical byte formats (these are the conformance contract — they MUST match
 * the reference implementation byte-for-byte):
 *   - commitment   = SHA-256( contentHash ‖ "\n" ‖ canonicalDeps.join("\n") )
 *                    where canonicalDeps = unique(deps) sorted lexicographically
 *                    (UTF-16 code-unit order), rendered as lowercase hex.
 *   - signed bytes = "dsa-peas-al3-v1" ‖ "\n" ‖ commitment ‖ "\n" ‖ author
 *                    signed with Ed25519; signature carried as base64.
 *
 * Depends on: node:crypto only.
 */

import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';

// ── Wire types ──────────────────────────────────────────────────────

/** The trust level a record's source was classified at. */
export type DsaPeasTrustLevel = 'trusted' | 'untrusted' | 'unknown';

/** A single DSA-PEAS provenance record, exactly as emitted on the wire. */
export interface DsaPeasRecord {
  readonly nodeId: string;
  readonly sessionId: string;
  readonly trustLevel: DsaPeasTrustLevel;
  readonly source: string;
  readonly contentHash: string;
  readonly timestamp: number;
  readonly deps: readonly string[];
  readonly commitment: string;
  /** Claimed author (AL3). Absent/empty ⇒ unsigned record (AL2 only). */
  readonly author?: string;
  /** Base64 Ed25519 signature over (commitment ‖ author) (AL3). */
  readonly signature?: string;
}

/**
 * Author → public-key registry. Each value is an Ed25519 public key in SPKI PEM
 * form (the safe, shareable half). Used to resolve a record's CLAIMED author to
 * the key its signature must verify against.
 */
export type DsaPeasKeyring = Readonly<Record<string, string>>;

// ── Domain constants ────────────────────────────────────────────────

/** Domain-separation prefix mixed into every AL3 signed message. */
export const AL3_DOMAIN = 'dsa-peas-al3-v1';

// ── Canonical byte derivations ──────────────────────────────────────

/** Canonicalize a dependency set: de-duplicated, lexicographically sorted. */
export function canonicalDeps(deps: readonly string[]): string[] {
  return [...new Set(deps)].sort();
}

/** The exact preimage the commitment hashes: contentHash ‖ "\n" ‖ sorted(deps). */
export function commitmentPreimage(contentHash: string, deps: readonly string[]): string {
  return `${contentHash}\n${canonicalDeps(deps).join('\n')}`;
}

/** Compute the content+deps commitment (lowercase SHA-256 hex). */
export function computeCommitment(contentHash: string, deps: readonly string[]): string {
  return createHash('sha256').update(commitmentPreimage(contentHash, deps), 'utf8').digest('hex');
}

/** The exact bytes an AL3 signature is taken over. */
export function authorshipMessage(commitment: string, author: string): Buffer {
  return Buffer.from(`${AL3_DOMAIN}\n${commitment}\n${author}`, 'utf8');
}

// ── Predicate checks ────────────────────────────────────────────────

/**
 * AL2: does the record's stored commitment match the one re-derived from its
 * content + deps? A mutated `contentHash` or mutated `deps` changes the preimage
 * and therefore fails this check — that binding is what makes AL2 tamper-evident.
 */
export function verifyCommitment(record: DsaPeasRecord): boolean {
  return record.commitment === computeCommitment(record.contentHash, record.deps);
}

/**
 * AL3: does the record's signature verify against its CLAIMED author's key?
 * Re-derives the commitment from content + deps (not the stored field), so an
 * altered content/deps breaks the signature too; binds the author into the
 * signed bytes, so an altered author claim breaks it; and checks against the
 * claimed author's registered key, so a signature minted by any other key
 * (forgery) is rejected. Returns `false` (never throws) on any failure: an
 * unsigned record, an unknown author, a malformed key, or a bad signature.
 */
export function verifyAuthorship(record: DsaPeasRecord, keyring: DsaPeasKeyring): boolean {
  if (!record.author || !record.signature) {
    return false;
  }
  const pem = keyring[record.author];
  if (!pem) {
    return false;
  }
  try {
    const publicKey = createPublicKey(pem);
    const commitment = computeCommitment(record.contentHash, record.deps);
    return edVerify(
      null,
      authorshipMessage(commitment, record.author),
      publicKey,
      Buffer.from(record.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

/** Whether a record carries AL3 authorship fields (so AL3 applies to it). */
export function isSigned(record: DsaPeasRecord): boolean {
  return Boolean(record.author) && Boolean(record.signature);
}

// ── Blast radius (AL2 superset / no-false-negative) ─────────────────

/** Build the dependent-edge adjacency (dep → records that depend on it). */
function buildChildren(records: readonly DsaPeasRecord[]): Map<string, string[]> {
  const children = new Map<string, string[]>();
  for (const r of records) {
    for (const dep of r.deps) {
      const arr = children.get(dep);
      if (arr) {
        arr.push(r.nodeId);
      } else {
        children.set(dep, [r.nodeId]);
      }
    }
  }
  return children;
}

function reachFrom(children: Map<string, string[]>, nodeId: string): Set<string> {
  const reached = new Set<string>();
  const queue = [...(children.get(nodeId) ?? [])];
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (reached.has(current) || current === nodeId) {
      continue;
    }
    reached.add(current);
    for (const child of children.get(current) ?? []) {
      if (!reached.has(child)) {
        queue.push(child);
      }
    }
  }
  return reached;
}

/**
 * Forward-reachable set B(p): every record transitively reachable from `nodeId`
 * over the dependency edges (dep → dependent). This is the contamination blast
 * radius. Because `deps` is itself a conservative over-approximation of true
 * data dependencies, B(p) is a SUPERSET of the true descendant set — the safe
 * direction for a containment tool. Excludes `nodeId` itself; cycle-safe.
 */
export function computeBlastRadius(
  records: readonly DsaPeasRecord[],
  nodeId: string,
): ReadonlySet<string> {
  return reachFrom(buildChildren(records), nodeId);
}

/**
 * The no-false-negative property: a computed blast radius must be CLOSED under
 * the descendant relation — if a record is contained, every record that depends
 * on it is contained too. A single escaping descendant would be a false
 * negative (poison leaks). Returns the first violating edge, or `null` if the
 * blast radius of every node in the stream is closed (a superset of truth).
 */
export function findBlastRadiusLeak(
  records: readonly DsaPeasRecord[],
): { readonly poison: string; readonly escaped: string; readonly via: string } | null {
  const children = buildChildren(records);
  for (const r of records) {
    const radius = reachFrom(children, r.nodeId);
    for (const contained of radius) {
      for (const grandchild of children.get(contained) ?? []) {
        if (grandchild !== r.nodeId && !radius.has(grandchild)) {
          return { poison: r.nodeId, escaped: grandchild, via: contained };
        }
      }
    }
  }
  return null;
}

// ── Conformance report ──────────────────────────────────────────────

/** Outcome of one named conformance check. */
export interface CheckResult {
  readonly name: string;
  readonly pass: boolean;
  readonly detail?: string;
}

/** Per-level (AL2 / AL3) conformance result for one record. */
export interface LevelResult {
  readonly level: 'AL2' | 'AL3';
  readonly applicable: boolean;
  readonly pass: boolean;
  readonly checks: readonly CheckResult[];
}

/** Full conformance result for a single record. */
export interface RecordConformance {
  readonly nodeId: string;
  readonly al2: LevelResult;
  readonly al3: LevelResult;
}

function check(name: string, pass: boolean, detail?: string): CheckResult {
  return detail === undefined ? { name, pass } : { name, pass, detail };
}

/**
 * Validate one record. AL2 asserts the commitment verifies AND that mutating the
 * content and the deps each break it (proving the binding is real, not a
 * coincidence). AL3 (only when the record is signed) asserts the signature
 * verifies AND that an altered author and altered content are each rejected
 * (proving authorship + integrity binding). A self-contained per-record verdict.
 */
export function validateRecord(record: DsaPeasRecord, keyring: DsaPeasKeyring): RecordConformance {
  // AL2 — tamper-evident commitment.
  const commitmentOk = verifyCommitment(record);
  const mutatedContent: DsaPeasRecord = {
    ...record,
    contentHash: createHash('sha256').update(`mutate:${record.contentHash}`).digest('hex'),
  };
  const mutatedDeps: DsaPeasRecord = { ...record, deps: [...record.deps, '__dsa_peas_probe__'] };
  const contentMutationCaught = !verifyCommitment(mutatedContent);
  const depsMutationCaught = !verifyCommitment(mutatedDeps);
  const al2Checks: CheckResult[] = [
    check('commitment-verifies', commitmentOk),
    check('content-mutation-rejected', contentMutationCaught),
    check('deps-mutation-rejected', depsMutationCaught),
  ];
  const al2: LevelResult = {
    level: 'AL2',
    applicable: true,
    pass: al2Checks.every((c) => c.pass),
    checks: al2Checks,
  };

  // AL3 — authorship-provable signature (only when the record is signed).
  const signed = isSigned(record);
  let al3: LevelResult;
  if (!signed) {
    al3 = {
      level: 'AL3',
      applicable: false,
      pass: true,
      checks: [check('unsigned', true, 'record carries no author/signature; AL3 not applicable')],
    };
  } else {
    const author = record.author!;
    const signatureOk = verifyAuthorship(record, keyring);
    // Relabel to any other identity — the signed bytes change, so it must fail.
    const otherAuthor = `${author}__forged`;
    const relabeled: DsaPeasRecord = { ...record, author: otherAuthor };
    const authorTamperCaught = !verifyAuthorship(relabeled, keyring);
    // Altering content must break the signature (commitment is re-derived).
    const contentTampered: DsaPeasRecord = { ...mutatedContent };
    const contentTamperCaught = !verifyAuthorship(contentTampered, keyring);
    const al3Checks: CheckResult[] = [
      check('signature-verifies', signatureOk, signatureOk ? undefined : `author=${author}`),
      check('author-tamper-rejected', authorTamperCaught),
      check('content-tamper-rejected', contentTamperCaught),
    ];
    al3 = {
      level: 'AL3',
      applicable: true,
      pass: al3Checks.every((c) => c.pass),
      checks: al3Checks,
    };
  }

  return { nodeId: record.nodeId, al2, al3 };
}

/** Stream-level conformance result. */
export interface StreamConformance {
  readonly recordCount: number;
  readonly signedCount: number;
  readonly al2Pass: boolean;
  readonly al3Pass: boolean;
  readonly blastRadiusSuperset: boolean;
  readonly blastRadiusLeak: ReturnType<typeof findBlastRadiusLeak>;
  readonly records: readonly RecordConformance[];
  /** Overall: every applicable check across every record + the stream passes. */
  readonly pass: boolean;
}

/**
 * Validate a stream of records: every record's AL2/AL3 checks plus the
 * stream-wide no-false-negative blast-radius property (every node's blast
 * radius is closed under descendants ⇒ a superset of truth).
 */
export function validateStream(
  records: readonly DsaPeasRecord[],
  keyring: DsaPeasKeyring,
): StreamConformance {
  const perRecord = records.map((r) => validateRecord(r, keyring));
  const leak = findBlastRadiusLeak(records);
  const al2Pass = perRecord.every((r) => r.al2.pass);
  const al3Pass = perRecord.every((r) => r.al3.pass);
  const blastRadiusSuperset = leak === null;
  return {
    recordCount: records.length,
    signedCount: records.filter(isSigned).length,
    al2Pass,
    al3Pass,
    blastRadiusSuperset,
    blastRadiusLeak: leak,
    records: perRecord,
    pass: al2Pass && al3Pass && blastRadiusSuperset,
  };
}
