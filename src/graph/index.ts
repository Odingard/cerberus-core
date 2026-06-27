export { createContaminationGraph } from './contamination.js';
export type { GraphNode, GraphEdge, ContaminationGraph } from './contamination.js';

// Open tier: the basic in-memory ledger + the shared integrity utilities.
// The durable SQLite ledger (`createLedger`) is paid (@cerberus-ai/enterprise).
export {
  createInMemoryLedger,
  hashContent,
  canonicalDeps,
  computeCommitment,
  parseDeps,
} from './ledger.js';
export type {
  ProvenanceRecord,
  ProvenanceWriteInput,
  ProvenanceEdge,
  TaintAnnotation,
  TaintDisposition,
  LedgerOptions,
  ProvenanceLedger,
} from './ledger.js';

// Provenance-summary scale lever: contracts are open, the implementation
// (createSummary/summaryFromBytes/resolveSummaryParams) is paid.
export type {
  AncestorSummary,
  ProvenanceSummaryParams,
  ProvenanceSummaryKind,
} from './provenance-summary.js';

// AL3 authorship: contracts are open, the signing/verification implementation
// is paid.
export type { AgentKeyPair, AgentSigner, AgentKeyRegistry } from './authorship.js';
