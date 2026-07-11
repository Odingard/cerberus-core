/**
 * @cerberus-ai/core — Agentic AI Runtime Security Platform
 *
 * Detects, correlates, and interrupts the Lethal Trifecta attack pattern
 * across all agentic AI systems.
 *
 * Usage:
 *   import { guard } from '@cerberus-ai/core';
 *   const guarded = guard(myToolExecutors, config, outboundTools);
 */

export type {
  TrustLevel,
  TurnId,
  SessionId,
  PrivilegedDataSignal,
  UntrustedTokensSignal,
  ExfiltrationRiskSignal,
  ContaminatedMemorySignal,
  SecretsDetectedSignal,
  InjectionPatternsSignal,
  EncodingDetectedSignal,
  SuspiciousDestinationSignal,
  ToolPoisoningSignal,
  BehavioralDriftSignal,
  LateToolRegisteredSignal,
  InjectionAssistedRegistrationSignal,
  ScopeExpansionSignal,
  ContextOverflowSignal,
  CrossAgentTrifectaSignal,
  ContextContaminationSignal,
  UnauthorizedAgentSpawnSignal,
  ToolDescription,
  ToolPoisoningResult,
  DetectionSignal,
  RiskVector,
  RiskAction,
  RiskAssessment,
  AlertMode,
  LogDestination,
  StreamingMode,
  ContextScoringMode,
  OverflowAction,
  AlwaysInspectRegions,
  CerberusConfig,
  MemoryDependencyGateConfig,
  ProvenanceSummaryConfig,
  ProvenanceSummaryKind,
  ToolCallContext,
  ToolExecutionPhase,
  ToolExecutionOutcome,
} from './types/index.js';
export { formatBlockedToolMessage } from './types/execution.js';

export { guard } from './middleware/wrap.js';
export type { GuardResult, MemoryGuardOptions } from './middleware/wrap.js';

// Zero-config onboarding (spike): auto-wrap + auto-classify + observe-only default.
export { autoGuard } from './middleware/auto-guard.js';
export type { AutoGuardOptions, AutoGuardResult } from './middleware/auto-guard.js';
export {
  classifyTool,
  classifyTools,
  toTrustOverrides,
  toOutboundTools,
  formatClassificationTable,
} from './middleware/auto-classify.js';
export type { ToolRole, ToolClassification } from './middleware/auto-classify.js';

// Opt-in memory trace capture (records real read/write sequences, replayable)
export {
  createTraceRecorder,
  serializeTrace,
  TRACE_FORMAT_VERSION,
} from './middleware/trace-capture.js';
export type {
  MemoryTraceRecorder,
  TraceRecorderOptions,
  CapturedTrace,
  CapturedTraceMeta,
  CapturedMemoryOp,
  CaptureRedactionMode,
  WriteDerivation,
} from './middleware/trace-capture.js';

// Multi-agent delegation graph
export { guardMultiAgent } from './middleware/multi-agent.js';
export type { MultiAgentGuardResult, SpawnAgentResult } from './middleware/multi-agent.js';
export {
  createDelegationGraph,
  addAgent,
  verifyGraphIntegrity,
  getGraphVerifier,
  getAgentChain,
  isAuthorizedAgent,
  computeContextFingerprint,
  updateAgentRiskState,
} from './graph/delegation.js';
export type {
  AgentType,
  RiskState,
  AgentNode,
  DelegationEdge,
  DelegationGraph,
  DelegationGraphOptions,
  EnforcementMode,
  EnforcementLayer,
  EnforcementPosture,
  HumanAck,
} from './graph/delegation.js';
export { deriveEnforcementPosture } from './graph/enforcement-posture.js';

// Signed-manifest authorization gate (open per-turn authorization).
// The cryptographic signer/verifier primitives + the fail-closed per-turn
// manifest gate. This is the OPEN integrity layer: "no valid signature →
// no state transition". (The paid per-record audit-evidence layer — AL3
// authorship + DSA-PEAS — lives in @cerberus-ai/enterprise.)
export {
  HmacSigner,
  Ed25519Signer,
  Ed25519Verifier,
  getDefaultSigner,
  setDefaultSigner,
  resetDefaultSigner,
} from './crypto/signer.js';
export type {
  SigningAlgorithm,
  Signer,
  Verifier,
  SignerVerifier,
  HmacSignerOptions,
  Ed25519SignerOptions,
  Ed25519VerifierOptions,
} from './crypto/signer.js';
export { verifyManifestBeforeTurn } from './engine/manifest-gate.js';
export type { ManifestSignatureInvalidSignal } from './types/signals.js';
export type { ToolExecutorFn } from './engine/interceptor.js';

// Dynamic tool registration
export { registerToolLate, computeSchemaHash } from './engine/tool-registration.js';
export type { ToolSchema, ToolRegistrationResult } from './engine/tool-registration.js';

// Tool coverage — surface (never silently fail open on) tools guard() is not
// protecting. computeCoverageReport() is also exposed on GuardResult.coverage.
// computeCoverageCommitment() / verifyCoverageCommitment() bind that coverage
// into the signed delegation manifest (the receipt attests what was protected).
export {
  computeCoverageReport,
  formatCoverageWarning,
  computeCoverageCommitment,
  verifyCoverageCommitment,
} from './engine/coverage.js';
export type {
  CoverageReport,
  ToolCoverage,
  UndeclaredCoverage,
  CoverageDeclarationSite,
  CoverageInputs,
} from './engine/coverage.js';

// Context window management
export { analyzeContextWindow, estimateTokens, computeEntropy } from './engine/context-window.js';
export type { ContentSegment, ContextWindowResult } from './engine/context-window.js';

// Standalone MCP tool description scanner
export { scanToolDescriptions } from './classifiers/mcp-scanner.js';

// L4 Memory Contamination Graph exports
export type { MemoryToolConfig } from './layers/l4-memory.js';
// Reusable L4 recording core — feed a read/write into the contamination graph +
// provenance ledger directly (the live framework memory adapter builds on this).
export { recordMemoryRead, recordMemoryWrite } from './layers/l4-memory.js';
export type { MemoryReadEvent, MemoryWriteEvent, RecordedWrite } from './layers/l4-memory.js';
// Read-relevance (content-derivation) gate helpers (L4 dependency capture).
export {
  tokenize,
  containmentOverlap,
  isDerivationDependency,
  isDerivationDependencyScored,
  tokenOverlapScorer,
  cosineSimilarity,
  createCharNgramEmbedder,
  createEmbeddingRelevanceScorer,
} from './layers/read-relevance.js';
export type { RelevanceScorer, Embedder } from './layers/read-relevance.js';

// Provenance type contracts (the engine interfaces). The durable ledger /
// blast-radius / AL3 / scale *implementations* are licensed and live in
// `@cerberus-ai/enterprise`, not in the open surface.
export type { ContaminationGraph, GraphNode, GraphEdge } from './graph/contamination.js';
export { createContaminationGraph } from './graph/contamination.js';
export type {
  ProvenanceLedger,
  ProvenanceRecord,
  ProvenanceWriteInput,
  ProvenanceEdge,
  TaintAnnotation,
  TaintDisposition,
  LedgerOptions,
} from './graph/ledger.js';
// Open in-memory provenance ledger (the adoption/proof tier) + the integrity
// utilities shared with the durable ledger. The durable SQLite ledger +
// blast-radius B(p) + containment + scale levers + AL3 live in
// `@cerberus-ai/enterprise` and implement this same ProvenanceLedger contract.
export {
  createInMemoryLedger,
  hashContent,
  computeCommitment,
  canonicalDeps,
  parseDeps,
} from './graph/ledger.js';
export type { AncestorSummary, ProvenanceSummaryParams } from './graph/provenance-summary.js';
// AL3 authorship type contracts (the per-agent signing implementation is paid).
export type { AgentSigner, AgentKeyPair, AgentKeyRegistry } from './graph/authorship.js';

// Runtime-hooks seam — `@cerberus-ai/enterprise` injects the licensed telemetry
// recorder and enforcement-gateway dispatcher through these setters at import
// time. Open default is a no-op (and warns once if the feature is configured
// without the paid package installed).
export {
  setTelemetryRecorder,
  resetTelemetryRecorder,
  hasTelemetryRecorder,
  setEnforcementDispatch,
  resetEnforcementDispatch,
  hasEnforcementDispatch,
} from './engine/runtime-hooks.js';
export type {
  TelemetryToolCallRecord,
  TelemetryRecorder,
  EnforcementDispatchInput,
  EnforcementDispatch,
} from './engine/runtime-hooks.js';

// Intelligence incident envelope (emitted by guard(); analysis is licensed).
export type { IntelligenceIncidentEnvelope } from './types/intelligence.js';
export { buildIntelligenceIncidentEnvelope } from './engine/intelligence-envelope.js';

// Framework adapters
export { guardLangChain } from './adapters/langchain.js';
export type {
  LangChainTool,
  LangChainGuardConfig,
  LangChainGuardResult,
} from './adapters/langchain.js';
export { guardVercelAI } from './adapters/vercel-ai.js';
export type {
  VercelAITool,
  VercelAIToolMap,
  VercelAIGuardConfig,
  VercelAIGuardResult,
} from './adapters/vercel-ai.js';
export { createCerberusGuardrail } from './adapters/openai-agents.js';
export type {
  GuardrailFunctionOutput,
  OpenAIAgentsGuardConfig,
  OpenAIAgentsGuardrailResult,
} from './adapters/openai-agents.js';
// Live framework memory adapter — wrap a framework's NATIVE memory store
// (LangGraph BaseStore, a KV cache, a retriever) so its reads/writes feed the
// TTP provenance ledger live, with no guarded tool executors and no
// hand-declared memoryTools. Closes the "deploy → memory auto-traced" gap.
export {
  createMemoryProvenanceTracker,
  guardMemoryStore,
  guardLangGraphStore,
  defaultStoreContent,
  langGraphNodeId,
} from './adapters/memory-store.js';
export type {
  MemoryProvenanceTracker,
  MemoryProvenanceTrackerOptions,
  MemoryWriteOptions,
  MemoryReadOptions,
  GuardableKVStore,
  StoreMapping,
  GuardableLangGraphStore,
  LangGraphStoreItem,
} from './adapters/memory-store.js';
// Inter-component channel observation adapter — record a value crossing a
// component / agent boundary (Intent, static-field mailbox, message bus) as a
// real ledger dependency edge, feeding the same tracker as the memory adapter.
export { createIpcChannelTracker, ipcChannelNodeId } from './adapters/ipc-channel.js';
export type {
  IpcChannelTracker,
  IpcChannelTrackerOptions,
  IpcSendOptions,
  IpcReceiveOptions,
  IpcUnresolvedCounts,
} from './adapters/ipc-channel.js';

// Runtime channel-identity resolution — the live counterpart to the static
// TaintBench resolver: turn a host's runtime channel event (the component an
// implicit Intent resolved to, the value a dynamic key evaluated to) into a
// stable channel identity and drive the ipc-channel adapter. A SEPARATE live
// surface — it does not move the static analysis number.
export {
  resolveRuntimeChannelIdentity,
  createRuntimeIpcChannelTracker,
} from './adapters/ipc-runtime-identity.js';
export type {
  RuntimeChannelEvent,
  RuntimeIpcChannelTracker,
} from './adapters/ipc-runtime-identity.js';

// ── Licensed (paid-tier) runtime ─────────────────────────────────────────────
// The durable provenance ledger + blast-radius containment, scale levers, AL3
// authorship, the intelligence/Verdict-Weight layer, the enforcement gateway,
// the HTTP proxy, OpenTelemetry, and license/metering are published separately
// as `@cerberus-ai/enterprise`. See ./enterprise.ts for that surface.
