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
  ToolCallContext,
  ToolExecutionPhase,
  ToolExecutionOutcome,
} from './types/index.js';
export { formatBlockedToolMessage } from './types/execution.js';

export { guard } from './middleware/wrap.js';
export type { GuardResult, MemoryGuardOptions } from './middleware/wrap.js';

// Multi-agent delegation graph
export { guardMultiAgent } from './middleware/multi-agent.js';
export type { MultiAgentGuardResult, SpawnAgentResult } from './middleware/multi-agent.js';
export {
  createDelegationGraph,
  addAgent,
  verifyGraphIntegrity,
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
} from './graph/delegation.js';
export type { ToolExecutorFn } from './engine/interceptor.js';

// Dynamic tool registration
export { registerToolLate, computeSchemaHash } from './engine/tool-registration.js';
export type { ToolSchema, ToolRegistrationResult } from './engine/tool-registration.js';

// Context window management
export { analyzeContextWindow, estimateTokens, computeEntropy } from './engine/context-window.js';
export type { ContentSegment, ContextWindowResult } from './engine/context-window.js';

// Standalone MCP tool description scanner
export { scanToolDescriptions } from './classifiers/mcp-scanner.js';

// L4 Memory Contamination Graph exports
export type { MemoryToolConfig } from './layers/l4-memory.js';
export type { ContaminationGraph, GraphNode, GraphEdge } from './graph/contamination.js';
export type { ProvenanceLedger, ProvenanceRecord } from './graph/ledger.js';

// OpenTelemetry instrumentation
export { recordToolCall } from './telemetry/otel.js';
export type { ToolCallRecord } from './telemetry/otel.js';

// Proxy/gateway mode
export { createProxy } from './proxy/server.js';
export type { ProxyConfig, ProxyToolConfig, ProxyServer } from './proxy/types.js';

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
