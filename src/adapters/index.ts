// ── LangChain ────────────────────────────────────────────────────────
export { guardLangChain } from './langchain.js';
export type { LangChainTool, LangChainGuardConfig, LangChainGuardResult } from './langchain.js';

// ── Vercel AI SDK ────────────────────────────────────────────────────
export { guardVercelAI } from './vercel-ai.js';
export type {
  VercelAITool,
  VercelAIToolMap,
  VercelAIGuardConfig,
  VercelAIGuardResult,
} from './vercel-ai.js';

// ── OpenAI Agents SDK ────────────────────────────────────────────────
export { createCerberusGuardrail } from './openai-agents.js';
export type {
  GuardrailFunctionOutput,
  OpenAIAgentsGuardConfig,
  OpenAIAgentsGuardrailResult,
} from './openai-agents.js';

// ── AutoGen (placeholder) ────────────────────────────────────────────
export type { AutoGenAdapterConfig } from './autogen.js';

// ── Live framework memory adapter (feeds the TTP ledger) ─────────────
export {
  createMemoryProvenanceTracker,
  guardMemoryStore,
  guardLangGraphStore,
  defaultStoreContent,
  langGraphNodeId,
} from './memory-store.js';
export type {
  MemoryProvenanceTracker,
  MemoryProvenanceTrackerOptions,
  MemoryWriteOptions,
  MemoryReadOptions,
  GuardableKVStore,
  StoreMapping,
  GuardableLangGraphStore,
  LangGraphStoreItem,
} from './memory-store.js';
