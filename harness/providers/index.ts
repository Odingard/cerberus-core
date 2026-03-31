/**
 * Provider factory and re-exports.
 *
 * Auto-selects the correct provider based on model name prefix:
 * - claude-*  → Anthropic
 * - gemini-*  → Google
 * - *         → OpenAI (default)
 */

export type {
  CanonicalToolDef,
  ProviderMessage,
  ProviderToolCall,
  ProviderResponse,
  ProviderFinishReason,
  CompletionOptions,
  ModelProvider,
} from './types.js';

export { CANONICAL_TOOLS } from './tool-defs.js';
export { OpenAIProvider } from './openai.js';
export { AnthropicProvider } from './anthropic.js';
export { GoogleProvider } from './google.js';

import type { ModelProvider } from './types.js';
import { OpenAIProvider } from './openai.js';
import { AnthropicProvider } from './anthropic.js';
import { GoogleProvider } from './google.js';

/** Detect the provider name from a model ID string. */
export function detectProvider(model: string): 'openai' | 'anthropic' | 'google' {
  if (model.startsWith('claude-')) return 'anthropic';
  if (model.startsWith('gemini-')) return 'google';
  return 'openai';
}

/** Create a ModelProvider instance for the given model ID. */
export function createProvider(model: string, apiKey?: string): ModelProvider {
  const provider = detectProvider(model);
  switch (provider) {
    case 'anthropic':
      return new AnthropicProvider(model, apiKey);
    case 'google':
      return new GoogleProvider(model, apiKey);
    default:
      return new OpenAIProvider(model, apiKey);
  }
}
