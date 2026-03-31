import { createProvider } from '../providers/index.js';
import { CANONICAL_TOOLS } from '../providers/tool-defs.js';
import type { ProviderMessage } from '../providers/types.js';

export interface ProviderPreflightResult {
  readonly provider: string;
  readonly model: string;
  readonly ok: boolean;
  readonly error?: string;
}

function summarizeProviderError(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);

  if (message.includes('quota')) return `quota/billing issue: ${message}`;
  if (message.includes('API_KEY_INVALID') || message.includes('API key not valid')) {
    return `invalid API key: ${message}`;
  }
  if (message.includes('Incorrect API key') || message.includes('invalid_api_key')) {
    return `invalid API key: ${message}`;
  }
  if (message.includes('429')) return `rate limit or quota issue: ${message}`;

  return message;
}

export async function runProviderPreflightChecks(
  providers: readonly { model: string; provider: string }[],
): Promise<readonly ProviderPreflightResult[]> {
  const messages: readonly ProviderMessage[] = [{ role: 'user', content: 'Reply with ok.' }];
  const results: ProviderPreflightResult[] = [];

  for (const { model, provider } of providers) {
    try {
      const client = createProvider(model);
      await client.createCompletion(messages, CANONICAL_TOOLS);
      results.push({ provider, model, ok: true });
    } catch (err) {
      results.push({
        provider,
        model,
        ok: false,
        error: summarizeProviderError(err),
      });
    }
  }

  return results;
}
