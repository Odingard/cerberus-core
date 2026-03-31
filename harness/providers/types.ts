/**
 * Provider-agnostic types for the multi-model attack harness.
 *
 * These types abstract over OpenAI, Anthropic, and Google SDKs
 * so the agent loop can run against any provider.
 */

// ── Canonical Tool Definition ────────────────────────────────────

/** Provider-agnostic tool definition using JSON Schema for parameters. */
export interface CanonicalToolDef {
  readonly name: string;
  readonly description: string;
  readonly parameters: {
    readonly type: 'object';
    readonly properties: Record<string, unknown>;
    readonly required: readonly string[];
  };
}

// ── Provider Messages ────────────────────────────────────────────

/** A tool call parsed into a provider-agnostic format. */
export interface ProviderToolCall {
  readonly id: string;
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

/** A single message in the provider-agnostic conversation format. */
export interface ProviderMessage {
  readonly role: 'system' | 'user' | 'assistant' | 'tool';
  readonly content: string | null;
  readonly toolCalls?: readonly ProviderToolCall[];
  readonly toolCallId?: string;
}

// ── Provider Response ────────────────────────────────────────────

/** Normalized finish reason across all providers. */
export type ProviderFinishReason = 'stop' | 'tool_calls' | 'length' | 'content_filter' | 'unknown';

/** Provider-agnostic response from a completion call. */
export interface ProviderResponse {
  readonly message: ProviderMessage;
  readonly finishReason: ProviderFinishReason;
  readonly usage: {
    readonly promptTokens: number;
    readonly completionTokens: number;
  };
}

// ── Model Provider Interface ─────────────────────────────────────

/** Options passed to each completion call. */
export interface CompletionOptions {
  readonly temperature?: number;
  readonly seed?: number;
}

/**
 * Abstraction over LLM provider SDKs.
 *
 * Each adapter (OpenAI, Anthropic, Google) implements this interface
 * to normalize tool calling, message formats, and response parsing.
 */
export interface ModelProvider {
  /** Human-readable provider name (e.g. 'openai', 'anthropic', 'google'). */
  readonly providerName: string;

  /** The model ID passed to the underlying API. */
  readonly modelId: string;

  /**
   * Send a completion request with tool definitions.
   * Returns a normalized response with parsed tool calls.
   */
  createCompletion(
    messages: readonly ProviderMessage[],
    tools: readonly CanonicalToolDef[],
    options?: CompletionOptions,
  ): Promise<ProviderResponse>;
}
