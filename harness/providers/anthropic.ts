/**
 * Anthropic provider adapter.
 *
 * Wraps the Anthropic SDK to implement the ModelProvider interface.
 * Key differences from OpenAI:
 * - System prompt is a separate parameter, not a message
 * - Tools use { name, input_schema } format
 * - Tool results are { type: 'tool_result', tool_use_id } content blocks
 * - Response content is an array of blocks (text or tool_use)
 * - Arguments are already objects (no JSON.parse needed)
 * - stop_reason: 'tool_use' instead of 'tool_calls'
 */

import Anthropic from '@anthropic-ai/sdk';
import type {
  MessageParam,
  ContentBlockParam,
  ToolResultBlockParam,
  Tool,
} from '@anthropic-ai/sdk/resources/messages/messages';
import type {
  ModelProvider,
  CanonicalToolDef,
  ProviderMessage,
  ProviderToolCall,
  ProviderResponse,
  ProviderFinishReason,
  CompletionOptions,
} from './types.js';

/** Convert canonical tool definitions to Anthropic format. */
export function toAnthropicTools(tools: readonly CanonicalToolDef[]): Tool[] {
  return tools.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: {
      type: 'object' as const,
      properties: t.parameters.properties,
      required: [...t.parameters.required],
    },
  }));
}

/**
 * Convert provider messages to Anthropic message format.
 * Extracts system messages separately (Anthropic uses a dedicated system param).
 */
export function toAnthropicMessages(messages: readonly ProviderMessage[]): {
  system: string | undefined;
  messages: MessageParam[];
} {
  let system: string | undefined;
  const result: MessageParam[] = [];

  for (const msg of messages) {
    if (msg.role === 'system') {
      system = msg.content ?? undefined;
      continue;
    }

    if (msg.role === 'tool') {
      // Tool results must be part of a user message in Anthropic's format
      const toolResult: ToolResultBlockParam = {
        type: 'tool_result',
        tool_use_id: msg.toolCallId ?? '',
        content: msg.content ?? '',
      };

      // Check if the last message is already a user message with content blocks
      const last = result[result.length - 1];
      if (last && last.role === 'user' && Array.isArray(last.content)) {
        (last.content as unknown as ContentBlockParam[]).push(toolResult);
      } else {
        result.push({
          role: 'user',
          content: [toolResult],
        });
      }
      continue;
    }

    if (msg.role === 'assistant' && msg.toolCalls && msg.toolCalls.length > 0) {
      const content: ContentBlockParam[] = [];
      if (msg.content) {
        content.push({ type: 'text', text: msg.content });
      }
      for (const tc of msg.toolCalls) {
        content.push({
          type: 'tool_use',
          id: tc.id,
          name: tc.name,
          input: tc.arguments,
        });
      }
      result.push({ role: 'assistant', content });
      continue;
    }

    // Plain user or assistant message
    result.push({
      role: msg.role,
      content: msg.content ?? '',
    });
  }

  return { system, messages: result };
}

/** Map Anthropic stop_reason to normalized ProviderFinishReason. */
function mapFinishReason(reason: string | null): ProviderFinishReason {
  switch (reason) {
    case 'end_turn':
      return 'stop';
    case 'tool_use':
      return 'tool_calls';
    case 'max_tokens':
      return 'length';
    case 'refusal':
      return 'content_filter';
    case 'stop_sequence':
      return 'stop';
    default:
      return 'unknown';
  }
}

/** Anthropic provider implementation. */
export class AnthropicProvider implements ModelProvider {
  readonly providerName = 'anthropic';
  readonly modelId: string;
  private readonly client: Anthropic;

  constructor(model: string, apiKey?: string) {
    this.modelId = model;
    this.client = new Anthropic({
      apiKey: apiKey ?? process.env['ANTHROPIC_API_KEY'],
    });
  }

  async createCompletion(
    messages: readonly ProviderMessage[],
    tools: readonly CanonicalToolDef[],
    options?: CompletionOptions,
  ): Promise<ProviderResponse> {
    const { system, messages: anthropicMessages } = toAnthropicMessages(messages);

    const response = await this.client.messages.create({
      model: this.modelId,
      max_tokens: 4096,
      messages: anthropicMessages,
      tools: toAnthropicTools(tools),
      tool_choice: { type: 'auto' },
      ...(system !== undefined ? { system } : {}),
      ...(options?.temperature !== undefined ? { temperature: options.temperature } : {}),
    });

    // Extract text and tool calls from content blocks
    let textContent: string | null = null;
    const toolCalls: ProviderToolCall[] = [];

    for (const block of response.content) {
      if (block.type === 'text') {
        textContent = block.text;
      } else if (block.type === 'tool_use') {
        toolCalls.push({
          id: block.id,
          name: block.name,
          arguments: block.input as Record<string, unknown>,
        });
      }
    }

    return {
      message: {
        role: 'assistant',
        content: textContent,
        ...(toolCalls.length > 0 ? { toolCalls } : {}),
      },
      finishReason: mapFinishReason(response.stop_reason),
      usage: {
        promptTokens: response.usage.input_tokens,
        completionTokens: response.usage.output_tokens,
      },
    };
  }
}
