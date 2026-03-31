/**
 * OpenAI provider adapter.
 *
 * Wraps the OpenAI SDK to implement the ModelProvider interface.
 * Converts canonical tool definitions to OpenAI's ChatCompletionTool format
 * and normalizes responses back to ProviderResponse.
 */

import OpenAI from 'openai';
import type {
  ChatCompletionMessageParam,
  ChatCompletionTool,
} from 'openai/resources/chat/completions';
import type {
  ModelProvider,
  CanonicalToolDef,
  ProviderMessage,
  ProviderToolCall,
  ProviderResponse,
  ProviderFinishReason,
  CompletionOptions,
} from './types.js';

/** Convert canonical tool definitions to OpenAI format. */
export function toOpenAITools(tools: readonly CanonicalToolDef[]): ChatCompletionTool[] {
  return tools.map((t) => ({
    type: 'function' as const,
    function: {
      name: t.name,
      description: t.description,
      parameters: {
        type: t.parameters.type,
        properties: t.parameters.properties,
        required: [...t.parameters.required],
      },
    },
  }));
}

/** Convert provider messages to OpenAI message format. */
export function toOpenAIMessages(
  messages: readonly ProviderMessage[],
): ChatCompletionMessageParam[] {
  return messages.map((msg): ChatCompletionMessageParam => {
    if (msg.role === 'tool') {
      return {
        role: 'tool',
        tool_call_id: msg.toolCallId ?? '',
        content: msg.content ?? '',
      };
    }

    if (msg.role === 'assistant' && msg.toolCalls && msg.toolCalls.length > 0) {
      return {
        role: 'assistant',
        content: msg.content ?? null,
        tool_calls: msg.toolCalls.map((tc) => ({
          id: tc.id,
          type: 'function' as const,
          function: {
            name: tc.name,
            arguments: JSON.stringify(tc.arguments),
          },
        })),
      };
    }

    return {
      role: msg.role,
      content: msg.content ?? '',
    };
  });
}

/** Map OpenAI finish_reason to normalized ProviderFinishReason. */
function mapFinishReason(reason: string | null): ProviderFinishReason {
  switch (reason) {
    case 'stop':
      return 'stop';
    case 'tool_calls':
      return 'tool_calls';
    case 'length':
      return 'length';
    case 'content_filter':
      return 'content_filter';
    default:
      return 'unknown';
  }
}

/** OpenAI provider implementation. */
export class OpenAIProvider implements ModelProvider {
  readonly providerName = 'openai';
  readonly modelId: string;
  private readonly client: OpenAI;

  constructor(model: string, apiKey?: string) {
    this.modelId = model;
    this.client = new OpenAI({
      apiKey: apiKey ?? process.env['OPENAI_API_KEY'],
      timeout: 60_000,
      maxRetries: 2,
    });
  }

  async createCompletion(
    messages: readonly ProviderMessage[],
    tools: readonly CanonicalToolDef[],
    options?: CompletionOptions,
  ): Promise<ProviderResponse> {
    const response = await this.client.chat.completions.create({
      model: this.modelId,
      messages: toOpenAIMessages(messages),
      tools: toOpenAITools(tools),
      tool_choice: 'auto',
      ...(options?.temperature !== undefined ? { temperature: options.temperature } : {}),
      ...(options?.seed !== undefined ? { seed: options.seed } : {}),
    });

    const choice = response.choices[0];
    if (!choice) {
      throw new Error('OpenAI returned empty choices array');
    }

    const assistantMessage = choice.message;
    const toolCalls: ProviderToolCall[] = [];

    if (assistantMessage.tool_calls) {
      for (const tc of assistantMessage.tool_calls) {
        if (tc.type !== 'function') continue;
        toolCalls.push({
          id: tc.id,
          name: tc.function.name,
          arguments: JSON.parse(tc.function.arguments) as Record<string, unknown>,
        });
      }
    }

    return {
      message: {
        role: 'assistant',
        content: assistantMessage.content ?? null,
        ...(toolCalls.length > 0 ? { toolCalls } : {}),
      },
      finishReason: mapFinishReason(choice.finish_reason),
      usage: {
        promptTokens: response.usage?.prompt_tokens ?? 0,
        completionTokens: response.usage?.completion_tokens ?? 0,
      },
    };
  }
}
