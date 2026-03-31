/**
 * Google Gemini provider adapter.
 *
 * Wraps the @google/generative-ai SDK to implement the ModelProvider interface.
 * Key differences from OpenAI:
 * - Tools use { functionDeclarations: [...] } format
 * - System prompt via systemInstruction parameter
 * - Tool results via functionResponse parts
 * - Arguments are already objects (no JSON.parse needed)
 * - finish_reason uses uppercase enums (STOP, MAX_TOKENS, etc.)
 * - Roles: 'model' instead of 'assistant', 'function' for tool results
 */

import { GoogleGenerativeAI, FunctionCallingMode } from '@google/generative-ai';
import type {
  Content,
  Part,
  FunctionDeclaration,
  FunctionDeclarationSchema,
  GenerateContentRequest,
} from '@google/generative-ai';
import type {
  ModelProvider,
  CanonicalToolDef,
  ProviderMessage,
  ProviderToolCall,
  ProviderResponse,
  ProviderFinishReason,
  CompletionOptions,
} from './types.js';

/** Convert canonical tool definitions to Gemini function declarations. */
export function toGeminiFunctionDeclarations(
  tools: readonly CanonicalToolDef[],
): FunctionDeclaration[] {
  return tools.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: {
      type: 'OBJECT',
      properties: t.parameters.properties as Record<string, FunctionDeclarationSchema>,
      required: [...t.parameters.required],
    } as unknown as FunctionDeclarationSchema,
  }));
}

/**
 * Convert provider messages to Gemini Content format.
 * Extracts system instruction separately.
 * Maps roles: assistant → model, tool → function.
 */
export function toGeminiContents(messages: readonly ProviderMessage[]): {
  systemInstruction: string | undefined;
  contents: Content[];
} {
  let systemInstruction: string | undefined;
  const contents: Content[] = [];

  for (const msg of messages) {
    if (msg.role === 'system') {
      systemInstruction = msg.content ?? undefined;
      continue;
    }

    if (msg.role === 'tool') {
      // Function response part
      // We need to know the function name — extract from the toolCallId pattern
      // or from the preceding assistant message's tool calls
      const responsePart: Part = {
        functionResponse: {
          name: msg.toolCallId ?? 'unknown',
          response: { result: msg.content ?? '' },
        },
      };

      // Check if the last content is already a function role — batch results together
      const last = contents[contents.length - 1];
      if (last && last.role === 'function') {
        last.parts.push(responsePart);
      } else {
        contents.push({
          role: 'function',
          parts: [responsePart],
        });
      }
      continue;
    }

    if (msg.role === 'assistant') {
      const parts: Part[] = [];
      if (msg.content) {
        parts.push({ text: msg.content });
      }
      if (msg.toolCalls) {
        for (const tc of msg.toolCalls) {
          parts.push({
            functionCall: {
              name: tc.name,
              args: tc.arguments,
            },
          });
        }
      }
      if (parts.length > 0) {
        contents.push({ role: 'model', parts });
      }
      continue;
    }

    // User message
    contents.push({
      role: 'user',
      parts: [{ text: msg.content ?? '' }],
    });
  }

  return { systemInstruction, contents };
}

/** Map Gemini finish reason to normalized ProviderFinishReason. */
function mapFinishReason(reason: string | undefined): ProviderFinishReason {
  switch (reason) {
    case 'STOP':
      return 'stop';
    case 'MAX_TOKENS':
      return 'length';
    case 'SAFETY':
      return 'content_filter';
    case 'RECITATION':
      return 'content_filter';
    case 'BLOCKLIST':
      return 'content_filter';
    case 'PROHIBITED_CONTENT':
      return 'content_filter';
    case 'MALFORMED_FUNCTION_CALL':
      return 'unknown';
    default:
      return 'unknown';
  }
}

/** Google Gemini provider implementation. */
export class GoogleProvider implements ModelProvider {
  readonly providerName = 'google';
  readonly modelId: string;
  private readonly apiKey: string;

  constructor(model: string, apiKey?: string) {
    this.modelId = model;
    this.apiKey = apiKey ?? process.env['GOOGLE_API_KEY'] ?? '';
  }

  async createCompletion(
    messages: readonly ProviderMessage[],
    tools: readonly CanonicalToolDef[],
    options?: CompletionOptions,
  ): Promise<ProviderResponse> {
    const client = new GoogleGenerativeAI(this.apiKey);
    const { systemInstruction, contents } = toGeminiContents(messages);

    const model = client.getGenerativeModel({
      model: this.modelId,
      tools: [{ functionDeclarations: toGeminiFunctionDeclarations(tools) }],
      toolConfig: {
        functionCallingConfig: { mode: FunctionCallingMode.AUTO },
      },
      ...(systemInstruction !== undefined ? { systemInstruction } : {}),
      generationConfig: {
        ...(options?.temperature !== undefined ? { temperature: options.temperature } : {}),
      },
    });

    const request: GenerateContentRequest = { contents };
    const result = await model.generateContent(request);
    const response = result.response;

    const candidate = response.candidates?.[0];
    if (!candidate) {
      throw new Error('Gemini returned no candidates');
    }

    // Extract text and function calls from parts
    let textContent: string | null = null;
    const toolCalls: ProviderToolCall[] = [];
    let callIndex = 0;

    for (const part of candidate.content?.parts ?? []) {
      if ('text' in part && part.text) {
        textContent = part.text;
      }
      if ('functionCall' in part && part.functionCall) {
        toolCalls.push({
          id: `gemini-call-${String(callIndex++)}`,
          name: part.functionCall.name,
          arguments: (part.functionCall.args ?? {}) as Record<string, unknown>,
        });
      }
    }

    // Determine finish reason — if there are function calls, it's tool_calls
    const rawFinishReason = candidate.finishReason;
    const finishReason: ProviderFinishReason =
      toolCalls.length > 0 ? 'tool_calls' : mapFinishReason(rawFinishReason);

    return {
      message: {
        role: 'assistant',
        content: textContent,
        ...(toolCalls.length > 0 ? { toolCalls } : {}),
      },
      finishReason,
      usage: {
        promptTokens: response.usageMetadata?.promptTokenCount ?? 0,
        completionTokens: response.usageMetadata?.candidatesTokenCount ?? 0,
      },
    };
  }
}
