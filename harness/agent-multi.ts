/**
 * Multi-provider attack agent.
 *
 * Same function-calling loop as agent.ts, but uses the ModelProvider
 * abstraction instead of the OpenAI SDK directly. Supports OpenAI,
 * Anthropic (Claude), and Google (Gemini) through a single interface.
 */

import { createProvider, CANONICAL_TOOLS } from './providers/index.js';
import type { ProviderMessage } from './providers/types.js';
import type {
  AgentConfig,
  AgentResult,
  TurnRecord,
  ToolCallRecord,
  ErrorInfo,
  FinishReason,
} from './types.js';

/**
 * Run the 3-tool agent against any supported model provider.
 *
 * The agent loops through completions with function calling,
 * executing tool calls via the provided executors, until the model
 * returns a final message (finish_reason=stop) or maxTurns is reached.
 */
export async function runAgentMulti(
  systemPrompt: string,
  userPrompt: string,
  config: AgentConfig,
): Promise<AgentResult> {
  const model = config.model ?? 'gpt-4o-mini';
  const maxTurns = config.maxTurns ?? 10;
  const provider = createProvider(model, config.apiKey);

  const messages: ProviderMessage[] = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt },
  ];

  const turns: TurnRecord[] = [];
  const errors: ErrorInfo[] = [];
  let totalPromptTokens = 0;
  let totalCompletionTokens = 0;
  let finalMessage: string | null = null;
  let stopReason: FinishReason = 'unknown';

  for (let turnIndex = 0; turnIndex < maxTurns; turnIndex++) {
    const response = await provider.createCompletion(messages, CANONICAL_TOOLS, {
      ...(config.temperature !== undefined ? { temperature: config.temperature } : {}),
      ...(config.seed !== undefined ? { seed: config.seed } : {}),
    });

    totalPromptTokens += response.usage.promptTokens;
    totalCompletionTokens += response.usage.completionTokens;

    // Add assistant message to conversation
    messages.push(response.message);

    const toolCallRecords: ToolCallRecord[] = [];

    if (response.message.toolCalls && response.message.toolCalls.length > 0) {
      for (const toolCall of response.message.toolCalls) {
        const fnName = toolCall.name;
        const fnArgs = toolCall.arguments;

        const executor = config.toolExecutors[fnName];
        if (!executor) {
          throw new Error(
            `Unknown tool "${fnName}" requested by model. ` +
              `Available tools: ${Object.keys(config.toolExecutors).join(', ')}`,
          );
        }

        // Safe executor call — tool failures don't crash the loop
        let result: string;
        try {
          result = await executor(fnArgs);
        } catch (execErr) {
          const errMsg = execErr instanceof Error ? execErr.message : String(execErr);
          errors.push({
            code: 'TOOL_EXEC',
            message: `Tool "${fnName}" threw: ${errMsg}`,
            turnIndex,
            toolName: fnName,
            timestamp: Date.now(),
          });
          result = `Error: Tool execution failed — ${errMsg}`;
        }

        toolCallRecords.push({
          toolName: fnName as ToolCallRecord['toolName'],
          arguments: fnArgs,
          result,
          timestamp: Date.now(),
          expectedSignals: [],
        });

        // Add tool result to conversation
        // For Google Gemini, we use the function name as toolCallId
        // since Gemini doesn't have persistent tool call IDs
        messages.push({
          role: 'tool',
          content: result,
          toolCallId: toolCall.id,
        });
      }
    }

    const finishReason = response.finishReason as FinishReason;

    const turnRecord: TurnRecord = {
      turnIndex,
      turnId: `turn-${String(turnIndex).padStart(3, '0')}`,
      role: 'assistant',
      assistantContent: response.message.content ?? null,
      toolCalls: toolCallRecords,
      finishReason,
      timestamp: Date.now(),
    };

    turns.push(turnRecord);
    config.onTurn?.(turnRecord);

    if (finishReason === 'stop') {
      finalMessage = response.message.content ?? null;
      stopReason = 'stop';
      break;
    }

    if (finishReason === 'content_filter') {
      errors.push({
        code: 'API_ERROR',
        message: 'Model response was filtered by content policy',
        turnIndex,
        timestamp: Date.now(),
      });
      stopReason = 'content_filter';
      break;
    }

    if (finishReason === 'length') {
      errors.push({
        code: 'API_ERROR',
        message: 'Model response was truncated due to max_tokens/context length',
        turnIndex,
        timestamp: Date.now(),
      });
      stopReason = 'length';
      break;
    }

    // tool_calls → continue the loop
    if (finishReason === 'tool_calls') {
      stopReason = 'tool_calls';
    }
  }

  // If we exhausted maxTurns without hitting stop, record it
  if (turns.length >= maxTurns && stopReason === 'tool_calls') {
    stopReason = 'unknown';
  }

  return {
    turns,
    finalMessage,
    tokenUsage: {
      promptTokens: totalPromptTokens,
      completionTokens: totalCompletionTokens,
      totalTokens: totalPromptTokens + totalCompletionTokens,
    },
    errors,
    stopReason,
  };
}
