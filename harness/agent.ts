/**
 * Attack Harness — 3-tool agent with OpenAI function calling.
 *
 * Implements a standard function-calling loop: send messages to the model,
 * execute any requested tool calls, feed results back, and repeat until
 * the model produces a final response or the turn limit is reached.
 *
 * Hardened for production use: retries transient errors, handles malformed
 * tool arguments, catches tool executor failures, and tracks all errors.
 */

import OpenAI from 'openai';
import type { ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { TOOL_DEFINITIONS } from './tools.js';
import type {
  AgentConfig,
  AgentResult,
  TurnRecord,
  ToolCallRecord,
  ErrorInfo,
  FinishReason,
} from './types.js';

/**
 * Run the 3-tool agent against a system prompt and user prompt.
 *
 * The agent loops through OpenAI chat completions with function calling,
 * executing tool calls via the provided executors, until the model
 * returns a final message (finish_reason=stop) or maxTurns is reached.
 */
export async function runAgent(
  systemPrompt: string,
  userPrompt: string,
  config: AgentConfig,
): Promise<AgentResult> {
  const client = new OpenAI({
    apiKey: config.apiKey ?? process.env['OPENAI_API_KEY'],
    timeout: config.timeoutMs ?? 60_000,
    maxRetries: config.maxRetries ?? 2,
  });
  const model = config.model ?? 'gpt-4o-mini';
  const maxTurns = config.maxTurns ?? 10;

  const messages: ChatCompletionMessageParam[] = [
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
    const response = await client.chat.completions.create({
      model,
      messages,
      tools: [...TOOL_DEFINITIONS],
      tool_choice: 'auto',
      ...(config.temperature !== undefined ? { temperature: config.temperature } : {}),
      ...(config.seed !== undefined ? { seed: config.seed } : {}),
    });

    const choice = response.choices[0];
    if (!choice) {
      errors.push({
        code: 'API_ERROR',
        message: 'OpenAI returned empty choices array',
        turnIndex,
        timestamp: Date.now(),
      });
      stopReason = 'unknown';
      break;
    }

    totalPromptTokens += response.usage?.prompt_tokens ?? 0;
    totalCompletionTokens += response.usage?.completion_tokens ?? 0;

    const assistantMessage = choice.message;
    messages.push(assistantMessage);

    const toolCallRecords: ToolCallRecord[] = [];

    if (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
      for (const toolCall of assistantMessage.tool_calls) {
        if (toolCall.type !== 'function') continue;

        const fnName = toolCall.function.name;

        // Safe JSON parse — malformed arguments don't crash the run
        let fnArgs: Record<string, unknown>;
        try {
          fnArgs = JSON.parse(toolCall.function.arguments) as Record<string, unknown>;
        } catch {
          errors.push({
            code: 'JSON_PARSE',
            message: `Malformed JSON in tool arguments for "${fnName}": ${toolCall.function.arguments}`,
            turnIndex,
            toolName: fnName,
            timestamp: Date.now(),
          });
          messages.push({
            role: 'tool',
            tool_call_id: toolCall.id,
            content: 'Error: Could not parse arguments. Invalid JSON received.',
          });
          continue;
        }

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
          expectedSignals: [], // Ground-truth signals are captured via the onToolCall callback
        });

        messages.push({
          role: 'tool',
          tool_call_id: toolCall.id,
          content: result,
        });
      }
    }

    const finishReason = (choice.finish_reason ?? 'unknown') as FinishReason;

    const turnRecord: TurnRecord = {
      turnIndex,
      turnId: `turn-${String(turnIndex).padStart(3, '0')}`,
      role: 'assistant',
      assistantContent: assistantMessage.content ?? null,
      toolCalls: toolCallRecords,
      finishReason,
      timestamp: Date.now(),
    };

    turns.push(turnRecord);
    config.onTurn?.(turnRecord);

    if (finishReason === 'stop') {
      finalMessage = assistantMessage.content ?? null;
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
