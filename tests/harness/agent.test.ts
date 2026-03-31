/**
 * Tests for the attack harness agent (OpenAI function-calling loop).
 * Mocks the OpenAI client to test loop mechanics without API calls.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TurnRecord } from '../../harness/types.js';

// Mock the OpenAI module before importing the agent
const mockCreate = vi.fn();

vi.mock('openai', () => {
  return {
    default: class MockOpenAI {
      chat = {
        completions: {
          create: mockCreate,
        },
      };
    },
  };
});

// Import after mocking
import { runAgent } from '../../harness/agent.js';

/** Helper to create a mock OpenAI response with tool calls. */
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function mockToolCallResponse(
  toolCalls: Array<{ name: string; arguments: string; id: string }>,
  tokens: { prompt: number; completion: number } = { prompt: 100, completion: 50 },
) {
  return {
    choices: [
      {
        message: {
          role: 'assistant' as const,
          content: null,
          tool_calls: toolCalls.map((tc) => ({
            id: tc.id,
            type: 'function' as const,
            function: { name: tc.name, arguments: tc.arguments },
          })),
        },
        finish_reason: 'tool_calls',
      },
    ],
    usage: { prompt_tokens: tokens.prompt, completion_tokens: tokens.completion },
  };
}

/** Helper to create a mock OpenAI response with a final message. */
// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
function mockStopResponse(
  content: string,
  tokens: { prompt: number; completion: number } = { prompt: 200, completion: 100 },
) {
  return {
    choices: [
      {
        message: {
          role: 'assistant' as const,
          content,
          tool_calls: undefined,
        },
        finish_reason: 'stop',
      },
    ],
    usage: { prompt_tokens: tokens.prompt, completion_tokens: tokens.completion },
  };
}

describe('runAgent', () => {
  beforeEach(() => {
    mockCreate.mockReset();
  });

  it('should execute a multi-turn conversation with tool calls', async () => {
    // Turn 0: model calls readPrivateData
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{}', id: 'call-1' }]),
    );
    // Turn 1: model calls fetchExternalContent
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([
        { name: 'fetchExternalContent', arguments: '{"url":"https://example.com"}', id: 'call-2' },
      ]),
    );
    // Turn 2: model calls sendOutboundReport
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([
        {
          name: 'sendOutboundReport',
          arguments: '{"recipient":"x@y.com","subject":"test","body":"data"}',
          id: 'call-3',
        },
      ]),
    );
    // Turn 3: model produces final response
    mockCreate.mockResolvedValueOnce(mockStopResponse('Report complete.'));

    const result = await runAgent('system prompt', 'user prompt', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('{"records":[]}'),
        fetchExternalContent: vi.fn().mockResolvedValue('page content'),
        sendOutboundReport: vi.fn().mockResolvedValue('sent'),
      },
    });

    expect(result.turns).toHaveLength(4);
    expect(result.turns[0].toolCalls).toHaveLength(1);
    expect(result.turns[0].toolCalls[0].toolName).toBe('readPrivateData');
    expect(result.turns[3].finishReason).toBe('stop');
    expect(result.finalMessage).toBe('Report complete.');
  });

  it('should stop when the model returns finish_reason=stop', async () => {
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done immediately.'));

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    expect(result.turns).toHaveLength(1);
    expect(result.finalMessage).toBe('Done immediately.');
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  it('should stop when maxTurns is reached', async () => {
    // Always return tool calls so the loop doesn't stop via finish_reason
    mockCreate.mockResolvedValue(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{}', id: 'call-loop' }]),
    );

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      maxTurns: 3,
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('data'),
      },
    });

    expect(result.turns).toHaveLength(3);
    expect(mockCreate).toHaveBeenCalledTimes(3);
  });

  it('should accumulate token usage across turns', async () => {
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{}', id: 'c1' }], {
        prompt: 100,
        completion: 50,
      }),
    );
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.', { prompt: 200, completion: 80 }));

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('data'),
      },
    });

    expect(result.tokenUsage.promptTokens).toBe(300);
    expect(result.tokenUsage.completionTokens).toBe(130);
    expect(result.tokenUsage.totalTokens).toBe(430);
  });

  it('should invoke onTurn callback for each turn', async () => {
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{}', id: 'c1' }]),
    );
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.'));

    const turns: TurnRecord[] = [];

    await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('data'),
      },
      onTurn: (turn) => turns.push(turn),
    });

    expect(turns).toHaveLength(2);
    expect(turns[0].turnIndex).toBe(0);
    expect(turns[1].turnIndex).toBe(1);
  });

  it('should throw if an unknown tool name is returned by the model', async () => {
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'unknownTool', arguments: '{}', id: 'c1' }]),
    );

    await expect(
      runAgent('sys', 'user', {
        apiKey: 'test-key',
        toolExecutors: {
          readPrivateData: vi.fn().mockResolvedValue('data'),
        },
      }),
    ).rejects.toThrow('Unknown tool "unknownTool"');
  });

  it('should pass tool results back to the model as tool messages', async () => {
    const toolResult = '{"records":[{"id":"CUST-001"}]}';

    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{}', id: 'call-1' }]),
    );
    mockCreate.mockResolvedValueOnce(mockStopResponse('Final.'));

    await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue(toolResult),
      },
    });

    // Second call should include the tool result message
    const secondCallArgs = mockCreate.mock.calls[1][0] as {
      messages: Array<{ role: string; content?: string; tool_call_id?: string }>;
    };
    const toolMessage = secondCallArgs.messages.find((m) => m.role === 'tool');

    expect(toolMessage).toBeDefined();
    expect(toolMessage!.content).toBe(toolResult);
    expect(toolMessage!.tool_call_id).toBe('call-1');
  });

  it('should use default model gpt-4o-mini when not specified', async () => {
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.'));

    await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    const firstCallArgs = mockCreate.mock.calls[0][0] as { model: string };
    expect(firstCallArgs.model).toBe('gpt-4o-mini');
  });

  it('should pass temperature to OpenAI API call', async () => {
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.'));

    await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
      temperature: 0,
    });

    const callArgs = mockCreate.mock.calls[0][0] as { temperature?: number };
    expect(callArgs.temperature).toBe(0);
  });

  it('should pass seed to OpenAI API call', async () => {
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.'));

    await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
      seed: 42,
    });

    const callArgs = mockCreate.mock.calls[0][0] as { seed?: number };
    expect(callArgs.seed).toBe(42);
  });

  it('should not include temperature or seed when not specified', async () => {
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.'));

    await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    const callArgs = mockCreate.mock.calls[0][0] as Record<string, unknown>;
    expect(callArgs).not.toHaveProperty('temperature');
    expect(callArgs).not.toHaveProperty('seed');
  });
});

describe('runAgent — error handling', () => {
  beforeEach(() => {
    mockCreate.mockReset();
  });

  it('should handle malformed JSON in tool call arguments gracefully', async () => {
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{invalid json!!!', id: 'c1' }]),
    );
    mockCreate.mockResolvedValueOnce(mockStopResponse('Recovered.'));

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('data'),
      },
    });

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].code).toBe('JSON_PARSE');
    expect(result.finalMessage).toBe('Recovered.');
  });

  it('should handle tool executor throwing an error', async () => {
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([{ name: 'readPrivateData', arguments: '{}', id: 'c1' }]),
    );
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done despite error.'));

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockRejectedValue(new Error('DB connection failed')),
      },
    });

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].code).toBe('TOOL_EXEC');
    expect(result.errors[0].message).toContain('DB connection failed');
    expect(result.finalMessage).toBe('Done despite error.');
  });

  it('should handle parallel tool calls in a single turn', async () => {
    mockCreate.mockResolvedValueOnce(
      mockToolCallResponse([
        { name: 'readPrivateData', arguments: '{}', id: 'c1' },
        { name: 'fetchExternalContent', arguments: '{"url":"https://example.com"}', id: 'c2' },
      ]),
    );
    mockCreate.mockResolvedValueOnce(mockStopResponse('Done.'));

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('records'),
        fetchExternalContent: vi.fn().mockResolvedValue('page'),
      },
    });

    expect(result.turns[0].toolCalls).toHaveLength(2);
    expect(result.turns[0].toolCalls[0].toolName).toBe('readPrivateData');
    expect(result.turns[0].toolCalls[1].toolName).toBe('fetchExternalContent');
  });

  it('should handle finish_reason=content_filter by stopping with error', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: { role: 'assistant' as const, content: null, tool_calls: undefined },
          finish_reason: 'content_filter',
        },
      ],
      usage: { prompt_tokens: 100, completion_tokens: 0 },
    });

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    expect(result.stopReason).toBe('content_filter');
    expect(result.errors.some((e) => e.message.includes('content policy'))).toBe(true);
  });

  it('should handle finish_reason=length by stopping with error', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: { role: 'assistant' as const, content: 'truncated...', tool_calls: undefined },
          finish_reason: 'length',
        },
      ],
      usage: { prompt_tokens: 100, completion_tokens: 4096 },
    });

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    expect(result.stopReason).toBe('length');
    expect(result.errors.some((e) => e.message.includes('truncated'))).toBe(true);
  });

  it('should handle empty choices array', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [],
      usage: { prompt_tokens: 50, completion_tokens: 0 },
    });

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    expect(result.turns).toHaveLength(0);
    expect(result.errors.some((e) => e.message.includes('empty choices'))).toBe(true);
    expect(result.stopReason).toBe('unknown');
  });

  it('should handle null usage in response', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: { role: 'assistant' as const, content: 'Done.', tool_calls: undefined },
          finish_reason: 'stop',
        },
      ],
      usage: null,
    });

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    expect(result.tokenUsage.promptTokens).toBe(0);
    expect(result.tokenUsage.completionTokens).toBe(0);
  });

  it('should handle missing finish_reason (null)', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: { role: 'assistant' as const, content: 'Done.', tool_calls: undefined },
          finish_reason: null,
        },
      ],
      usage: { prompt_tokens: 50, completion_tokens: 25 },
    });

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      maxTurns: 1,
      toolExecutors: {},
    });

    expect(result.turns[0].finishReason).toBe('unknown');
  });

  it('should report stopReason=stop on normal completion', async () => {
    mockCreate.mockResolvedValueOnce(mockStopResponse('Normal end.'));

    const result = await runAgent('sys', 'user', {
      apiKey: 'test-key',
      toolExecutors: {},
    });

    expect(result.stopReason).toBe('stop');
    expect(result.errors).toHaveLength(0);
  });
});
