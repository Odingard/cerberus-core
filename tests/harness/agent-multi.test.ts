/**
 * Tests for the multi-provider attack agent.
 * Mocks the provider layer to test the agent loop mechanics.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { TurnRecord } from '../../harness/types.js';
import type { ProviderResponse, ModelProvider } from '../../harness/providers/types.js';

// Mock the providers module
const mockCreateProvider = vi.fn();

vi.mock('../../harness/providers/index.js', () => {
  return {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/explicit-function-return-type
    createProvider: (...args: unknown[]) => mockCreateProvider(...args),
    CANONICAL_TOOLS: [
      {
        name: 'readPrivateData',
        description: 'Read data',
        parameters: { type: 'object', properties: {}, required: [] },
      },
      {
        name: 'fetchExternalContent',
        description: 'Fetch',
        parameters: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
      },
      {
        name: 'sendOutboundReport',
        description: 'Send',
        parameters: {
          type: 'object',
          properties: {
            recipient: { type: 'string' },
            subject: { type: 'string' },
            body: { type: 'string' },
          },
          required: ['recipient', 'subject', 'body'],
        },
      },
    ],
  };
});

import { runAgentMulti } from '../../harness/agent-multi.js';

/** Create a mock provider that returns responses in sequence. */
function createMockProvider(responses: ProviderResponse[]): ModelProvider {
  let callIndex = 0;
  return {
    providerName: 'mock',
    modelId: 'mock-model',
    createCompletion: vi.fn(() => {
      const response = responses[callIndex];
      if (!response) throw new Error('No more mock responses');
      callIndex++;
      return Promise.resolve(response);
    }),
  };
}

describe('runAgentMulti', () => {
  beforeEach(() => {
    mockCreateProvider.mockReset();
  });

  it('should execute a multi-turn conversation with tool calls', async () => {
    const provider = createMockProvider([
      // Turn 0: tool call
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'call-1', name: 'readPrivateData', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 100, completionTokens: 30 },
      },
      // Turn 1: tool call
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [
            {
              id: 'call-2',
              name: 'fetchExternalContent',
              arguments: { url: 'https://example.com' },
            },
          ],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 200, completionTokens: 40 },
      },
      // Turn 2: final response
      {
        message: { role: 'assistant', content: 'Report complete.' },
        finishReason: 'stop',
        usage: { promptTokens: 300, completionTokens: 50 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('system prompt', 'user prompt', {
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('{"records":[]}'),
        fetchExternalContent: vi.fn().mockResolvedValue('page content'),
        sendOutboundReport: vi.fn().mockResolvedValue('sent'),
      },
    });

    expect(result.turns).toHaveLength(3);
    expect(result.turns[0].toolCalls).toHaveLength(1);
    expect(result.turns[0].toolCalls[0].toolName).toBe('readPrivateData');
    expect(result.finalMessage).toBe('Report complete.');
    expect(result.stopReason).toBe('stop');
  });

  it('should stop when the model returns finish_reason=stop', async () => {
    const provider = createMockProvider([
      {
        message: { role: 'assistant', content: 'Done immediately.' },
        finishReason: 'stop',
        usage: { promptTokens: 50, completionTokens: 10 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('sys', 'user', {
      toolExecutors: {},
    });

    expect(result.turns).toHaveLength(1);
    expect(result.finalMessage).toBe('Done immediately.');
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(provider.createCompletion).toHaveBeenCalledTimes(1);
  });

  it('should stop when maxTurns is reached', async () => {
    const provider = createMockProvider([
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'call-loop', name: 'readPrivateData', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 50, completionTokens: 20 },
      },
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'call-loop-2', name: 'readPrivateData', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 50, completionTokens: 20 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('sys', 'user', {
      maxTurns: 2,
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('data'),
      },
    });

    expect(result.turns).toHaveLength(2);
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(provider.createCompletion).toHaveBeenCalledTimes(2);
  });

  it('should accumulate token usage across turns', async () => {
    const provider = createMockProvider([
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'c1', name: 'readPrivateData', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 100, completionTokens: 50 },
      },
      {
        message: { role: 'assistant', content: 'Done.' },
        finishReason: 'stop',
        usage: { promptTokens: 200, completionTokens: 80 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('sys', 'user', {
      toolExecutors: {
        readPrivateData: vi.fn().mockResolvedValue('data'),
      },
    });

    expect(result.tokenUsage.promptTokens).toBe(300);
    expect(result.tokenUsage.completionTokens).toBe(130);
    expect(result.tokenUsage.totalTokens).toBe(430);
  });

  it('should invoke onTurn callback for each turn', async () => {
    const provider = createMockProvider([
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'c1', name: 'readPrivateData', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 50, completionTokens: 20 },
      },
      {
        message: { role: 'assistant', content: 'Done.' },
        finishReason: 'stop',
        usage: { promptTokens: 100, completionTokens: 30 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const turns: TurnRecord[] = [];
    await runAgentMulti('sys', 'user', {
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
    const provider = createMockProvider([
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'c1', name: 'unknownTool', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 50, completionTokens: 20 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    await expect(
      runAgentMulti('sys', 'user', {
        toolExecutors: {
          readPrivateData: vi.fn().mockResolvedValue('data'),
        },
      }),
    ).rejects.toThrow('Unknown tool "unknownTool"');
  });

  it('should handle tool executor errors gracefully', async () => {
    const provider = createMockProvider([
      {
        message: {
          role: 'assistant',
          content: null,
          toolCalls: [{ id: 'c1', name: 'readPrivateData', arguments: {} }],
        },
        finishReason: 'tool_calls',
        usage: { promptTokens: 50, completionTokens: 20 },
      },
      {
        message: { role: 'assistant', content: 'Done despite error.' },
        finishReason: 'stop',
        usage: { promptTokens: 100, completionTokens: 30 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('sys', 'user', {
      toolExecutors: {
        readPrivateData: vi.fn().mockRejectedValue(new Error('DB failed')),
      },
    });

    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].code).toBe('TOOL_EXEC');
    expect(result.errors[0].message).toContain('DB failed');
    expect(result.finalMessage).toBe('Done despite error.');
  });

  it('should handle content_filter finish reason', async () => {
    const provider = createMockProvider([
      {
        message: { role: 'assistant', content: null },
        finishReason: 'content_filter',
        usage: { promptTokens: 50, completionTokens: 0 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('sys', 'user', {
      toolExecutors: {},
    });

    expect(result.stopReason).toBe('content_filter');
    expect(result.errors.some((e) => e.message.includes('content policy'))).toBe(true);
  });

  it('should handle length finish reason', async () => {
    const provider = createMockProvider([
      {
        message: { role: 'assistant', content: 'truncated...' },
        finishReason: 'length',
        usage: { promptTokens: 50, completionTokens: 4096 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    const result = await runAgentMulti('sys', 'user', {
      toolExecutors: {},
    });

    expect(result.stopReason).toBe('length');
    expect(result.errors.some((e) => e.message.includes('truncated'))).toBe(true);
  });

  it('should use default model gpt-4o-mini when not specified', async () => {
    const provider = createMockProvider([
      {
        message: { role: 'assistant', content: 'Done.' },
        finishReason: 'stop',
        usage: { promptTokens: 50, completionTokens: 10 },
      },
    ]);

    mockCreateProvider.mockReturnValue(provider);

    await runAgentMulti('sys', 'user', { toolExecutors: {} });

    expect(mockCreateProvider).toHaveBeenCalledWith('gpt-4o-mini', undefined);
  });
});
