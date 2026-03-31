/**
 * Tests for the OpenAI provider adapter.
 * Mocks the OpenAI SDK to test format conversions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CANONICAL_TOOLS } from '../../../harness/providers/tool-defs.js';

// Mock the OpenAI SDK
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

import {
  OpenAIProvider,
  toOpenAITools,
  toOpenAIMessages,
} from '../../../harness/providers/openai.js';
import type { ProviderMessage } from '../../../harness/providers/types.js';

describe('toOpenAITools', () => {
  it('should wrap canonical tools in OpenAI function format', () => {
    const result = toOpenAITools(CANONICAL_TOOLS);
    expect(result).toHaveLength(3);
    const first = result[0] as unknown as Record<string, unknown>;
    expect(first.type).toBe('function');
    const fn = first.function as Record<string, unknown>;
    expect(fn.name).toBe('readPrivateData');
    expect(fn.parameters).toHaveProperty('type', 'object');
  });

  it('should preserve parameter schemas', () => {
    const result = toOpenAITools(CANONICAL_TOOLS) as unknown as Array<{
      type: string;
      function: { name: string; parameters: { required: string[] } };
    }>;
    const sendReport = result.find((t) => t.function.name === 'sendOutboundReport');
    expect(sendReport).toBeDefined();
    expect(sendReport!.function.parameters.required).toContain('recipient');
  });
});

describe('toOpenAIMessages', () => {
  it('should convert system messages', () => {
    const messages: ProviderMessage[] = [{ role: 'system', content: 'You are helpful' }];
    const result = toOpenAIMessages(messages);
    expect(result[0]).toEqual({ role: 'system', content: 'You are helpful' });
  });

  it('should convert tool messages with tool_call_id', () => {
    const messages: ProviderMessage[] = [
      { role: 'tool', content: 'result data', toolCallId: 'call-1' },
    ];
    const result = toOpenAIMessages(messages);
    expect(result[0]).toEqual({
      role: 'tool',
      tool_call_id: 'call-1',
      content: 'result data',
    });
  });

  it('should convert assistant messages with tool calls', () => {
    const messages: ProviderMessage[] = [
      {
        role: 'assistant',
        content: null,
        toolCalls: [
          { id: 'call-1', name: 'readPrivateData', arguments: { customerId: 'CUST-001' } },
        ],
      },
    ];
    const result = toOpenAIMessages(messages);
    const msg = result[0] as unknown as Record<string, unknown>;
    expect(msg.role).toBe('assistant');
    expect(msg.content).toBeNull();
    const toolCalls = msg.tool_calls as Array<Record<string, unknown>>;
    expect(toolCalls).toHaveLength(1);
    expect(toolCalls[0].id).toBe('call-1');
    const fn = toolCalls[0].function as Record<string, unknown>;
    expect(fn.arguments).toBe('{"customerId":"CUST-001"}');
  });
});

describe('OpenAIProvider', () => {
  beforeEach(() => {
    mockCreate.mockReset();
  });

  it('should send completion request and parse response', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: {
            role: 'assistant',
            content: 'Hello!',
            tool_calls: undefined,
          },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 100, completion_tokens: 20 },
    });

    const provider = new OpenAIProvider('gpt-4o-mini', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Hi' }],
      CANONICAL_TOOLS,
    );

    expect(result.message.content).toBe('Hello!');
    expect(result.finishReason).toBe('stop');
    expect(result.usage.promptTokens).toBe(100);
    expect(result.usage.completionTokens).toBe(20);
  });

  it('should parse tool calls from response', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: {
            role: 'assistant',
            content: null,
            tool_calls: [
              {
                id: 'call-1',
                type: 'function',
                function: {
                  name: 'readPrivateData',
                  arguments: '{"customerId":"CUST-001"}',
                },
              },
            ],
          },
          finish_reason: 'tool_calls',
        },
      ],
      usage: { prompt_tokens: 100, completion_tokens: 30 },
    });

    const provider = new OpenAIProvider('gpt-4o-mini', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Read data' }],
      CANONICAL_TOOLS,
    );

    expect(result.finishReason).toBe('tool_calls');
    expect(result.message.toolCalls).toHaveLength(1);
    expect(result.message.toolCalls![0].name).toBe('readPrivateData');
    expect(result.message.toolCalls![0].arguments).toEqual({ customerId: 'CUST-001' });
  });

  it('should throw on empty choices', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [],
      usage: { prompt_tokens: 50, completion_tokens: 0 },
    });

    const provider = new OpenAIProvider('gpt-4o-mini', 'test-key');
    await expect(
      provider.createCompletion([{ role: 'user', content: 'Hi' }], CANONICAL_TOOLS),
    ).rejects.toThrow('empty choices');
  });

  it('should pass temperature and seed', async () => {
    mockCreate.mockResolvedValueOnce({
      choices: [
        {
          message: { role: 'assistant', content: 'Ok', tool_calls: undefined },
          finish_reason: 'stop',
        },
      ],
      usage: { prompt_tokens: 50, completion_tokens: 10 },
    });

    const provider = new OpenAIProvider('gpt-4o-mini', 'test-key');
    await provider.createCompletion([{ role: 'user', content: 'Hi' }], CANONICAL_TOOLS, {
      temperature: 0,
      seed: 42,
    });

    const callArgs = mockCreate.mock.calls[0][0] as Record<string, unknown>;
    expect(callArgs.temperature).toBe(0);
    expect(callArgs.seed).toBe(42);
  });

  it('should map finish reasons correctly', async () => {
    const reasons = [
      { input: 'stop', expected: 'stop' },
      { input: 'tool_calls', expected: 'tool_calls' },
      { input: 'length', expected: 'length' },
      { input: 'content_filter', expected: 'content_filter' },
      { input: null, expected: 'unknown' },
    ];

    for (const { input, expected } of reasons) {
      mockCreate.mockResolvedValueOnce({
        choices: [
          {
            message: { role: 'assistant', content: 'x', tool_calls: undefined },
            finish_reason: input,
          },
        ],
        usage: { prompt_tokens: 10, completion_tokens: 5 },
      });

      const provider = new OpenAIProvider('gpt-4o-mini', 'test-key');
      const result = await provider.createCompletion(
        [{ role: 'user', content: 'Hi' }],
        CANONICAL_TOOLS,
      );
      expect(result.finishReason).toBe(expected);
    }
  });
});
