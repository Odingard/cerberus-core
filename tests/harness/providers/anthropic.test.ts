/**
 * Tests for the Anthropic provider adapter.
 * Mocks the Anthropic SDK to test format conversions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CANONICAL_TOOLS } from '../../../harness/providers/tool-defs.js';

// Mock the Anthropic SDK
const mockCreate = vi.fn();

vi.mock('@anthropic-ai/sdk', () => {
  return {
    default: class MockAnthropic {
      messages = {
        create: mockCreate,
      };
    },
  };
});

import {
  AnthropicProvider,
  toAnthropicTools,
  toAnthropicMessages,
} from '../../../harness/providers/anthropic.js';
import type { ProviderMessage } from '../../../harness/providers/types.js';

describe('toAnthropicTools', () => {
  it('should convert canonical tools to Anthropic input_schema format', () => {
    const result = toAnthropicTools(CANONICAL_TOOLS);
    expect(result).toHaveLength(3);
    expect(result[0].name).toBe('readPrivateData');
    expect(result[0].input_schema.type).toBe('object');
    expect(result[0].description).toBeTruthy();
  });

  it('should preserve required fields', () => {
    const result = toAnthropicTools(CANONICAL_TOOLS);
    const sendReport = result.find((t) => t.name === 'sendOutboundReport');
    expect(sendReport).toBeDefined();
    expect(sendReport!.input_schema.required).toContain('recipient');
  });
});

describe('toAnthropicMessages', () => {
  it('should extract system prompt separately', () => {
    const messages: ProviderMessage[] = [
      { role: 'system', content: 'You are helpful' },
      { role: 'user', content: 'Hi' },
    ];
    const result = toAnthropicMessages(messages);
    expect(result.system).toBe('You are helpful');
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0].role).toBe('user');
  });

  it('should convert tool results to user messages with tool_result blocks', () => {
    const messages: ProviderMessage[] = [
      { role: 'tool', content: 'result data', toolCallId: 'tool-use-1' },
    ];
    const result = toAnthropicMessages(messages);
    expect(result.messages).toHaveLength(1);
    expect(result.messages[0].role).toBe('user');
    const content = result.messages[0].content as unknown as Array<Record<string, unknown>>;
    expect(content[0].type).toBe('tool_result');
    expect(content[0].tool_use_id).toBe('tool-use-1');
  });

  it('should batch consecutive tool results into one user message', () => {
    const messages: ProviderMessage[] = [
      { role: 'tool', content: 'result 1', toolCallId: 'tc-1' },
      { role: 'tool', content: 'result 2', toolCallId: 'tc-2' },
    ];
    const result = toAnthropicMessages(messages);
    expect(result.messages).toHaveLength(1);
    const content = result.messages[0].content as unknown as Array<Record<string, unknown>>;
    expect(content).toHaveLength(2);
  });

  it('should convert assistant messages with tool calls to content blocks', () => {
    const messages: ProviderMessage[] = [
      {
        role: 'assistant',
        content: 'Let me check.',
        toolCalls: [{ id: 'tc-1', name: 'readPrivateData', arguments: {} }],
      },
    ];
    const result = toAnthropicMessages(messages);
    expect(result.messages).toHaveLength(1);
    const content = result.messages[0].content as unknown as Array<Record<string, unknown>>;
    expect(content).toHaveLength(2); // text + tool_use
    expect(content[0].type).toBe('text');
    expect(content[1].type).toBe('tool_use');
  });
});

describe('AnthropicProvider', () => {
  beforeEach(() => {
    mockCreate.mockReset();
  });

  it('should send completion request and parse text response', async () => {
    mockCreate.mockResolvedValueOnce({
      content: [{ type: 'text', text: 'Hello!' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 100, output_tokens: 20 },
    });

    const provider = new AnthropicProvider('claude-sonnet-4-6', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Hi' }],
      CANONICAL_TOOLS,
    );

    expect(result.message.content).toBe('Hello!');
    expect(result.finishReason).toBe('stop');
    expect(result.usage.promptTokens).toBe(100);
    expect(result.usage.completionTokens).toBe(20);
  });

  it('should parse tool_use blocks from response', async () => {
    mockCreate.mockResolvedValueOnce({
      content: [
        { type: 'text', text: 'Let me read the data.' },
        {
          type: 'tool_use',
          id: 'toolu_123',
          name: 'readPrivateData',
          input: { customerId: 'CUST-001' },
        },
      ],
      stop_reason: 'tool_use',
      usage: { input_tokens: 150, output_tokens: 40 },
    });

    const provider = new AnthropicProvider('claude-sonnet-4-6', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Read data' }],
      CANONICAL_TOOLS,
    );

    expect(result.finishReason).toBe('tool_calls');
    expect(result.message.toolCalls).toHaveLength(1);
    expect(result.message.toolCalls![0].id).toBe('toolu_123');
    expect(result.message.toolCalls![0].name).toBe('readPrivateData');
    expect(result.message.toolCalls![0].arguments).toEqual({ customerId: 'CUST-001' });
    expect(result.message.content).toBe('Let me read the data.');
  });

  it('should map stop reasons correctly', async () => {
    const reasons = [
      { input: 'end_turn', expected: 'stop' },
      { input: 'tool_use', expected: 'tool_calls' },
      { input: 'max_tokens', expected: 'length' },
      { input: 'refusal', expected: 'content_filter' },
      { input: 'stop_sequence', expected: 'stop' },
    ];

    for (const { input, expected } of reasons) {
      mockCreate.mockResolvedValueOnce({
        content: [{ type: 'text', text: 'x' }],
        stop_reason: input,
        usage: { input_tokens: 10, output_tokens: 5 },
      });

      const provider = new AnthropicProvider('claude-sonnet-4-6', 'test-key');
      const result = await provider.createCompletion(
        [{ role: 'user', content: 'Hi' }],
        CANONICAL_TOOLS,
      );
      expect(result.finishReason).toBe(expected);
    }
  });

  it('should pass temperature but not seed (Anthropic does not support seed)', async () => {
    mockCreate.mockResolvedValueOnce({
      content: [{ type: 'text', text: 'Ok' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 50, output_tokens: 10 },
    });

    const provider = new AnthropicProvider('claude-sonnet-4-6', 'test-key');
    await provider.createCompletion([{ role: 'user', content: 'Hi' }], CANONICAL_TOOLS, {
      temperature: 0,
    });

    const callArgs = mockCreate.mock.calls[0][0] as Record<string, unknown>;
    expect(callArgs.temperature).toBe(0);
    expect(callArgs.model).toBe('claude-sonnet-4-6');
    expect(callArgs.max_tokens).toBe(4096);
  });

  it('should pass system prompt separately', async () => {
    mockCreate.mockResolvedValueOnce({
      content: [{ type: 'text', text: 'Ok' }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 50, output_tokens: 10 },
    });

    const provider = new AnthropicProvider('claude-sonnet-4-6', 'test-key');
    await provider.createCompletion(
      [
        { role: 'system', content: 'Be helpful' },
        { role: 'user', content: 'Hi' },
      ],
      CANONICAL_TOOLS,
    );

    const callArgs = mockCreate.mock.calls[0][0] as Record<string, unknown>;
    expect(callArgs.system).toBe('Be helpful');
  });
});
