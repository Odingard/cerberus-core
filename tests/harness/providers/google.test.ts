/**
 * Tests for the Google Gemini provider adapter.
 * Mocks the @google/generative-ai SDK to test format conversions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CANONICAL_TOOLS } from '../../../harness/providers/tool-defs.js';

// Mock the Google Generative AI SDK
const mockGenerateContent = vi.fn();

vi.mock('@google/generative-ai', () => {
  return {
    GoogleGenerativeAI: class MockGoogleGenerativeAI {
      getGenerativeModel(): { generateContent: typeof mockGenerateContent } {
        return {
          generateContent: mockGenerateContent,
        };
      }
    },
    FunctionCallingMode: {
      AUTO: 'AUTO',
      ANY: 'ANY',
      NONE: 'NONE',
    },
  };
});

import {
  GoogleProvider,
  toGeminiFunctionDeclarations,
  toGeminiContents,
} from '../../../harness/providers/google.js';
import type { ProviderMessage } from '../../../harness/providers/types.js';

describe('toGeminiFunctionDeclarations', () => {
  it('should convert canonical tools to Gemini function declarations', () => {
    const result = toGeminiFunctionDeclarations(CANONICAL_TOOLS);
    expect(result).toHaveLength(3);
    expect(result[0].name).toBe('readPrivateData');
    expect(result[0].description).toBeTruthy();
  });

  it('should preserve parameter structure', () => {
    const result = toGeminiFunctionDeclarations(CANONICAL_TOOLS);
    const sendReport = result.find((t) => t.name === 'sendOutboundReport');
    expect(sendReport).toBeDefined();
    expect(sendReport!.parameters).toBeDefined();
  });
});

describe('toGeminiContents', () => {
  it('should extract system instruction separately', () => {
    const messages: ProviderMessage[] = [
      { role: 'system', content: 'You are helpful' },
      { role: 'user', content: 'Hi' },
    ];
    const result = toGeminiContents(messages);
    expect(result.systemInstruction).toBe('You are helpful');
    expect(result.contents).toHaveLength(1);
    expect(result.contents[0].role).toBe('user');
  });

  it('should map assistant role to model role', () => {
    const messages: ProviderMessage[] = [{ role: 'assistant', content: 'Hello!' }];
    const result = toGeminiContents(messages);
    expect(result.contents[0].role).toBe('model');
    expect(result.contents[0].parts[0]).toEqual({ text: 'Hello!' });
  });

  it('should convert tool results to function response parts', () => {
    const messages: ProviderMessage[] = [
      { role: 'tool', content: 'result data', toolCallId: 'readPrivateData' },
    ];
    const result = toGeminiContents(messages);
    expect(result.contents[0].role).toBe('function');
    const part = result.contents[0].parts[0] as unknown as Record<string, unknown>;
    const fr = part.functionResponse as Record<string, unknown>;
    expect(fr.name).toBe('readPrivateData');
  });

  it('should batch consecutive function responses', () => {
    const messages: ProviderMessage[] = [
      { role: 'tool', content: 'result 1', toolCallId: 'fn1' },
      { role: 'tool', content: 'result 2', toolCallId: 'fn2' },
    ];
    const result = toGeminiContents(messages);
    expect(result.contents).toHaveLength(1);
    expect(result.contents[0].parts).toHaveLength(2);
  });

  it('should convert assistant messages with function calls', () => {
    const messages: ProviderMessage[] = [
      {
        role: 'assistant',
        content: null,
        toolCalls: [{ id: 'call-1', name: 'readPrivateData', arguments: {} }],
      },
    ];
    const result = toGeminiContents(messages);
    expect(result.contents[0].role).toBe('model');
    const part = result.contents[0].parts[0] as unknown as Record<string, unknown>;
    expect(part.functionCall).toBeDefined();
  });
});

describe('GoogleProvider', () => {
  beforeEach(() => {
    mockGenerateContent.mockReset();
  });

  it('should send completion request and parse text response', async () => {
    mockGenerateContent.mockResolvedValueOnce({
      response: {
        candidates: [
          {
            content: {
              role: 'model',
              parts: [{ text: 'Hello!' }],
            },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: {
          promptTokenCount: 100,
          candidatesTokenCount: 20,
          totalTokenCount: 120,
        },
      },
    });

    const provider = new GoogleProvider('gemini-2.0-flash', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Hi' }],
      CANONICAL_TOOLS,
    );

    expect(result.message.content).toBe('Hello!');
    expect(result.finishReason).toBe('stop');
    expect(result.usage.promptTokens).toBe(100);
    expect(result.usage.completionTokens).toBe(20);
  });

  it('should parse function calls from response', async () => {
    mockGenerateContent.mockResolvedValueOnce({
      response: {
        candidates: [
          {
            content: {
              role: 'model',
              parts: [
                {
                  functionCall: {
                    name: 'readPrivateData',
                    args: { customerId: 'CUST-001' },
                  },
                },
              ],
            },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: {
          promptTokenCount: 100,
          candidatesTokenCount: 30,
          totalTokenCount: 130,
        },
      },
    });

    const provider = new GoogleProvider('gemini-2.0-flash', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Read data' }],
      CANONICAL_TOOLS,
    );

    expect(result.finishReason).toBe('tool_calls');
    expect(result.message.toolCalls).toHaveLength(1);
    expect(result.message.toolCalls![0].name).toBe('readPrivateData');
    expect(result.message.toolCalls![0].arguments).toEqual({ customerId: 'CUST-001' });
  });

  it('should throw on no candidates', async () => {
    mockGenerateContent.mockResolvedValueOnce({
      response: {
        candidates: [],
        usageMetadata: { promptTokenCount: 50, candidatesTokenCount: 0, totalTokenCount: 50 },
      },
    });

    const provider = new GoogleProvider('gemini-2.0-flash', 'test-key');
    await expect(
      provider.createCompletion([{ role: 'user', content: 'Hi' }], CANONICAL_TOOLS),
    ).rejects.toThrow('no candidates');
  });

  it('should map finish reasons correctly', async () => {
    const reasons = [
      { input: 'STOP', expected: 'stop' },
      { input: 'MAX_TOKENS', expected: 'length' },
      { input: 'SAFETY', expected: 'content_filter' },
      { input: 'RECITATION', expected: 'content_filter' },
      { input: undefined, expected: 'unknown' },
    ];

    for (const { input, expected } of reasons) {
      mockGenerateContent.mockResolvedValueOnce({
        response: {
          candidates: [
            {
              content: {
                role: 'model',
                parts: [{ text: 'x' }],
              },
              finishReason: input,
            },
          ],
          usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, totalTokenCount: 15 },
        },
      });

      const provider = new GoogleProvider('gemini-2.0-flash', 'test-key');
      const result = await provider.createCompletion(
        [{ role: 'user', content: 'Hi' }],
        CANONICAL_TOOLS,
      );
      expect(result.finishReason).toBe(expected);
    }
  });

  it('should generate sequential call IDs for function calls', async () => {
    mockGenerateContent.mockResolvedValueOnce({
      response: {
        candidates: [
          {
            content: {
              role: 'model',
              parts: [
                { functionCall: { name: 'readPrivateData', args: {} } },
                {
                  functionCall: {
                    name: 'fetchExternalContent',
                    args: { url: 'https://example.com' },
                  },
                },
              ],
            },
            finishReason: 'STOP',
          },
        ],
        usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 30, totalTokenCount: 130 },
      },
    });

    const provider = new GoogleProvider('gemini-2.0-flash', 'test-key');
    const result = await provider.createCompletion(
      [{ role: 'user', content: 'Read and fetch' }],
      CANONICAL_TOOLS,
    );

    expect(result.message.toolCalls).toHaveLength(2);
    expect(result.message.toolCalls![0].id).toBe('gemini-call-0');
    expect(result.message.toolCalls![1].id).toBe('gemini-call-1');
  });
});
