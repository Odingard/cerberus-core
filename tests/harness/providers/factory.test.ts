/**
 * Tests for provider factory and detection.
 */

import { describe, it, expect } from 'vitest';
import { detectProvider, createProvider } from '../../../harness/providers/index.js';

describe('detectProvider', () => {
  it('should detect OpenAI models', () => {
    expect(detectProvider('gpt-4o-mini')).toBe('openai');
    expect(detectProvider('gpt-4o')).toBe('openai');
    expect(detectProvider('gpt-3.5-turbo')).toBe('openai');
    expect(detectProvider('o1-preview')).toBe('openai');
  });

  it('should detect Anthropic models', () => {
    expect(detectProvider('claude-sonnet-4-6')).toBe('anthropic');
    expect(detectProvider('claude-opus-4-6')).toBe('anthropic');
    expect(detectProvider('claude-haiku-4-5-20251001')).toBe('anthropic');
    expect(detectProvider('claude-3-haiku-20240307')).toBe('anthropic');
  });

  it('should detect Google models', () => {
    expect(detectProvider('gemini-2.0-flash')).toBe('google');
    expect(detectProvider('gemini-1.5-pro')).toBe('google');
    expect(detectProvider('gemini-1.5-flash')).toBe('google');
  });

  it('should default to OpenAI for unknown model names', () => {
    expect(detectProvider('unknown-model')).toBe('openai');
    expect(detectProvider('')).toBe('openai');
  });
});

describe('createProvider', () => {
  it('should create OpenAI provider for GPT models', () => {
    const provider = createProvider('gpt-4o-mini', 'test-key');
    expect(provider.providerName).toBe('openai');
    expect(provider.modelId).toBe('gpt-4o-mini');
  });

  it('should create Anthropic provider for Claude models', () => {
    const provider = createProvider('claude-sonnet-4-6', 'test-key');
    expect(provider.providerName).toBe('anthropic');
    expect(provider.modelId).toBe('claude-sonnet-4-6');
  });

  it('should create Google provider for Gemini models', () => {
    const provider = createProvider('gemini-2.0-flash', 'test-key');
    expect(provider.providerName).toBe('google');
    expect(provider.modelId).toBe('gemini-2.0-flash');
  });
});
