/**
 * Tests for Secrets/Credential Detector.
 */

import { describe, it, expect } from 'vitest';
import { detectSecrets, detectSecretsInResult } from '../../src/classifiers/secrets-detector.js';
import { createSession } from '../../src/engine/session.js';
import type { ToolCallContext } from '../../src/types/context.js';

function makeCtx(overrides: Partial<ToolCallContext> = {}): ToolCallContext {
  return {
    turnId: 'turn-001',
    sessionId: 'session-test',
    toolName: 'readPrivateData',
    toolArguments: {},
    toolResult: '',
    timestamp: Date.now(),
    ...overrides,
  };
}

describe('detectSecrets', () => {
  it('should detect AWS access keys', () => {
    const text = 'key: AKIAIOSFODNN7EXAMPLE';
    const results = detectSecrets(text);
    expect(results.has('aws_key')).toBe(true);
    expect(results.get('aws_key')![0]).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  it('should detect GitHub tokens (personal)', () => {
    const text = 'token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';
    const results = detectSecrets(text);
    expect(results.has('github_token')).toBe(true);
  });

  it('should detect GitHub tokens (secret)', () => {
    const text = 'ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';
    const results = detectSecrets(text);
    expect(results.has('github_token')).toBe(true);
  });

  it('should detect JWTs', () => {
    const text =
      'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const results = detectSecrets(text);
    expect(results.has('jwt')).toBe(true);
  });

  it('should detect generic API keys', () => {
    const text = 'api_key = "sk_live_abcdefghijklmnop1234"';
    const results = detectSecrets(text);
    expect(results.has('generic_api_key')).toBe(true);
  });

  it('should detect API keys with colon separator', () => {
    const text = 'secret_key: ABCDEFGHIJKLMNOPQRSTUVWX';
    const results = detectSecrets(text);
    expect(results.has('generic_api_key')).toBe(true);
  });

  it('should detect private key headers', () => {
    const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...';
    const results = detectSecrets(text);
    expect(results.has('private_key')).toBe(true);
  });

  it('should detect EC private key headers', () => {
    const text = '-----BEGIN EC PRIVATE KEY-----\nMHQC...';
    const results = detectSecrets(text);
    expect(results.has('private_key')).toBe(true);
  });

  it('should detect connection strings', () => {
    const text = 'DATABASE_URL=postgres://user:pass@host:5432/db';
    const results = detectSecrets(text);
    expect(results.has('connection_string')).toBe(true);
  });

  it('should detect MongoDB connection strings', () => {
    const text = 'mongodb://admin:secret@cluster0.example.net/mydb';
    const results = detectSecrets(text);
    expect(results.has('connection_string')).toBe(true);
  });

  it('should detect Redis connection strings', () => {
    const text = 'redis://default:password@redis-host:6379';
    const results = detectSecrets(text);
    expect(results.has('connection_string')).toBe(true);
  });

  it('should return empty map for text with no secrets', () => {
    const text = 'Hello world, no secrets here. Just a normal sentence.';
    const results = detectSecrets(text);
    expect(results.size).toBe(0);
  });

  it('should detect multiple secret types in one text', () => {
    const text = 'AWS: AKIAIOSFODNN7EXAMPLE\nDB: postgres://user:pass@host/db';
    const results = detectSecrets(text);
    expect(results.has('aws_key')).toBe(true);
    expect(results.has('connection_string')).toBe(true);
  });
});

describe('detectSecretsInResult', () => {
  it('should return signal when secrets found in trusted tool result', () => {
    const session = createSession();
    const ctx = makeCtx({ toolResult: 'key: AKIAIOSFODNN7EXAMPLE' });
    const signal = detectSecretsInResult(ctx, session, true);
    expect(signal).not.toBeNull();
    expect(signal!.layer).toBe('L1');
    expect(signal!.signal).toBe('SECRETS_DETECTED');
    expect(signal!.secretTypes).toContain('aws_key');
    expect(signal!.count).toBe(1);
  });

  it('should return null for untrusted tools', () => {
    const session = createSession();
    const ctx = makeCtx({ toolResult: 'key: AKIAIOSFODNN7EXAMPLE' });
    expect(detectSecretsInResult(ctx, session, false)).toBeNull();
  });

  it('should return null when no secrets detected', () => {
    const session = createSession();
    const ctx = makeCtx({ toolResult: 'no secrets here' });
    expect(detectSecretsInResult(ctx, session, true)).toBeNull();
  });

  it('should update session.detectedSecrets', () => {
    const session = createSession();
    const ctx = makeCtx({ toolResult: 'key: AKIAIOSFODNN7EXAMPLE' });
    detectSecretsInResult(ctx, session, true);
    expect(session.detectedSecrets.has('AKIAIOSFODNN7EXAMPLE')).toBe(true);
  });

  it('should add secrets to session.privilegedValues for L3 matching', () => {
    const session = createSession();
    const ctx = makeCtx({ toolResult: 'key: AKIAIOSFODNN7EXAMPLE' });
    detectSecretsInResult(ctx, session, true);
    expect(session.privilegedValues.has('akiaiosfodnn7example')).toBe(true);
  });

  it('should set correct turnId', () => {
    const session = createSession();
    const ctx = makeCtx({ turnId: 'turn-042', toolResult: 'key: AKIAIOSFODNN7EXAMPLE' });
    const signal = detectSecretsInResult(ctx, session, true);
    expect(signal!.turnId).toBe('turn-042');
  });

  it('should count multiple secrets correctly', () => {
    const session = createSession();
    const ctx = makeCtx({
      toolResult: 'AWS: AKIAIOSFODNN7EXAMPLE\nDB: postgres://user:pass@host/db',
    });
    const signal = detectSecretsInResult(ctx, session, true);
    expect(signal!.count).toBe(2);
    expect(signal!.secretTypes).toHaveLength(2);
  });
});
