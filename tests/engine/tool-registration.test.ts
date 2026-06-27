/**
 * Tests for Dynamic Tool Registration — registerToolLate(), schema hashing, scope expansion.
 */

import { describe, it, expect } from 'vitest';
import { createSession } from '../../src/engine/session.js';
import { registerToolLate, computeSchemaHash } from '../../src/engine/tool-registration.js';
import type { ToolSchema } from '../../src/engine/tool-registration.js';

describe('computeSchemaHash', () => {
  it('should produce a deterministic hash for the same schema', () => {
    const schema: ToolSchema = {
      name: 'sendEmail',
      description: 'Send an email',
      parameters: { to: { type: 'string' }, body: { type: 'string' } },
    };

    const hash1 = computeSchemaHash(schema);
    const hash2 = computeSchemaHash(schema);

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[0-9a-f]{8}$/);
  });

  it('should produce different hashes for different schemas', () => {
    const schema1: ToolSchema = {
      name: 'sendEmail',
      description: 'Send an email',
    };
    const schema2: ToolSchema = {
      name: 'sendEmail',
      description: 'Send an email to anyone',
    };

    expect(computeSchemaHash(schema1)).not.toBe(computeSchemaHash(schema2));
  });

  it('should produce different hashes when parameters differ', () => {
    const schema1: ToolSchema = {
      name: 'readFile',
      parameters: { path: { type: 'string' } },
    };
    const schema2: ToolSchema = {
      name: 'readFile',
      parameters: { path: { type: 'string' }, recursive: { type: 'boolean' } },
    };

    expect(computeSchemaHash(schema1)).not.toBe(computeSchemaHash(schema2));
  });

  it('should handle schema with no optional fields', () => {
    const schema: ToolSchema = { name: 'simple' };
    const hash = computeSchemaHash(schema);
    expect(hash).toMatch(/^[0-9a-f]{8}$/);
  });
});

describe('registerToolLate', () => {
  it('should register a tool and emit LATE_TOOL_REGISTERED signal', () => {
    const session = createSession('test-session');
    const tool: ToolSchema = {
      name: 'newTool',
      description: 'A dynamically registered tool',
      parameters: { input: { type: 'string' } },
    };

    const result = registerToolLate(tool, 'plugin loaded', 'admin', session);

    expect(result.registered).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.signals).toHaveLength(1);
    expect(result.signals[0].signal).toBe('LATE_TOOL_REGISTERED');

    const sig = result.signals[0];
    expect(sig.layer).toBe('L2');
    if (sig.signal === 'LATE_TOOL_REGISTERED') {
      expect(sig.toolName).toBe('newTool');
      expect(sig.reason).toBe('plugin loaded');
      expect(sig.authorizedBy).toBe('admin');
      expect(sig.schemaHash).toMatch(/^[0-9a-f]{8}$/);
    }
  });

  it('should add the tool to the session registered tools map', () => {
    const session = createSession('test-session');
    const tool: ToolSchema = { name: 'myTool', description: 'test' };

    registerToolLate(tool, 'test', 'user', session);

    expect(session.registeredTools.has('myTool')).toBe(true);
    const entry = session.registeredTools.get('myTool')!;
    expect(entry.toolName).toBe('myTool');
    expect(entry.authorizedBy).toBe('user');
    expect(entry.schemaHash).toMatch(/^[0-9a-f]{8}$/);
  });

  it('should create an audit entry for registration', () => {
    const session = createSession('test-session');
    const tool: ToolSchema = { name: 'auditTool' };

    registerToolLate(tool, 'audit test', 'operator', session);

    expect(session.toolRegistrationAudit).toHaveLength(1);
    const audit = session.toolRegistrationAudit[0];
    expect(audit.toolName).toBe('auditTool');
    expect(audit.reason).toBe('audit test');
    expect(audit.authorizedBy).toBe('operator');
    expect(audit.blocked).toBe(false);
  });

  it('should record the signal in session signalsByTurn', () => {
    const session = createSession('test-session');
    const tool: ToolSchema = { name: 'trackedTool' };

    registerToolLate(tool, 'test', 'admin', session);

    expect(session.signalsByTurn.size).toBe(1);
    const turnSignals = [...session.signalsByTurn.values()][0];
    expect(turnSignals[0].signal).toBe('LATE_TOOL_REGISTERED');
  });

  it('should block registration when injection patterns are active', () => {
    const session = createSession('test-session');
    // Simulate injection patterns detected in session
    session.injectionPatternsFound.add('role_override');
    session.injectionPatternsFound.add('exfiltration_command');

    const tool: ToolSchema = {
      name: 'suspiciousTool',
      description: 'Tool registered during injection attack',
    };

    const result = registerToolLate(tool, 'attacker request', 'unknown', session);

    expect(result.registered).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.blockReason).toContain('Injection patterns');
    expect(result.signals).toHaveLength(1);
    expect(result.signals[0].signal).toBe('INJECTION_ASSISTED_REGISTRATION');

    const sig = result.signals[0];
    if (sig.signal === 'INJECTION_ASSISTED_REGISTRATION') {
      expect(sig.toolName).toBe('suspiciousTool');
      expect(sig.injectionPatterns).toContain('role_override');
      expect(sig.injectionPatterns).toContain('exfiltration_command');
    }
  });

  it('should not add blocked tool to registered tools map', () => {
    const session = createSession('test-session');
    session.injectionPatternsFound.add('authority_spoofing');

    const tool: ToolSchema = { name: 'blockedTool' };
    registerToolLate(tool, 'test', 'admin', session);

    expect(session.registeredTools.has('blockedTool')).toBe(false);
  });

  it('should create a blocked audit entry when registration is denied', () => {
    const session = createSession('test-session');
    session.injectionPatternsFound.add('instruction_injection');

    const tool: ToolSchema = { name: 'deniedTool' };
    registerToolLate(tool, 'deny test', 'unknown', session);

    expect(session.toolRegistrationAudit).toHaveLength(1);
    const audit = session.toolRegistrationAudit[0];
    expect(audit.blocked).toBe(true);
    expect(audit.blockReason).toContain('Injection patterns');
  });

  it('should detect scope expansion when tool schema changes', () => {
    const session = createSession('test-session');

    // Register initial version
    const toolV1: ToolSchema = {
      name: 'expandingTool',
      parameters: { query: { type: 'string' } },
    };
    const result1 = registerToolLate(toolV1, 'initial', 'admin', session);
    expect(result1.registered).toBe(true);
    expect(result1.signals).toHaveLength(1);

    // Register expanded version — should emit SCOPE_EXPANSION + LATE_TOOL_REGISTERED
    const toolV2: ToolSchema = {
      name: 'expandingTool',
      parameters: {
        query: { type: 'string' },
        admin: { type: 'boolean' },
        deleteAll: { type: 'boolean' },
      },
    };
    const result2 = registerToolLate(toolV2, 'expanded', 'admin', session);

    expect(result2.registered).toBe(true);
    expect(result2.signals).toHaveLength(2);

    const scopeSignal = result2.signals.find((s) => s.signal === 'SCOPE_EXPANSION');
    expect(scopeSignal).toBeDefined();
    if (scopeSignal && scopeSignal.signal === 'SCOPE_EXPANSION') {
      expect(scopeSignal.toolName).toBe('expandingTool');
      expect(scopeSignal.originalHash).not.toBe(scopeSignal.newHash);
    }

    const lateSignal = result2.signals.find((s) => s.signal === 'LATE_TOOL_REGISTERED');
    expect(lateSignal).toBeDefined();
  });

  it('should not emit scope expansion when re-registering with same schema', () => {
    const session = createSession('test-session');

    const tool: ToolSchema = {
      name: 'stableTool',
      parameters: { x: { type: 'number' } },
    };

    registerToolLate(tool, 'first', 'admin', session);
    const result2 = registerToolLate(tool, 'second', 'admin', session);

    expect(result2.registered).toBe(true);
    // Should only have LATE_TOOL_REGISTERED, no SCOPE_EXPANSION
    expect(result2.signals).toHaveLength(1);
    expect(result2.signals[0].signal).toBe('LATE_TOOL_REGISTERED');
  });

  it('should update schema hash on re-registration with different schema', () => {
    const session = createSession('test-session');

    const toolV1: ToolSchema = { name: 'updatedTool', description: 'v1' };
    registerToolLate(toolV1, 'v1', 'admin', session);
    const hash1 = session.registeredTools.get('updatedTool')!.schemaHash;

    const toolV2: ToolSchema = { name: 'updatedTool', description: 'v2 with more capabilities' };
    registerToolLate(toolV2, 'v2', 'admin', session);
    const hash2 = session.registeredTools.get('updatedTool')!.schemaHash;

    expect(hash1).not.toBe(hash2);
  });

  it('should allow registration of multiple different tools', () => {
    const session = createSession('test-session');

    registerToolLate({ name: 'tool1' }, 'reason1', 'admin', session);
    registerToolLate({ name: 'tool2' }, 'reason2', 'admin', session);
    registerToolLate({ name: 'tool3' }, 'reason3', 'admin', session);

    expect(session.registeredTools.size).toBe(3);
    expect(session.toolRegistrationAudit).toHaveLength(3);
  });

  it('should use turn counter for turn ID prefix', () => {
    const session = createSession('test-session');
    session.turnCounter = 5;

    const result = registerToolLate({ name: 'tool' }, 'test', 'admin', session);

    expect(result.signals[0].turnId).toBe('reg-005');
  });
});
