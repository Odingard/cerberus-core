/**
 * Dynamic Tool Registration — Runtime tool registration with security checks.
 *
 * Allows tools to be registered after session start. Checks for injection-assisted
 * registration, tracks schema fingerprints, and detects scope expansion.
 */

import type { DetectionSignal } from '../types/signals.js';
import type { DetectionSession } from './session.js';
import { recordSignal } from './session.js';

/** Schema definition for a dynamically registered tool. */
export interface ToolSchema {
  readonly name: string;
  readonly description?: string;
  readonly parameters?: Readonly<Record<string, unknown>>;
}

/** Result of a late tool registration attempt. */
export interface ToolRegistrationResult {
  readonly registered: boolean;
  readonly signals: readonly DetectionSignal[];
  readonly blocked: boolean;
  readonly blockReason?: string;
}

/**
 * Compute a deterministic hash of a tool schema for fingerprinting.
 * Uses a simple but stable string hash of the JSON-serialized schema.
 */
export function computeSchemaHash(schema: ToolSchema): string {
  const normalized = JSON.stringify({
    name: schema.name,
    ...(schema.description !== undefined ? { description: schema.description } : {}),
    ...(schema.parameters !== undefined ? { parameters: schema.parameters } : {}),
  });

  // djb2 hash — simple, deterministic, no crypto dependency
  let hash = 5381;
  for (let i = 0; i < normalized.length; i++) {
    hash = ((hash << 5) + hash + normalized.charCodeAt(i)) | 0;
  }

  // Convert to unsigned hex string
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Check whether the session has active injection context.
 * Returns true if injection patterns were detected in the current or recent session.
 */
function hasActiveInjectionContext(session: DetectionSession): boolean {
  return session.injectionPatternsFound.size > 0;
}

/**
 * Register a tool at runtime with security checks.
 *
 * - If injection patterns are active in the session, blocks the registration
 *   and emits INJECTION_ASSISTED_REGISTRATION.
 * - Otherwise, registers the tool with a schema fingerprint and emits
 *   LATE_TOOL_REGISTERED.
 * - If the tool was already registered with a different schema, emits
 *   SCOPE_EXPANSION.
 */
export function registerToolLate(
  tool: ToolSchema,
  reason: string,
  authorizedBy: string,
  session: DetectionSession,
): ToolRegistrationResult {
  const turnId = `reg-${String(session.turnCounter).padStart(3, '0')}`;
  const now = Date.now();
  const schemaHash = computeSchemaHash(tool);
  const signals: DetectionSignal[] = [];

  // Check for injection-assisted registration
  if (hasActiveInjectionContext(session)) {
    const injectionSignal: DetectionSignal = {
      layer: 'L2',
      signal: 'INJECTION_ASSISTED_REGISTRATION',
      turnId,
      toolName: tool.name,
      injectionPatterns: [...session.injectionPatternsFound],
      timestamp: now,
    };
    signals.push(injectionSignal);
    recordSignal(session, injectionSignal);

    // Record audit entry
    session.toolRegistrationAudit.push({
      toolName: tool.name,
      reason,
      authorizedBy,
      schemaHash,
      timestamp: now,
      blocked: true,
      blockReason: 'Injection patterns detected in session context',
    });

    return {
      registered: false,
      signals,
      blocked: true,
      blockReason: 'Injection patterns detected in session context',
    };
  }

  // Check for scope expansion (tool already registered with different schema)
  const existingEntry = session.registeredTools.get(tool.name);
  if (existingEntry && existingEntry.schemaHash !== schemaHash) {
    const expansionSignal: DetectionSignal = {
      layer: 'L2',
      signal: 'SCOPE_EXPANSION',
      turnId,
      toolName: tool.name,
      originalHash: existingEntry.schemaHash,
      newHash: schemaHash,
      timestamp: now,
    };
    signals.push(expansionSignal);
    recordSignal(session, expansionSignal);
  }

  // Register the tool
  session.registeredTools.set(tool.name, {
    toolName: tool.name,
    schemaHash,
    registeredAt: now,
    authorizedBy,
  });

  // Emit late registration signal
  const registeredSignal: DetectionSignal = {
    layer: 'L2',
    signal: 'LATE_TOOL_REGISTERED',
    turnId,
    toolName: tool.name,
    reason,
    authorizedBy,
    schemaHash,
    timestamp: now,
  };
  signals.push(registeredSignal);
  recordSignal(session, registeredSignal);

  // Record audit entry
  session.toolRegistrationAudit.push({
    toolName: tool.name,
    reason,
    authorizedBy,
    schemaHash,
    timestamp: now,
    blocked: false,
  });

  return {
    registered: true,
    signals,
    blocked: false,
  };
}
