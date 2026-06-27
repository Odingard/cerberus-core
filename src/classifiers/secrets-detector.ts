/**
 * Secrets/Credential Detector — Sub-classifier enhancing L1.
 *
 * Scans tool results for leaked credentials: API keys, JWTs, private keys,
 * connection strings, AWS keys, GitHub tokens. Adds detected secrets to
 * session state for L3 cross-correlation.
 */

import type { SecretsDetectedSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';

/** Secret pattern definition with type label. */
interface SecretPattern {
  readonly type: string;
  readonly pattern: RegExp;
}

/** Patterns for detecting secrets/credentials in text. */
const SECRET_PATTERNS: readonly SecretPattern[] = [
  { type: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/g },
  { type: 'github_token', pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g },
  { type: 'jwt', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g },
  {
    type: 'generic_api_key',
    pattern:
      /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+=]{16,}/gi,
  },
  { type: 'private_key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  {
    type: 'connection_string',
    pattern: /(?:mongodb|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s"']+/gi,
  },
];

/**
 * Scan text for secret patterns. Returns a map of secret type → matched values.
 */
export function detectSecrets(text: string): Map<string, string[]> {
  const results = new Map<string, string[]>();

  for (const { type, pattern } of SECRET_PATTERNS) {
    // Reset regex state for each scan
    pattern.lastIndex = 0;
    const matches: string[] = [];
    let match = pattern.exec(text);
    while (match) {
      matches.push(match[0]);
      match = pattern.exec(text);
    }
    if (matches.length > 0) {
      results.set(type, matches);
    }
  }

  return results;
}

/**
 * Detect secrets in a tool result and emit an L1 signal.
 * Only runs when the tool is trusted (same gate as L1).
 * Updates session.detectedSecrets and session.privilegedValues.
 */
export function detectSecretsInResult(
  ctx: ToolCallContext,
  session: DetectionSession,
  isTrusted: boolean,
): SecretsDetectedSignal | null {
  if (!isTrusted) {
    return null;
  }

  const secrets = detectSecrets(ctx.toolResult);
  if (secrets.size === 0) {
    return null;
  }

  const secretTypes: string[] = [];
  let totalCount = 0;

  for (const [type, values] of secrets) {
    secretTypes.push(type);
    totalCount += values.length;
    for (const value of values) {
      session.detectedSecrets.add(value);
      session.privilegedValues.add(value.toLowerCase());
    }
  }

  return {
    layer: 'L1',
    signal: 'SECRETS_DETECTED',
    turnId: ctx.turnId,
    secretTypes,
    count: totalCount,
    timestamp: ctx.timestamp,
  };
}
