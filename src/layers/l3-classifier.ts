/**
 * Layer 3 — Outbound Intent Classifier
 *
 * For outbound tool calls (tools that send data externally), checks
 * if the outbound content correlates with privileged data that L1
 * previously observed. This is the core exfiltration detector.
 *
 * L3 reads session state accumulated by L1 (privilegedValues) to detect
 * when PII flows out through an untrusted channel.
 */

import type { ExfiltrationRiskSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import type { SensitiveEntity } from './sensitive-entities.js';
import { matchesSensitiveEntityInText } from './sensitive-entities.js';

/** Destination field names to look for in tool arguments. */
const DESTINATION_FIELDS = [
  'recipient',
  'to',
  'destination',
  'url',
  'endpoint',
  'webhook',
  'target',
  'address',
  'host',
  'forward_to',
  'cc',
  'bcc',
];

/**
 * Classify whether this tool call is an exfiltration attempt.
 * Only runs for tools listed in outboundTools. Checks correlation
 * between tool arguments and previously accessed privileged data.
 *
 * When authorizedDestinations is provided, destinations matching an
 * authorized domain are considered expected business behavior and
 * L3 does NOT fire. This prevents false positives for agents that
 * legitimately report on customer data to authorized recipients.
 */
export function classifyOutboundIntent(
  ctx: ToolCallContext,
  session: DetectionSession,
  outboundTools: readonly string[],
  authorizedDestinations?: readonly string[],
): ExfiltrationRiskSignal | null {
  if (!isOutboundTool(ctx.toolName, outboundTools)) {
    return null;
  }

  if (session.privilegedValues.size === 0 && session.sensitiveEntities.length === 0) {
    return null;
  }

  const destination = extractDestination(ctx.toolArguments);

  // Skip L3 for authorized destinations — PII flow is expected
  if (isAuthorizedDestination(destination, authorizedDestinations ?? [])) {
    return null;
  }

  const outboundText = serializeArguments(ctx.toolArguments);
  const { score, matchedFields } =
    session.sensitiveEntities.length > 0
      ? computeEntitySimilarityScore(outboundText, session.sensitiveEntities)
      : computeSimilarityScore(outboundText, session.privilegedValues);

  if (matchedFields.length === 0) {
    return null;
  }

  return {
    layer: 'L3',
    signal: 'EXFILTRATION_RISK',
    turnId: ctx.turnId,
    matchedFields,
    destination,
    similarityScore: score,
    timestamp: ctx.timestamp,
  };
}

export function computeEntitySimilarityScore(
  outboundText: string,
  sensitiveEntities: readonly SensitiveEntity[],
): { score: number; matchedFields: readonly string[] } {
  if (sensitiveEntities.length === 0) {
    return { score: 0, matchedFields: [] };
  }

  const matched = sensitiveEntities
    .filter((entity) => matchesSensitiveEntityInText(entity, outboundText))
    .map((entity) => entity.rawValue);

  return {
    score: matched.length / sensitiveEntities.length,
    matchedFields: matched,
  };
}

/**
 * Determine if a tool is outbound based on explicit configuration.
 */
export function isOutboundTool(toolName: string, outboundTools: readonly string[]): boolean {
  return outboundTools.includes(toolName);
}

/**
 * Compute similarity score between outbound content and privileged values.
 * Uses case-insensitive substring matching.
 * Returns a score between 0 and 1 indicating the fraction of
 * privileged values found in the outbound text.
 */
export function computeSimilarityScore(
  outboundText: string,
  privilegedValues: ReadonlySet<string>,
): { score: number; matchedFields: readonly string[] } {
  if (privilegedValues.size === 0) {
    return { score: 0, matchedFields: [] };
  }

  const lowerText = outboundText.toLowerCase();
  const digitText = digitsOnly(outboundText);
  const matched: string[] = [];

  for (const value of privilegedValues) {
    if (matchesSensitiveValue(lowerText, digitText, value)) {
      matched.push(value);
    }
  }

  return {
    score: matched.length / privilegedValues.size,
    matchedFields: matched,
  };
}

/**
 * Match a privileged value against outbound content using simple canonical
 * normalization for common sensitive data shapes.
 */
function matchesSensitiveValue(lowerText: string, digitText: string, value: string): boolean {
  const lowerValue = value.toLowerCase();
  if (lowerText.includes(lowerValue)) {
    return true;
  }

  if (looksLikeEmail(value)) {
    return lowerText.includes(lowerValue);
  }

  if (looksLikeSsn(value) || looksLikeCard(value)) {
    const normalized = digitsOnly(value);
    return normalized.length > 0 && digitText.includes(normalized);
  }

  if (looksLikePhone(value)) {
    const digits = digitsOnly(value);
    if (digits.length >= 10 && digitText.includes(digits)) {
      return true;
    }

    const last7 = digits.slice(-7);
    return last7.length >= 7 && digitText.includes(last7);
  }

  if (looksLikeFinancialIdentifier(value) || looksLikeCurrencyAmount(value)) {
    const normalized = normalizeFinancialValue(value);
    return (
      normalized.length > 0 && normalizeFinancialText(lowerText, digitText).includes(normalized)
    );
  }

  return false;
}

function digitsOnly(value: string): string {
  return value.replace(/\D/g, '');
}

function looksLikeEmail(value: string): boolean {
  return /@/.test(value) && /\./.test(value);
}

function looksLikeSsn(value: string): boolean {
  return /^\d{3}[-\s]?\d{2}[-\s]?\d{4}$/.test(value);
}

function looksLikeCard(value: string): boolean {
  return /^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$/.test(value);
}

function looksLikePhone(value: string): boolean {
  const digits = digitsOnly(value);
  return digits.length >= 7 && digits.length <= 11 && /[+().\-\s]/.test(value);
}

function looksLikeFinancialIdentifier(value: string): boolean {
  return /^(?:[A-Z]{2}\d{2}[A-Z0-9]{8,30}|[A-Z0-9-]{6,34})$/i.test(value);
}

function looksLikeCurrencyAmount(value: string): boolean {
  return /(?:\$|usd|dollars?)/i.test(value) || /^\d[\d,]*(?:\.\d{2})?$/.test(value.trim());
}

function normalizeFinancialValue(value: string): string {
  if (looksLikeCurrencyAmount(value)) {
    return value.replace(/[^0-9.]/g, '');
  }
  return value.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function normalizeFinancialText(lowerText: string, digitText: string): string {
  return `${lowerText.replace(/[^a-z0-9.]/gi, '')} ${digitText}`;
}

/**
 * Extract destination from tool arguments.
 * Looks for common destination field names.
 */
export function extractDestination(args: Record<string, unknown>): string {
  for (const field of DESTINATION_FIELDS) {
    const value = args[field];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }
  return 'unknown';
}

/**
 * Recursively serialize all string values from tool arguments
 * into a single string for PII scanning.
 */
export function serializeArguments(args: Record<string, unknown>): string {
  const parts: string[] = [];
  collectStrings(args, parts);
  return parts.join(' ');
}

/**
 * Check if a destination matches an authorized domain.
 * Entries are matched as domain suffixes (e.g., 'acme.com' matches
 * 'user@acme.com' and 'user@sub.acme.com').
 */
export function isAuthorizedDestination(
  destination: string,
  authorizedDestinations: readonly string[],
): boolean {
  if (authorizedDestinations.length === 0 || destination === 'unknown') {
    return false;
  }

  const domain = normalizeDestinationForClustering(destination);
  if (!domain) {
    return false;
  }

  return authorizedDestinations.some((auth) => {
    const authLower = auth.toLowerCase();
    return domain === authLower || domain.endsWith(`.${authLower}`);
  });
}

/**
 * Extract the domain portion from a destination (email or URL).
 */
export function normalizeDestinationForClustering(destination: string): string | null {
  // Email address
  const atIndex = destination.indexOf('@');
  if (atIndex > 0) {
    return destination.slice(atIndex + 1).toLowerCase();
  }

  // URL
  try {
    const url = new URL(destination);
    return url.hostname.toLowerCase();
  } catch {
    return destination === 'unknown' ? null : destination.toLowerCase();
  }
}

/** Recursively collect string values from a nested structure. */
function collectStrings(value: unknown, parts: string[]): void {
  if (typeof value === 'string') {
    parts.push(value);
    return;
  }

  if (value === null || value === undefined || typeof value !== 'object') {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, parts);
    }
    return;
  }

  const obj = value as Record<string, unknown>;
  for (const v of Object.values(obj)) {
    collectStrings(v, parts);
  }
}
