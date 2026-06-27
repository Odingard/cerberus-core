/**
 * Prompt Injection Heuristic Scanner — Sub-classifier enhancing L2.
 *
 * Scans untrusted tool results for prompt injection patterns.
 * Content-level complement to L2's trust-level tagging.
 */

import type { InjectionPatternsSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';

/** Injection pattern with category and weight. */
interface InjectionPattern {
  readonly category: string;
  readonly pattern: RegExp;
  readonly weight: number;
}

/** Weighted injection heuristic patterns. */
const INJECTION_PATTERNS: readonly InjectionPattern[] = [
  // Role override
  {
    category: 'role_override',
    pattern: /ignore\s+(?:previous|all|prior|above)\s+instructions/gi,
    weight: 0.9,
  },
  { category: 'role_override', pattern: /you\s+are\s+now\b/gi, weight: 0.7 },
  { category: 'role_override', pattern: /new\s+role\s*:/gi, weight: 0.8 },
  { category: 'role_override', pattern: /system\s+prompt\s*:/gi, weight: 0.8 },
  { category: 'role_override', pattern: /forget\s+(?:everything|all|your)\b/gi, weight: 0.7 },

  // Authority spoofing
  { category: 'authority_spoofing', pattern: /<IMPORTANT>/gi, weight: 0.9 },
  { category: 'authority_spoofing', pattern: /<SYSTEM>/gi, weight: 0.8 },
  { category: 'authority_spoofing', pattern: /<ADMIN>/gi, weight: 0.8 },
  { category: 'authority_spoofing', pattern: /\[OVERRIDE\]/gi, weight: 0.9 },
  { category: 'authority_spoofing', pattern: /\[SYSTEM\s*(?:MESSAGE|UPDATE)\]/gi, weight: 0.8 },
  { category: 'authority_spoofing', pattern: /ADMIN\s*(?:NOTICE|OVERRIDE)\s*:/gi, weight: 0.7 },

  // Instruction injection
  {
    category: 'instruction_injection',
    pattern: /instead,?\s+(?:do|send|forward|email|report|output)/gi,
    weight: 0.8,
  },
  {
    category: 'instruction_injection',
    pattern: /your\s+(?:new\s+|real\s+)?task\s+is/gi,
    weight: 0.9,
  },
  {
    category: 'instruction_injection',
    pattern: /(?:actually|really),?\s+(?:you\s+(?:should|must|need\s+to))/gi,
    weight: 0.7,
  },
  {
    category: 'instruction_injection',
    pattern: /do\s+not\s+follow\s+(?:the|your)\s+(?:original|previous)/gi,
    weight: 0.9,
  },

  // Exfiltration commands
  {
    category: 'exfiltration_command',
    pattern:
      /send\s+(?:all\s+(?:the\s+)?(?:\w+\s+)?|the\s+|this\s+)?(?:data|info|information)\s+to/gi,
    weight: 0.9,
  },
  { category: 'exfiltration_command', pattern: /forward\s+.*\s+to\s+\S+@/gi, weight: 0.8 },
  { category: 'exfiltration_command', pattern: /exfiltrate|ex-filtrate/gi, weight: 1.0 },
  {
    category: 'exfiltration_command',
    pattern: /(?:send|post|upload)\s+(?:it|them|everything)\s+to\s+https?:\/\//gi,
    weight: 0.8,
  },

  // Encoded payload markers
  {
    category: 'encoded_payload',
    pattern: /(?:decode|execute|run|eval)\s+(?:the\s+)?(?:following|this)\s+(?:base64|encoded)/gi,
    weight: 0.8,
  },
  { category: 'encoded_payload', pattern: /atob\s*\(|btoa\s*\(/g, weight: 0.6 },
];

/**
 * Scan text for injection patterns. Returns matched categories with total confidence.
 */
export function scanForInjection(text: string): { patternsFound: string[]; confidence: number } {
  const matchedCategories = new Set<string>();
  let weightSum = 0;
  let maxPossibleWeight = 0;

  // Deduplicate by category — use highest weight per category
  const categoryMaxWeights = new Map<string, number>();
  for (const { category, weight } of INJECTION_PATTERNS) {
    const current = categoryMaxWeights.get(category) ?? 0;
    if (weight > current) {
      categoryMaxWeights.set(category, weight);
    }
  }

  for (const [, w] of categoryMaxWeights) {
    maxPossibleWeight += w;
  }

  for (const { category, pattern, weight } of INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      if (!matchedCategories.has(category)) {
        matchedCategories.add(category);
        weightSum += weight;
      }
    }
  }

  const confidence = maxPossibleWeight > 0 ? Math.min(weightSum / maxPossibleWeight, 1) : 0;
  return { patternsFound: [...matchedCategories], confidence };
}

/**
 * Scan untrusted tool result for injection patterns.
 * Only runs when the tool is untrusted (same gate as L2).
 * Updates session.injectionPatternsFound.
 */
export function scanInjectionInResult(
  ctx: ToolCallContext,
  session: DetectionSession,
  isUntrusted: boolean,
): InjectionPatternsSignal | null {
  if (!isUntrusted) {
    return null;
  }

  const { patternsFound, confidence } = scanForInjection(ctx.toolResult);
  if (patternsFound.length === 0) {
    return null;
  }

  for (const pattern of patternsFound) {
    session.injectionPatternsFound.add(pattern);
  }

  return {
    layer: 'L2',
    signal: 'INJECTION_PATTERNS_DETECTED',
    turnId: ctx.turnId,
    patternsFound,
    confidence,
    timestamp: ctx.timestamp,
  };
}
