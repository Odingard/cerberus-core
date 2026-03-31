/**
 * Context Window Manager — Handles large RAG payloads.
 *
 * When content exceeds the configured context window limit, segments are
 * scored by entropy, structural patterns, and position. High-priority
 * regions (system prompts, tool schemas, tool results) are always inspected.
 * Runs BEFORE the L1/L2/L3 detection pipeline in the interceptor.
 */

import type { CerberusConfig, AlwaysInspectRegions } from '../types/config.js';
import type { ContextOverflowSignal, TurnId } from '../types/signals.js';

/** Default context window limit in tokens. */
const DEFAULT_CONTEXT_WINDOW_LIMIT = 32000;

/** Default segment size in approximate tokens. */
const SEGMENT_SIZE = 512;

/** A scored segment of content. */
export interface ContentSegment {
  readonly text: string;
  readonly index: number;
  readonly score: number;
  readonly region: 'system-prompt' | 'tool-schema' | 'tool-result' | 'general';
  readonly inspected: boolean;
}

/** Result of context window analysis. */
export interface ContextWindowResult {
  /** Whether the content exceeded the configured limit. */
  readonly overflow: boolean;
  /** Total estimated token count. */
  readonly totalTokens: number;
  /** The configured limit. */
  readonly limit: number;
  /** Segments that were inspected. */
  readonly inspectedSegments: readonly ContentSegment[];
  /** Segments that were dropped (not inspected). */
  readonly droppedSegments: readonly ContentSegment[];
  /** Content to pass to the detection pipeline (inspected segments joined). */
  readonly inspectedContent: string;
  /** Overflow signal if limit was exceeded. */
  readonly signal?: ContextOverflowSignal;
  /** Whether detection should be blocked entirely (when overflowAction is 'block'). */
  readonly blocked: boolean;
}

/**
 * Estimate token count from text.
 * Uses a simple ~4 chars per token heuristic (GPT-style approximation).
 */
export function estimateTokens(text: string): number {
  if (text.length === 0) return 0;
  return Math.ceil(text.length / 4);
}

/**
 * Compute Shannon entropy of a text segment.
 * Higher entropy may indicate encoded/compressed/obfuscated content.
 */
export function computeEntropy(text: string): number {
  if (text.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of text) {
    freq.set(char, (freq.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const len = text.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/** Structural patterns that increase a segment's priority score. */
const STRUCTURAL_PATTERNS: readonly { pattern: RegExp; weight: number }[] = [
  { pattern: /https?:\/\/\S+/g, weight: 0.3 }, // URLs
  { pattern: /\S+@\S+\.\S+/g, weight: 0.3 }, // Email addresses
  { pattern: /<(?:SYSTEM|IMPORTANT|ADMIN|OVERRIDE)/gi, weight: 0.5 }, // Authority tags
  { pattern: /ignore\s+(?:previous|all|prior)/gi, weight: 0.5 }, // Injection patterns
  { pattern: /(?:api[_-]?key|password|secret|token)\s*[:=]/gi, weight: 0.4 }, // Credentials
  { pattern: /base64|atob|btoa|decode/gi, weight: 0.3 }, // Encoding markers
  { pattern: /\b(?:ssn|social.security|credit.card)\b/gi, weight: 0.4 }, // PII markers
];

/**
 * Score a text segment by entropy, structural patterns, and position.
 *
 * Returns a score in [0, 1] where higher means more important to inspect.
 */
export function scoreSegment(text: string, index: number, totalSegments: number): number {
  // Entropy component (normalized to 0-1, typical text entropy is 3-5 bits)
  const entropy = computeEntropy(text);
  const entropyScore = Math.min(entropy / 6, 1) * 0.3;

  // Structural pattern component
  let structuralScore = 0;
  for (const { pattern, weight } of STRUCTURAL_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      structuralScore += weight;
    }
  }
  structuralScore = Math.min(structuralScore, 1) * 0.4;

  // Position component: first and last segments are higher priority
  let positionScore = 0;
  if (totalSegments > 1) {
    const normalizedPos = index / (totalSegments - 1);
    // U-shaped: high at start and end, lower in middle
    positionScore =
      1 - 4 * (normalizedPos - 0.5) ** 2 > 0.5
        ? 0.2
        : 0.3 * (1 - Math.min(normalizedPos, 1 - normalizedPos) * 2);
  } else {
    positionScore = 0.3;
  }

  return Math.min(entropyScore + structuralScore + positionScore, 1);
}

/**
 * Classify a text segment into a region based on content heuristics.
 */
export function classifyRegion(
  text: string,
): 'system-prompt' | 'tool-schema' | 'tool-result' | 'general' {
  const lower = text.toLowerCase();

  if (
    lower.includes('system:') ||
    lower.includes('system prompt') ||
    lower.includes('<system>') ||
    lower.includes('you are a')
  ) {
    return 'system-prompt';
  }

  if (
    lower.includes('"parameters"') ||
    lower.includes('"type": "object"') ||
    lower.includes('"properties"') ||
    lower.includes('tool_schema') ||
    lower.includes('function_definition')
  ) {
    return 'tool-schema';
  }

  if (
    lower.includes('tool_result') ||
    lower.includes('tool result') ||
    lower.includes('function_result') ||
    lower.includes('observation:')
  ) {
    return 'tool-result';
  }

  return 'general';
}

/**
 * Determine whether a region should always be inspected.
 */
function shouldAlwaysInspect(
  region: 'system-prompt' | 'tool-schema' | 'tool-result' | 'general',
  config: AlwaysInspectRegions,
): boolean {
  switch (region) {
    case 'system-prompt':
      return config.systemPrompts !== false;
    case 'tool-schema':
      return config.toolSchemas !== false;
    case 'tool-result':
      return config.toolResults !== false;
    case 'general':
      return false;
  }
}

/**
 * Split text into segments of approximately SEGMENT_SIZE tokens each.
 */
export function splitIntoSegments(text: string): readonly string[] {
  const charsPerSegment = SEGMENT_SIZE * 4; // ~4 chars per token
  const segments: string[] = [];

  for (let i = 0; i < text.length; i += charsPerSegment) {
    segments.push(text.slice(i, i + charsPerSegment));
  }

  if (segments.length === 0) {
    segments.push('');
  }

  return segments;
}

/**
 * Analyze content against the context window limit.
 *
 * When content exceeds the limit:
 * 1. Split into ~512-token segments
 * 2. Score each segment by entropy + structural patterns + position
 * 3. Always-inspect regions are kept regardless of limit
 * 4. Remaining budget is filled by highest-scoring segments
 * 5. Emits CONTEXT_OVERFLOW signal with inspection metadata
 */
export function analyzeContextWindow(
  content: string,
  turnId: TurnId,
  config: CerberusConfig,
): ContextWindowResult {
  const limit = config.contextWindowLimit ?? DEFAULT_CONTEXT_WINDOW_LIMIT;
  const overflowAction = config.overflowAction ?? 'partial-scan';
  const alwaysInspect: AlwaysInspectRegions = config.alwaysInspectRegions ?? {};
  const totalTokens = estimateTokens(content);

  // No overflow — inspect everything
  if (totalTokens <= limit) {
    const rawSegments = splitIntoSegments(content);
    const segments: ContentSegment[] = rawSegments.map((text, index) => ({
      text,
      index,
      score: scoreSegment(text, index, rawSegments.length),
      region: classifyRegion(text),
      inspected: true,
    }));

    return {
      overflow: false,
      totalTokens,
      limit,
      inspectedSegments: segments,
      droppedSegments: [],
      inspectedContent: content,
      blocked: false,
    };
  }

  // Overflow detected — segment and prioritize
  const rawSegments = splitIntoSegments(content);
  const scoredSegments: ContentSegment[] = rawSegments.map((text, index) => ({
    text,
    index,
    score: scoreSegment(text, index, rawSegments.length),
    region: classifyRegion(text),
    inspected: false, // will be updated below
  }));

  // Block mode — emit signal and block detection
  if (overflowAction === 'block') {
    const signal: ContextOverflowSignal = {
      layer: 'L1',
      signal: 'CONTEXT_OVERFLOW',
      turnId,
      totalTokens,
      limit,
      segmentsInspected: 0,
      segmentsDropped: scoredSegments.length,
      overflowAction: 'block',
      timestamp: Date.now(),
    };

    return {
      overflow: true,
      totalTokens,
      limit,
      inspectedSegments: [],
      droppedSegments: scoredSegments,
      inspectedContent: '',
      signal,
      blocked: true,
    };
  }

  // Partial-scan mode — prioritize segments
  const alwaysInspectIndices = new Set<number>();
  let alwaysInspectTokens = 0;

  for (let i = 0; i < scoredSegments.length; i++) {
    const seg = scoredSegments[i];
    if (shouldAlwaysInspect(seg.region, alwaysInspect)) {
      alwaysInspectIndices.add(i);
      alwaysInspectTokens += estimateTokens(seg.text);
    }
  }

  // Remaining budget for general segments
  const remainingBudget = Math.max(0, limit - alwaysInspectTokens);

  // Sort non-always-inspect segments by score descending
  const generalIndices = scoredSegments
    .map((seg, i) => ({ index: i, score: seg.score, tokens: estimateTokens(seg.text) }))
    .filter((entry) => !alwaysInspectIndices.has(entry.index))
    .sort((a, b) => b.score - a.score);

  // Fill remaining budget with highest-scoring segments
  let usedBudget = 0;
  const selectedGeneralIndices = new Set<number>();
  for (const entry of generalIndices) {
    if (usedBudget + entry.tokens <= remainingBudget) {
      selectedGeneralIndices.add(entry.index);
      usedBudget += entry.tokens;
    }
  }

  // Build final segment lists
  const inspectedSegments: ContentSegment[] = [];
  const droppedSegments: ContentSegment[] = [];

  for (let i = 0; i < scoredSegments.length; i++) {
    const seg = scoredSegments[i];
    const inspected = alwaysInspectIndices.has(i) || selectedGeneralIndices.has(i);
    const finalSeg: ContentSegment = { ...seg, inspected };

    if (inspected) {
      inspectedSegments.push(finalSeg);
    } else {
      droppedSegments.push(finalSeg);
    }
  }

  // Build inspected content (in original order)
  const inspectedContent = inspectedSegments
    .sort((a, b) => a.index - b.index)
    .map((s) => s.text)
    .join('');

  const signal: ContextOverflowSignal = {
    layer: 'L1',
    signal: 'CONTEXT_OVERFLOW',
    turnId,
    totalTokens,
    limit,
    segmentsInspected: inspectedSegments.length,
    segmentsDropped: droppedSegments.length,
    overflowAction: 'partial-scan',
    timestamp: Date.now(),
  };

  return {
    overflow: true,
    totalTokens,
    limit,
    inspectedSegments,
    droppedSegments,
    inspectedContent,
    signal,
    blocked: false,
  };
}
