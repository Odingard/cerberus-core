/**
 * MCP Tool Description Poisoning Scanner — Sub-classifier enhancing L2.
 *
 * Scans MCP tool descriptions for hidden instructions, sensitive file
 * references, cross-tool manipulation, and obfuscation. Based on Invariant
 * Labs research (84.2% tool poisoning attack success rate).
 *
 * Two modes:
 * 1. Standalone: scanToolDescriptions() — called at registration time
 * 2. Runtime: checkToolCallPoisoning() — called per-tool-call if configured
 */

import type {
  ToolDescription,
  ToolPoisoningResult,
  ToolPoisoningSignal,
} from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';

/** Poisoning pattern with category. */
interface PoisoningPattern {
  readonly category: string;
  readonly pattern: RegExp;
}

/** Patterns for detecting tool description poisoning. */
const POISONING_PATTERNS: readonly PoisoningPattern[] = [
  // Hidden instruction tags
  { category: 'hidden_instruction', pattern: /<IMPORTANT>/gi },
  { category: 'hidden_instruction', pattern: /<SYSTEM>/gi },
  { category: 'hidden_instruction', pattern: /<ADMIN>/gi },
  { category: 'hidden_instruction', pattern: /<!--[\s\S]*?-->/g },

  // Sensitive file references
  { category: 'sensitive_file_ref', pattern: /~\/\.ssh\b/g },
  { category: 'sensitive_file_ref', pattern: /~\/\.env\b/g },
  { category: 'sensitive_file_ref', pattern: /~\/\.aws\b/g },
  { category: 'sensitive_file_ref', pattern: /\/etc\/passwd\b/g },
  { category: 'sensitive_file_ref', pattern: /~\/\.gnupg\b/g },
  {
    category: 'sensitive_file_ref',
    pattern: /(?:credentials|secrets)\.(?:json|yaml|yml|toml|env)/gi,
  },

  // Cross-tool manipulation
  { category: 'cross_tool_manipulation', pattern: /before\s+calling\b/gi },
  { category: 'cross_tool_manipulation', pattern: /instead\s+of\s+(?:using|calling)\b/gi },
  { category: 'cross_tool_manipulation', pattern: /after\s+using\b/gi },
  { category: 'cross_tool_manipulation', pattern: /when\s+.*\btool\b/gi },

  // Instruction injection in descriptions
  { category: 'instruction_injection', pattern: /\byou\s+must\b/gi },
  {
    category: 'instruction_injection',
    pattern: /\balways\b.*\b(?:send|forward|include|attach)\b/gi,
  },
  { category: 'instruction_injection', pattern: /\bnever\b.*\b(?:tell|inform|reveal|show)\b/gi },
  {
    category: 'instruction_injection',
    pattern: /\bignore\b.*\b(?:instructions|rules|policies)\b/gi,
  },
  { category: 'instruction_injection', pattern: /\boverride\b/gi },

  // Data routing commands
  { category: 'data_routing', pattern: /\bsend\s+to\b/gi },
  { category: 'data_routing', pattern: /\bforward\s+to\b/gi },
  { category: 'data_routing', pattern: /\bcopy\s+to\b/gi },
  { category: 'data_routing', pattern: /\bexfiltrate\b/gi },
  { category: 'data_routing', pattern: /\bupload\s+(?:to|all)\b/gi },

  // Zero-width character obfuscation
  { category: 'obfuscation', pattern: /\u200B|\u200C|\uFEFF|\u00AD/g },
];

/**
 * Scan a single tool description for poisoning patterns.
 * Returns matched categories.
 */
export function scanDescription(text: string): string[] {
  const matched = new Set<string>();

  for (const { category, pattern } of POISONING_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      matched.add(category);
    }
  }

  return [...matched];
}

/**
 * Determine severity based on pattern categories found.
 */
function determineSeverity(patterns: readonly string[]): 'low' | 'medium' | 'high' {
  const highRisk = ['hidden_instruction', 'data_routing', 'obfuscation'];
  const mediumRisk = ['sensitive_file_ref', 'cross_tool_manipulation'];

  if (patterns.some((p) => highRisk.includes(p))) {
    return 'high';
  }
  if (patterns.some((p) => mediumRisk.includes(p))) {
    return 'medium';
  }
  return 'low';
}

/**
 * Standalone scan — check all tool descriptions for poisoning at registration time.
 */
export function scanToolDescriptions(
  tools: readonly ToolDescription[],
): readonly ToolPoisoningResult[] {
  const results: ToolPoisoningResult[] = [];

  for (const tool of tools) {
    const patternsFound = scanDescription(tool.description);

    // Also scan parameter descriptions if present
    if (tool.parameters) {
      const paramJson = JSON.stringify(tool.parameters);
      const paramPatterns = scanDescription(paramJson);
      for (const p of paramPatterns) {
        if (!patternsFound.includes(p)) {
          patternsFound.push(p);
        }
      }
    }

    results.push({
      toolName: tool.name,
      poisoned: patternsFound.length > 0,
      patternsFound,
      severity: patternsFound.length > 0 ? determineSeverity(patternsFound) : 'low',
    });
  }

  return results;
}

/**
 * Runtime scan — check current tool call against configured tool descriptions.
 * Emits L2 signal if the tool being called has a poisoned description.
 */
export function checkToolCallPoisoning(
  ctx: ToolCallContext,
  toolDescriptions: readonly ToolDescription[],
  _session: DetectionSession,
): ToolPoisoningSignal | null {
  const toolDesc = toolDescriptions.find((t) => t.name === ctx.toolName);
  if (!toolDesc) {
    return null;
  }

  const patternsFound = scanDescription(toolDesc.description);
  if (patternsFound.length === 0) {
    return null;
  }

  return {
    layer: 'L2',
    signal: 'TOOL_POISONING_DETECTED',
    turnId: ctx.turnId,
    toolName: ctx.toolName,
    patternsFound,
    severity: determineSeverity(patternsFound),
    timestamp: ctx.timestamp,
  };
}
