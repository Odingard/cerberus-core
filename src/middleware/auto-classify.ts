/**
 * Zero-config tool auto-classification (spike).
 *
 * The hard part of wiring Cerberus is not *coverage* (which tools it sees) —
 * that can be automatic — it is *classification*: labeling each tool as a
 * privileged data source (arms L1), untrusted-content ingestion (arms L2), or
 * an outbound channel (the L3 block surface). This module infers a conservative
 * first guess for each tool from its NAME (and optional description) so a
 * developer starts from a reviewable draft instead of a blank config.
 *
 * These are heuristics, not ground truth. They are meant to be reviewed and
 * corrected — which is exactly why {@link autoGuard} defaults to observe-only
 * `log` mode: a wrong guess never blocks production before a human has seen the
 * inferred table.
 */

import type { TrustOverride } from '../types/config.js';

/** The inferred security role of a tool. */
export type ToolRole = 'data-source' | 'external-content' | 'outbound' | 'unclassified';

/** One tool's inferred classification. */
export interface ToolClassification {
  readonly toolName: string;
  /** Primary role label (outbound takes precedence when a tool both reads and sends). */
  readonly role: ToolRole;
  /** Trust level to feed `trustOverrides`, when one could be inferred. */
  readonly trustLevel?: 'trusted' | 'untrusted';
  /** Whether the tool is treated as an outbound (L3-blockable) channel. */
  readonly outbound: boolean;
  /** Human-readable reason (which signal decided the label). */
  readonly reason: string;
  /**
   * Low-confidence guess (no keyword matched — defaulted). Surfaced so a
   * reviewer knows which rows most need a human decision.
   */
  readonly lowConfidence: boolean;
}

interface Rule {
  readonly keyword: string;
  readonly re: RegExp;
}

// Verbs/nouns that indicate DATA LEAVING the system → outbound (L3 surface).
const OUTBOUND_RULES: readonly Rule[] = [
  'send', 'email', 'mail', 'post', 'publish', 'upload', 'webhook', 'notify',
  'sms', 'slack', 'dispatch', 'forward', 'transmit', 'export', 'push',
  'submit', 'tweet', 'deliver', 'wire', 'remit', 'sync',
].map((k) => ({ keyword: k, re: new RegExp(`(^|[^a-z])${k}`, 'i') }));

// Ingestion of EXTERNAL / attacker-influenceable content → untrusted (L2).
const UNTRUSTED_RULES: readonly Rule[] = [
  'fetch', 'http', 'https', 'url', 'web', 'browse', 'scrape', 'crawl',
  'download', 'search', 'rss', 'feed', 'external', 'internet', 'page',
  'request', 'webhookin',
].map((k) => ({ keyword: k, re: new RegExp(`(^|[^a-z])${k}`, 'i') }));

// Reads of PRIVILEGED / INTERNAL data → trusted data source (L1).
const TRUSTED_RULES: readonly Rule[] = [
  'read', 'query', 'db', 'database', 'record', 'file', 'lookup', 'load',
  'list', 'find', 'select', 'retrieve', 'customer', 'account', 'user',
  'crm', 'sql', 'table', 'document', 'secret', 'credential', 'vault',
  'profile', 'ledger', 'inventory',
].map((k) => ({ keyword: k, re: new RegExp(`(^|[^a-z])${k}`, 'i') }));

function firstMatch(haystack: string, rules: readonly Rule[]): string | undefined {
  for (const rule of rules) {
    if (rule.re.test(haystack)) return rule.keyword;
  }
  return undefined;
}

/** Normalize a tool name + description into one searchable, camelCase-split string. */
function normalize(toolName: string, description?: string): string {
  const split = toolName.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_\-.]/g, ' ');
  return `${split} ${description ?? ''}`.toLowerCase();
}

/**
 * Infer a conservative classification for a single tool from its name and
 * optional description.
 *
 * Precedence: outbound is decided first and independently (a tool that sends
 * data is an L3 surface regardless of what it reads). Trust level then prefers
 * `untrusted` (external content) over `trusted` (internal data) when both hit,
 * because an untrusted-content read is the more dangerous default to miss.
 */
export function classifyTool(toolName: string, description?: string): ToolClassification {
  const hay = normalize(toolName, description);

  const outboundKeyword = firstMatch(hay, OUTBOUND_RULES);
  const untrustedKeyword = firstMatch(hay, UNTRUSTED_RULES);
  const trustedKeyword = firstMatch(hay, TRUSTED_RULES);

  const outbound = outboundKeyword !== undefined;

  let trustLevel: 'trusted' | 'untrusted' | undefined;
  let trustReason = '';
  if (untrustedKeyword !== undefined) {
    trustLevel = 'untrusted';
    trustReason = `ingests external content (matched "${untrustedKeyword}")`;
  } else if (trustedKeyword !== undefined) {
    trustLevel = 'trusted';
    trustReason = `reads privileged/internal data (matched "${trustedKeyword}")`;
  }

  let role: ToolRole;
  let reason: string;
  let lowConfidence = false;

  if (outbound) {
    role = 'outbound';
    reason = `outbound channel (matched "${outboundKeyword ?? ''}")`;
    if (trustReason) reason += `; also ${trustReason}`;
  } else if (trustLevel === 'untrusted') {
    role = 'external-content';
    reason = trustReason;
  } else if (trustLevel === 'trusted') {
    role = 'data-source';
    reason = trustReason;
  } else {
    // Nothing matched. Default conservatively to trusted (privileged data
    // source) — the safest miss in observe mode, since L1 alone never blocks
    // and it makes the tool visible to the correlation engine for review.
    role = 'unclassified';
    trustLevel = 'trusted';
    reason = 'no keyword matched — defaulted to trusted (review recommended)';
    lowConfidence = true;
  }

  return {
    toolName,
    role,
    ...(trustLevel !== undefined ? { trustLevel } : {}),
    outbound,
    reason,
    lowConfidence,
  };
}

/** Classify every tool name (with optional descriptions keyed by tool name). */
export function classifyTools(
  toolNames: readonly string[],
  descriptions?: Readonly<Record<string, string>>,
): ToolClassification[] {
  return toolNames.map((name) => classifyTool(name, descriptions?.[name]));
}

/** Project inferred classifications into the `trustOverrides` config shape. */
export function toTrustOverrides(
  classifications: readonly ToolClassification[],
): TrustOverride[] {
  const overrides: TrustOverride[] = [];
  for (const c of classifications) {
    if (c.trustLevel !== undefined) {
      overrides.push({ toolName: c.toolName, trustLevel: c.trustLevel });
    }
  }
  return overrides;
}

/** Project inferred classifications into the outbound-tools list. */
export function toOutboundTools(classifications: readonly ToolClassification[]): string[] {
  return classifications.filter((c) => c.outbound).map((c) => c.toolName);
}

/** Render the classification set as an aligned, human-readable table. */
export function formatClassificationTable(
  classifications: readonly ToolClassification[],
): string {
  const header = ['TOOL', 'ROLE', 'TRUST', 'OUTBOUND', 'WHY'];
  const rows = classifications.map((c) => [
    c.toolName,
    c.role,
    c.trustLevel ?? '—',
    c.outbound ? 'yes' : 'no',
    c.reason,
  ]);
  const widths = header.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => r[i].length)),
  );
  const pad = (cells: string[]): string =>
    cells.map((cell, i) => cell.padEnd(widths[i])).join('  ');
  const sep = widths.map((w) => '─'.repeat(w)).join('  ');
  const lowCount = classifications.filter((c) => c.lowConfidence).length;
  const lines = [
    '[Cerberus] Auto-classification (observe-only — review before enforcing):',
    pad(header),
    sep,
    ...rows.map(pad),
  ];
  if (lowCount > 0) {
    lines.push(
      `\n⚠ ${lowCount} tool(s) could not be classified from their name and were ` +
        `defaulted. Review the rows marked "review recommended" and correct them ` +
        `via overrides before switching alertMode to 'interrupt'.`,
    );
  }
  return lines.join('\n');
}
