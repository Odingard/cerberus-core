/**
 * Tool coverage report — surface (never silently fail open on) the tools that
 * guard() is NOT protecting.
 *
 * guard() declares protection by *tool name string* in three places that are
 * independent of the actual wrapped executors:
 *   - `config.trustOverrides[].toolName`  → L1 data-source classification
 *   - `outboundTools[]`                   → L3 exfiltration coverage
 *   - `memoryOptions.memoryTools[]`       → L4 memory-contamination coverage
 *
 * Nothing cross-checks those names against the executors actually handed to
 * guard(). So a typo, a renamed tool, or a forgotten executor (e.g.
 * `outboundTools: ['sendEmial']`) means that tool's protection silently never
 * runs — the deployer believes a tool is guarded when it is not. Conversely a
 * wrapped tool with no trust classification runs at the default `unknown` trust
 * and a wrapped tool absent from `outboundTools` gets no exfiltration coverage.
 *
 * This module computes a structured, inspectable report of exactly that — so a
 * coverage gap is LOUD (warned / assertable / optionally fail-closed) instead
 * of silent.
 */

import { createHash } from 'node:crypto';

import type { MemoryToolConfig } from '../layers/l4-memory.js';
import type { CerberusConfig } from '../types/config.js';
import type { TrustLevel } from '../types/signals.js';
import { resolveTrustLevel } from '../layers/l1-classifier.js';

/** Where a tool name was declared in the guard() configuration. */
export type CoverageDeclarationSite = 'trustOverride' | 'outboundTool' | 'memoryTool';

/** Per-tool coverage across the detection layers. */
export interface ToolCoverage {
  readonly toolName: string;
  /** Whether the tool is among the executors guard() actually wraps. */
  readonly wrapped: boolean;
  /** Whether the tool has an explicit trust classification (L1). */
  readonly trustClassified: boolean;
  /** Resolved trust level (`unknown` when no override is present). */
  readonly trustLevel: TrustLevel;
  /** Whether the tool is monitored as an outbound/exfiltration sink (L3). */
  readonly outboundMonitored: boolean;
  /** Whether the tool feeds the L4 memory-contamination ledger. */
  readonly memoryTracked: boolean;
}

/** A tool name declared in config but with no matching wrapped executor. */
export interface UndeclaredCoverage {
  readonly toolName: string;
  /** Every config site that referenced this (unwrapped) tool name. */
  readonly declaredIn: readonly CoverageDeclarationSite[];
}

/** Structured coverage report for a guard() invocation. */
export interface CoverageReport {
  /** Every wrapped tool with its per-layer coverage. */
  readonly tools: readonly ToolCoverage[];
  /**
   * Tool names declared in `trustOverrides` / `outboundTools` / `memoryTools`
   * that have NO matching wrapped executor — their declared protection silently
   * never runs (typo / rename / forgotten executor). The dangerous case.
   */
  readonly declaredButUnwrapped: readonly UndeclaredCoverage[];
  /** Wrapped tools with no trust classification (running at default `unknown`). */
  readonly unclassifiedTools: readonly string[];
  /** True when at least one declared tool name has no wrapped executor. */
  readonly hasUnwrappedDeclarations: boolean;
}

/** Inputs needed to compute a coverage report. */
export interface CoverageInputs {
  readonly executorNames: readonly string[];
  readonly config: CerberusConfig;
  readonly outboundTools: readonly string[];
  readonly memoryTools: readonly MemoryToolConfig[];
}

/**
 * Compute the coverage report for a guard() configuration. Pure: no logging,
 * no throwing — callers decide how loud to be (see {@link formatCoverageWarning}
 * and the `strictCoverage` handling in guard()).
 */
export function computeCoverageReport(inputs: CoverageInputs): CoverageReport {
  const { executorNames, config, outboundTools, memoryTools } = inputs;
  const trustOverrides = config.trustOverrides ?? [];
  const wrapped = new Set(executorNames);
  const outboundSet = new Set(outboundTools);
  const trustClassifiedSet = new Set(trustOverrides.map((o) => o.toolName));
  const memorySet = new Set(memoryTools.map((t) => t.toolName));

  const tools: ToolCoverage[] = [...executorNames].sort().map((toolName) => ({
    toolName,
    wrapped: true,
    trustClassified: trustClassifiedSet.has(toolName),
    trustLevel: resolveTrustLevel(toolName, trustOverrides),
    outboundMonitored: outboundSet.has(toolName),
    memoryTracked: memorySet.has(toolName),
  }));

  // Collect every declaration site per tool name, then keep only the ones with
  // no matching wrapped executor.
  const declaredSites = new Map<string, Set<CoverageDeclarationSite>>();
  const note = (toolName: string, site: CoverageDeclarationSite): void => {
    const sites = declaredSites.get(toolName) ?? new Set<CoverageDeclarationSite>();
    sites.add(site);
    declaredSites.set(toolName, sites);
  };
  for (const o of trustOverrides) note(o.toolName, 'trustOverride');
  for (const name of outboundTools) note(name, 'outboundTool');
  for (const t of memoryTools) note(t.toolName, 'memoryTool');

  const declaredButUnwrapped: UndeclaredCoverage[] = [...declaredSites.entries()]
    .filter(([toolName]) => !wrapped.has(toolName))
    .map(([toolName, sites]) => ({
      toolName,
      declaredIn: [...sites].sort(),
    }))
    .sort((a, b) => a.toolName.localeCompare(b.toolName));

  const unclassifiedTools = tools.filter((t) => !t.trustClassified).map((t) => t.toolName);

  return {
    tools,
    declaredButUnwrapped,
    unclassifiedTools,
    hasUnwrappedDeclarations: declaredButUnwrapped.length > 0,
  };
}

/**
 * Render a human-readable warning for the unwrapped declarations in a report,
 * or `null` when there are none. Used both for the loud `console.warn` guard()
 * emits and for the `strictCoverage` thrown-error message.
 */
export function formatCoverageWarning(report: CoverageReport): string | null {
  if (!report.hasUnwrappedDeclarations) {
    return null;
  }
  const lines = report.declaredButUnwrapped.map(
    (u) => `  - "${u.toolName}" (declared in: ${u.declaredIn.join(', ')})`,
  );
  return (
    '[Cerberus Coverage] The following tools are declared in your configuration ' +
    'but have NO matching wrapped executor, so their protection never runs ' +
    '(likely a typo, a renamed tool, or a forgotten executor):\n' +
    lines.join('\n') +
    "\nPass these tools in guard()'s executors map, fix the names, or remove the " +
    'stale declarations. Set `strictCoverage: true` to make this a hard error.'
  );
}

/** Domain-separation prefix for the coverage commitment preimage. */
const COVERAGE_COMMITMENT_DOMAIN = 'cerberus-coverage-v1';

/**
 * Canonical, order-stable serialization of a {@link CoverageReport}. Every
 * collection the report exposes is already emitted in a deterministic order
 * (`tools` and `declaredButUnwrapped` sorted by name, `declaredIn` sorted), so
 * this re-projects exactly the coverage-bearing fields into a fixed shape. Two
 * reports describing the same coverage produce byte-identical output.
 */
function canonicalCoverage(report: CoverageReport): string {
  return JSON.stringify({
    v: 1,
    tools: report.tools.map((t) => ({
      toolName: t.toolName,
      wrapped: t.wrapped,
      trustClassified: t.trustClassified,
      trustLevel: t.trustLevel,
      outboundMonitored: t.outboundMonitored,
      memoryTracked: t.memoryTracked,
    })),
    declaredButUnwrapped: report.declaredButUnwrapped.map((u) => ({
      toolName: u.toolName,
      declaredIn: [...u.declaredIn],
    })),
    unclassifiedTools: [...report.unclassifiedTools],
    hasUnwrappedDeclarations: report.hasUnwrappedDeclarations,
  });
}

/**
 * Compute a tamper-evident commitment over a coverage report — a lowercase-hex
 * SHA-256 of its canonical serialization, domain-separated so it can never be
 * replayed as a hash over some other protocol's bytes.
 *
 * This is what binds coverage into the signed delegation manifest (the
 * receipt): the manifest signature covers this commitment, so the receipt
 * attests *exactly what coverage was in force* when it was signed — not just
 * the authorization decision. A holder of the receipt and the live report
 * recomputes the commitment and compares (see {@link verifyCoverageCommitment}).
 */
export function computeCoverageCommitment(report: CoverageReport): string {
  const preimage = `${COVERAGE_COMMITMENT_DOMAIN}\n${canonicalCoverage(report)}`;
  return createHash('sha256').update(preimage, 'utf8').digest('hex');
}

/**
 * Constant-shape check that a coverage report matches a bound commitment.
 * Returns true iff `computeCoverageCommitment(report) === commitment`. An empty
 * `commitment` (no coverage was bound at signing time) never matches a report.
 */
export function verifyCoverageCommitment(report: CoverageReport, commitment: string): boolean {
  if (!commitment) {
    return false;
  }
  return computeCoverageCommitment(report) === commitment;
}
