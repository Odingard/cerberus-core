/**
 * Tests for the tool coverage report (src/engine/coverage.ts) and its wiring
 * into guard(): a tool declared in config with no matching wrapped executor is
 * surfaced loudly (warn by default, throw under strictCoverage) and is never a
 * silent fail-open.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  computeCoverageReport,
  formatCoverageWarning,
  computeCoverageCommitment,
  verifyCoverageCommitment,
} from '../../src/engine/coverage.js';
import { guard } from '../../src/middleware/wrap.js';
import type { CerberusConfig } from '../../src/types/config.js';

// ── computeCoverageReport (pure) ────────────────────────────────────

describe('computeCoverageReport', () => {
  it('reports per-tool L1/L3/L4 coverage for wrapped tools', () => {
    const report = computeCoverageReport({
      executorNames: ['readDb', 'sendEmail', 'writeMemory'],
      config: {
        trustOverrides: [
          { toolName: 'readDb', trustLevel: 'trusted' },
          { toolName: 'sendEmail', trustLevel: 'untrusted' },
        ],
      },
      outboundTools: ['sendEmail'],
      memoryTools: [{ toolName: 'writeMemory', operation: 'write' }],
    });

    const byName = Object.fromEntries(report.tools.map((t) => [t.toolName, t]));
    expect(byName.readDb).toMatchObject({
      trustClassified: true,
      trustLevel: 'trusted',
      outboundMonitored: false,
      memoryTracked: false,
    });
    expect(byName.sendEmail).toMatchObject({
      trustLevel: 'untrusted',
      outboundMonitored: true,
    });
    expect(byName.writeMemory).toMatchObject({
      trustClassified: false,
      trustLevel: 'unknown',
      memoryTracked: true,
    });
    expect(report.hasUnwrappedDeclarations).toBe(false);
  });

  it('flags a tool declared in config but not wrapped (the typo case)', () => {
    const report = computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      // Typo: declared 'sendEmial' as outbound, but the executor is 'sendEmail'.
      outboundTools: ['sendEmial'],
      memoryTools: [],
    });

    expect(report.hasUnwrappedDeclarations).toBe(true);
    expect(report.declaredButUnwrapped).toEqual([
      { toolName: 'sendEmial', declaredIn: ['outboundTool'] },
    ]);
  });

  it('aggregates every declaration site for an unwrapped tool name', () => {
    const report = computeCoverageReport({
      executorNames: [],
      config: { trustOverrides: [{ toolName: 'ghost', trustLevel: 'trusted' }] },
      outboundTools: ['ghost'],
      memoryTools: [{ toolName: 'ghost', operation: 'read' }],
    });

    expect(report.declaredButUnwrapped).toEqual([
      { toolName: 'ghost', declaredIn: ['memoryTool', 'outboundTool', 'trustOverride'] },
    ]);
  });

  it('lists wrapped tools with no trust classification', () => {
    const report = computeCoverageReport({
      executorNames: ['classified', 'unclassified'],
      config: { trustOverrides: [{ toolName: 'classified', trustLevel: 'trusted' }] },
      outboundTools: [],
      memoryTools: [],
    });

    expect(report.unclassifiedTools).toEqual(['unclassified']);
  });
});

describe('formatCoverageWarning', () => {
  it('returns null when there are no unwrapped declarations', () => {
    const report = computeCoverageReport({
      executorNames: ['a'],
      config: { trustOverrides: [{ toolName: 'a', trustLevel: 'trusted' }] },
      outboundTools: [],
      memoryTools: [],
    });
    expect(formatCoverageWarning(report)).toBeNull();
  });

  it('names the unwrapped tools and their declaration sites', () => {
    const report = computeCoverageReport({
      executorNames: [],
      config: { trustOverrides: [] },
      outboundTools: ['sendEmial'],
      memoryTools: [],
    });
    const warning = formatCoverageWarning(report);
    expect(warning).toContain('sendEmial');
    expect(warning).toContain('outboundTool');
    expect(warning).toContain('strictCoverage');
  });
});

// ── guard() wiring ──────────────────────────────────────────────────

const WRAPPED = (): Record<string, () => Promise<string>> => ({
  sendEmail: () => Promise.resolve('sent'),
});

describe('guard() coverage wiring', () => {
  it('exposes the coverage report on the result', () => {
    const result = guard(WRAPPED(), { trustOverrides: [] }, ['sendEmail']);
    expect(result.coverage.tools.map((t) => t.toolName)).toEqual(['sendEmail']);
    expect(result.coverage.hasUnwrappedDeclarations).toBe(false);
  });

  it('warns loudly (does not throw) on an unwrapped declaration by default', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const result = guard(WRAPPED(), { trustOverrides: [] }, ['sendEmial']);

    expect(result.coverage.hasUnwrappedDeclarations).toBe(true);
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0][0]).toContain('sendEmial');
    warn.mockRestore();
  });

  it('throws on an unwrapped declaration when strictCoverage is true', () => {
    const config: CerberusConfig = { strictCoverage: true, trustOverrides: [] };
    expect(() => guard(WRAPPED(), config, ['sendEmial'])).toThrow(/sendEmial/);
  });

  it('does not warn when every declaration maps to a wrapped executor', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    guard(WRAPPED(), { trustOverrides: [{ toolName: 'sendEmail', trustLevel: 'untrusted' }] }, [
      'sendEmail',
    ]);
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});

// ── computeCoverageCommitment / verifyCoverageCommitment ────────────

describe('computeCoverageCommitment', () => {
  const REPORT = () =>
    computeCoverageReport({
      executorNames: ['readDb', 'sendEmail', 'writeMemory'],
      config: {
        trustOverrides: [
          { toolName: 'readDb', trustLevel: 'trusted' },
          { toolName: 'sendEmail', trustLevel: 'untrusted' },
        ],
      },
      outboundTools: ['sendEmail'],
      memoryTools: [{ toolName: 'writeMemory', operation: 'write' }],
    });

  it('produces a lowercase-hex SHA-256 digest', () => {
    expect(computeCoverageCommitment(REPORT())).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for the same coverage', () => {
    expect(computeCoverageCommitment(REPORT())).toBe(computeCoverageCommitment(REPORT()));
  });

  it('is invariant to executor declaration order (canonicalized)', () => {
    const a = computeCoverageReport({
      executorNames: ['readDb', 'sendEmail', 'writeMemory'],
      config: { trustOverrides: [{ toolName: 'sendEmail', trustLevel: 'untrusted' }] },
      outboundTools: ['sendEmail'],
      memoryTools: [{ toolName: 'writeMemory', operation: 'write' }],
    });
    const b = computeCoverageReport({
      executorNames: ['writeMemory', 'sendEmail', 'readDb'],
      config: { trustOverrides: [{ toolName: 'sendEmail', trustLevel: 'untrusted' }] },
      outboundTools: ['sendEmail'],
      memoryTools: [{ toolName: 'writeMemory', operation: 'write' }],
    });
    expect(computeCoverageCommitment(a)).toBe(computeCoverageCommitment(b));
  });

  it('changes when the trust classification of a tool changes', () => {
    const trusted = computeCoverageReport({
      executorNames: ['readDb'],
      config: { trustOverrides: [{ toolName: 'readDb', trustLevel: 'trusted' }] },
      outboundTools: [],
      memoryTools: [],
    });
    const untrusted = computeCoverageReport({
      executorNames: ['readDb'],
      config: { trustOverrides: [{ toolName: 'readDb', trustLevel: 'untrusted' }] },
      outboundTools: [],
      memoryTools: [],
    });
    expect(computeCoverageCommitment(trusted)).not.toBe(computeCoverageCommitment(untrusted));
  });

  it('changes when an outbound (L3) coverage gap appears', () => {
    const covered = computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      outboundTools: ['sendEmail'],
      memoryTools: [],
    });
    const uncovered = computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      outboundTools: [],
      memoryTools: [],
    });
    expect(computeCoverageCommitment(covered)).not.toBe(computeCoverageCommitment(uncovered));
  });

  it('changes when a declared-but-unwrapped tool (the typo case) appears', () => {
    const clean = computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      outboundTools: ['sendEmail'],
      memoryTools: [],
    });
    const typo = computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      outboundTools: ['sendEmail', 'sendEmial'],
      memoryTools: [],
    });
    expect(computeCoverageCommitment(clean)).not.toBe(computeCoverageCommitment(typo));
  });
});

describe('verifyCoverageCommitment', () => {
  const REPORT = () =>
    computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      outboundTools: ['sendEmail'],
      memoryTools: [],
    });

  it('accepts a report that matches its own commitment', () => {
    const report = REPORT();
    expect(verifyCoverageCommitment(report, computeCoverageCommitment(report))).toBe(true);
  });

  it('rejects a report whose coverage has diverged from the commitment', () => {
    const signed = computeCoverageCommitment(REPORT());
    const drifted = computeCoverageReport({
      executorNames: ['sendEmail'],
      config: { trustOverrides: [] },
      // Coverage shrank: the outbound monitoring was dropped after signing.
      outboundTools: [],
      memoryTools: [],
    });
    expect(verifyCoverageCommitment(drifted, signed)).toBe(false);
  });

  it('rejects an empty commitment (no coverage was bound)', () => {
    expect(verifyCoverageCommitment(REPORT(), '')).toBe(false);
  });
});
