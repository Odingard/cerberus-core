/**
 * Tests for the zero-config spike: tool auto-classification
 * (src/middleware/auto-classify.ts) and the autoGuard() entry point
 * (src/middleware/auto-guard.ts).
 *
 * The contract under test: coverage is automatic (every executor wrapped),
 * classification is inferred conservatively from names, and enforcement
 * defaults to observe-only `log` mode so a wrong guess never blocks.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  classifyTool,
  classifyTools,
  toTrustOverrides,
  toOutboundTools,
  formatClassificationTable,
} from '../../src/middleware/auto-classify.js';
import { autoGuard } from '../../src/middleware/auto-guard.js';

describe('classifyTool', () => {
  it('classifies an outbound sender as outbound (L3 surface)', () => {
    const c = classifyTool('sendEmail');
    expect(c.role).toBe('outbound');
    expect(c.outbound).toBe(true);
    expect(c.lowConfidence).toBe(false);
  });

  it('classifies external-content fetchers as untrusted (L2)', () => {
    const c = classifyTool('fetchWebPage');
    expect(c.role).toBe('external-content');
    expect(c.trustLevel).toBe('untrusted');
    expect(c.outbound).toBe(false);
  });

  it('classifies internal data readers as trusted (L1)', () => {
    const c = classifyTool('readCustomerDatabase');
    expect(c.role).toBe('data-source');
    expect(c.trustLevel).toBe('trusted');
    expect(c.outbound).toBe(false);
  });

  it('marks outbound even when the tool also reads data', () => {
    const c = classifyTool('exportCustomerRecords');
    expect(c.outbound).toBe(true);
    expect(c.role).toBe('outbound');
  });

  it('prefers untrusted over trusted when both keywords hit', () => {
    const c = classifyTool('searchCustomerRecords');
    expect(c.trustLevel).toBe('untrusted');
  });

  it('defaults an unrecognizable name to trusted + low confidence', () => {
    const c = classifyTool('frobnicate');
    expect(c.role).toBe('unclassified');
    expect(c.trustLevel).toBe('trusted');
    expect(c.lowConfidence).toBe(true);
  });

  it('uses the description to sharpen inference', () => {
    const c = classifyTool('handle', 'posts the payload to an external webhook');
    expect(c.outbound).toBe(true);
  });
});

describe('projection helpers', () => {
  const classifications = classifyTools(['readDb', 'fetchUrl', 'sendEmail']);

  it('projects trust overrides for classified tools', () => {
    const overrides = toTrustOverrides(classifications);
    const byName = Object.fromEntries(overrides.map((o) => [o.toolName, o.trustLevel]));
    expect(byName.readDb).toBe('trusted');
    expect(byName.fetchUrl).toBe('untrusted');
  });

  it('projects the outbound list', () => {
    expect(toOutboundTools(classifications)).toEqual(['sendEmail']);
  });

  it('renders a table containing every tool', () => {
    const table = formatClassificationTable(classifications);
    expect(table).toContain('readDb');
    expect(table).toContain('fetchUrl');
    expect(table).toContain('sendEmail');
  });
});

describe('autoGuard', () => {
  const executors = {
    readDb: (): Promise<string> => Promise.resolve('ok'),
    fetchUrl: (): Promise<string> => Promise.resolve('ok'),
    sendEmail: (): Promise<string> => Promise.resolve('ok'),
  };

  it('wraps every executor (automatic coverage)', () => {
    const result = autoGuard(executors, { print: false });
    expect(Object.keys(result.executors).sort()).toEqual(
      ['fetchUrl', 'readDb', 'sendEmail'],
    );
  });

  it('defaults to observe-only log mode', () => {
    const result = autoGuard(executors, { print: false });
    expect(result.effectiveConfig.alertMode).toBe('log');
  });

  it('infers outbound tools and trust overrides', () => {
    const result = autoGuard(executors, { print: false });
    expect(result.effectiveOutboundTools).toContain('sendEmail');
    const trust = Object.fromEntries(
      (result.effectiveConfig.trustOverrides ?? []).map((o) => [o.toolName, o.trustLevel]),
    );
    expect(trust.readDb).toBe('trusted');
    expect(trust.fetchUrl).toBe('untrusted');
  });

  it('lets user overrides win over inference', () => {
    const result = autoGuard(executors, {
      print: false,
      overrides: [{ toolName: 'readDb', trustLevel: 'untrusted' }],
    });
    const trust = Object.fromEntries(
      (result.effectiveConfig.trustOverrides ?? []).map((o) => [o.toolName, o.trustLevel]),
    );
    expect(trust.readDb).toBe('untrusted');
  });

  it('unions user-forced outbound tools with inferred ones', () => {
    const result = autoGuard(executors, {
      print: false,
      outboundTools: ['readDb'],
    });
    expect(result.effectiveOutboundTools).toContain('readDb');
    expect(result.effectiveOutboundTools).toContain('sendEmail');
  });

  it('prints the classification table by default', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    autoGuard(executors);
    expect(spy).toHaveBeenCalled();
    const printed = spy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(printed).toContain('Auto-classification');
    spy.mockRestore();
  });

  it('honors an explicit interrupt-mode promotion once classified', () => {
    // readDb → trusted, fetchUrl → untrusted, sendEmail → outbound: both trust
    // levels present, so interrupt-mode validation passes.
    expect(() =>
      autoGuard(executors, { print: false, config: { alertMode: 'interrupt' } }),
    ).not.toThrow();
    const result = autoGuard(executors, { print: false, config: { alertMode: 'interrupt' } });
    expect(result.effectiveConfig.alertMode).toBe('interrupt');
  });

  it('returns a working guarded executor', async () => {
    const result = autoGuard(executors, { print: false });
    await expect(result.executors.readDb({})).resolves.toBe('ok');
    result.destroy();
  });
});
