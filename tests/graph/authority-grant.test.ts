/**
 * Invariant tests for purpose-bound / time-bound authority grants
 * (Track B #3 — see docs/authority/PRE_REGISTRATION.md).
 *
 * These lock the PURE-function invariants at the enforcement core:
 *   I1  Expired / not-yet-valid grant is fail-closed (never PASS).
 *   I2  Purpose-mismatch is fail-closed.
 *   I3  Enforcement is a pure function of (grant, injected turn context):
 *       identical inputs → identical verdict over many randomized runs.
 *   I4  The clock is an injected input — the verdict tracks the injected
 *       timestamp, never the process wall-clock.
 *
 * The gate-level invariants (I5 golden byte-identity, I6 signed-edge tamper,
 * I8 fail-closed ordering) live in tests/engine/authority-grant-gate.test.ts.
 * I7 (XBEN non-regression) is covered by tests/integration/argus-xben095.test.ts.
 */
import { describe, it, expect } from 'vitest';

import {
  enforceGrant,
  purposeMatches,
  canonicalGrant,
  hasGrant,
  type AuthorityGrant,
  type TurnAuthorityContext,
} from '../../src/graph/authority-grant.js';

const T0 = 1_700_000_000_000; // fixed reference epoch-ms

describe('authority-grant — I1 time-window is fail-closed', () => {
  const windowed: AuthorityGrant = { notBefore: T0, notAfter: T0 + 1_000 };

  it('permits a timestamp inside the window (inclusive bounds)', () => {
    expect(enforceGrant(windowed, { turnTs: T0 })).toBeNull();
    expect(enforceGrant(windowed, { turnTs: T0 + 500 })).toBeNull();
    expect(enforceGrant(windowed, { turnTs: T0 + 1_000 })).toBeNull();
  });

  it('fails closed just before the window opens', () => {
    expect(enforceGrant(windowed, { turnTs: T0 - 1 })).toBe('WINDOW_NOT_YET_VALID');
  });

  it('fails closed just after the window expires — never degrades to null/PASS', () => {
    expect(enforceGrant(windowed, { turnTs: T0 + 1_001 })).toBe('WINDOW_EXPIRED');
  });

  it('enforces a one-sided notAfter (expiry only)', () => {
    const g: AuthorityGrant = { notAfter: T0 };
    expect(enforceGrant(g, { turnTs: T0 })).toBeNull();
    expect(enforceGrant(g, { turnTs: T0 + 1 })).toBe('WINDOW_EXPIRED');
  });

  it('enforces a one-sided notBefore (activation only)', () => {
    const g: AuthorityGrant = { notBefore: T0 };
    expect(enforceGrant(g, { turnTs: T0 - 1 })).toBe('WINDOW_NOT_YET_VALID');
    expect(enforceGrant(g, { turnTs: T0 })).toBeNull();
  });
});

describe('authority-grant — I2 purpose is fail-closed', () => {
  const scoped: AuthorityGrant = { purpose: ['billing.read', 'support'] };

  it('permits an exact scope match', () => {
    expect(enforceGrant(scoped, { turnTs: T0, declaredPurpose: 'support' })).toBeNull();
  });

  it('permits a dot-prefix (hierarchical) scope match', () => {
    expect(enforceGrant(scoped, { turnTs: T0, declaredPurpose: 'billing.read' })).toBeNull();
    expect(
      enforceGrant({ purpose: ['billing'] }, { turnTs: T0, declaredPurpose: 'billing.read.pdf' }),
    ).toBeNull();
  });

  it('fails closed on a purpose outside the bound scope', () => {
    expect(enforceGrant(scoped, { turnTs: T0, declaredPurpose: 'billing.write' })).toBe(
      'PURPOSE_MISMATCH',
    );
  });

  it('fails closed when no purpose is declared against a bound scope', () => {
    expect(enforceGrant(scoped, { turnTs: T0 })).toBe('PURPOSE_MISMATCH');
    expect(enforceGrant(scoped, { turnTs: T0, declaredPurpose: '' })).toBe('PURPOSE_MISMATCH');
  });

  it('does NOT treat a bound scope as a prefix of an unrelated sibling', () => {
    // 'bill' must not match 'billing' — only 'bill' or 'bill.*'
    expect(enforceGrant({ purpose: ['bill'] }, { turnTs: T0, declaredPurpose: 'billing' })).toBe(
      'PURPOSE_MISMATCH',
    );
  });
});

describe('purposeMatches — declarative scope-match rule', () => {
  it('an empty bound scope enforces nothing', () => {
    expect(purposeMatches([], undefined)).toBe(true);
    expect(purposeMatches([], 'anything')).toBe(true);
  });

  it('matches exact and dot-prefixed scopes only', () => {
    expect(purposeMatches(['a.b'], 'a.b')).toBe(true);
    expect(purposeMatches(['a.b'], 'a.b.c')).toBe(true);
    expect(purposeMatches(['a.b'], 'a.bc')).toBe(false);
    expect(purposeMatches(['a.b'], 'a')).toBe(false);
  });
});

describe('authority-grant — I1/I2 combined ordering', () => {
  it('reports the window failure before the purpose failure', () => {
    const g: AuthorityGrant = { notAfter: T0, purpose: ['x'] };
    // Both fail; window is checked first.
    expect(enforceGrant(g, { turnTs: T0 + 1, declaredPurpose: 'y' })).toBe('WINDOW_EXPIRED');
  });
});

describe('authority-grant — absent / empty grant is a no-op', () => {
  it('returns null for undefined, empty, and empty-purpose grants', () => {
    expect(enforceGrant(undefined, { turnTs: T0 })).toBeNull();
    expect(enforceGrant({}, { turnTs: T0 })).toBeNull();
    expect(enforceGrant({ purpose: [] }, { turnTs: T0 })).toBeNull();
    expect(hasGrant(undefined)).toBe(false);
    expect(hasGrant({})).toBe(false);
    expect(hasGrant({ purpose: [] })).toBe(false);
    expect(hasGrant({ notAfter: T0 })).toBe(true);
  });
});

describe('authority-grant — I3 enforcement is pure/deterministic', () => {
  it('identical inputs yield identical verdicts over 10k randomized runs', () => {
    // Deterministic LCG so the sweep is reproducible without importing a seed lib.
    let state = 0x2545_f491;
    const rand = (): number => {
      state = (state * 1_103_515_245 + 12_345) & 0x7fff_ffff;
      return state / 0x7fff_ffff;
    };
    const purposes = ['a', 'a.b', 'b', 'c.d', undefined];
    for (let i = 0; i < 10_000; i++) {
      const grant: AuthorityGrant = {
        notBefore: T0 + Math.floor((rand() - 0.5) * 4_000),
        notAfter: T0 + Math.floor((rand() + 0.5) * 4_000),
        purpose: rand() < 0.5 ? ['a', 'c.d'] : ['b'],
      };
      const picked = purposes[Math.floor(rand() * purposes.length)];
      const ctx: TurnAuthorityContext = {
        turnTs: T0 + Math.floor((rand() - 0.5) * 8_000),
        ...(picked !== undefined ? { declaredPurpose: picked } : {}),
      };
      const first = enforceGrant(grant, ctx);
      // Re-run many times — a pure function must be invariant.
      for (let k = 0; k < 5; k++) {
        expect(enforceGrant(grant, ctx)).toBe(first);
      }
    }
  });
});

describe('authority-grant — I4 clock is an injected input', () => {
  const g: AuthorityGrant = { notAfter: T0 };

  it('the verdict tracks the injected timestamp, not wall-clock time', () => {
    // Inject a past timestamp → valid; inject a future timestamp → expired.
    // The real Date.now() is ~2025+, far beyond T0, so if enforcement read the
    // wall clock this "valid" case would wrongly fail.
    expect(enforceGrant(g, { turnTs: T0 - 10_000 })).toBeNull();
    expect(enforceGrant(g, { turnTs: T0 + 10_000 })).toBe('WINDOW_EXPIRED');
    // Sanity: the machine clock is well past T0, proving the value is injected.
    expect(Date.now()).toBeGreaterThan(T0);
  });
});

describe('canonicalGrant — signed-preimage normalization', () => {
  it('returns null for absent/empty grants (byte-identity with no-grant payload)', () => {
    expect(canonicalGrant(undefined)).toBeNull();
    expect(canonicalGrant({})).toBeNull();
    expect(canonicalGrant({ purpose: [] })).toBeNull();
  });

  it('sorts and de-duplicates bound purpose scopes deterministically', () => {
    const a = canonicalGrant({ purpose: ['b', 'a', 'b', 'c'] });
    const b = canonicalGrant({ purpose: ['c', 'b', 'a'] });
    expect(a).toEqual({ notBefore: null, notAfter: null, purpose: ['a', 'b', 'c'] });
    expect(a).toEqual(b);
  });

  it('normalizes absent window bounds to null', () => {
    expect(canonicalGrant({ notBefore: T0 })).toEqual({
      notBefore: T0,
      notAfter: null,
      purpose: [],
    });
  });
});
