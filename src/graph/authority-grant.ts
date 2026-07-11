/**
 * Authority Grant — purpose-bound / time-bound authority for signed manifests
 * (Track B #3).
 *
 * A grant is an OPTIONAL addition to the signed manifest (and to individual
 * delegation edges, #4). It carries a validity window (`notBefore`/`notAfter`)
 * and a declarative purpose scope. Enforcement is a PURE function of the grant
 * plus a caller-injected turn context — the clock is passed in, never read from
 * `Date.now()` inside the scored decision path (the same defect removed from the
 * governor; see docs/authority/PRE_REGISTRATION.md, invariants I3/I4).
 *
 * Enforcement is fail-closed: an out-of-window or purpose-mismatched grant
 * yields a violation reason, which the manifest gate turns into an INTEGRITY
 * blocking signal — never a soft alert.
 *
 * Scope semantics are declarative scope-match, NOT semantic intent
 * verification (pre-reg §1.2).
 */

/** A purpose-bound / time-bound authority grant. All fields optional; an empty
 *  grant is equivalent to no grant (enforces nothing, binds nothing). */
export interface AuthorityGrant {
  /** Inclusive lower bound of the validity window (epoch-ms, injected-clock). */
  readonly notBefore?: number;
  /** Inclusive upper bound of the validity window (epoch-ms, injected-clock). */
  readonly notAfter?: number;
  /** Bound purpose scopes. A turn's declared purpose must scope-match one. */
  readonly purpose?: readonly string[];
}

/** The caller-injected turn context the grant is enforced against. */
export interface TurnAuthorityContext {
  /** Injected turn timestamp (epoch-ms). Never read from the process clock
   *  inside the pure enforcement function. */
  readonly turnTs: number;
  /** The turn's declared purpose, matched against a grant's bound scopes. */
  readonly declaredPurpose?: string;
}

/** Why a grant failed enforcement. */
export type GrantViolationReason = 'WINDOW_NOT_YET_VALID' | 'WINDOW_EXPIRED' | 'PURPOSE_MISMATCH';

/** Canonical (signed-preimage) form of a grant: fixed field order, sorted and
 *  de-duplicated purpose scopes. `null` when the grant is absent or empty, so a
 *  no-grant manifest's signed payload is byte-identical to the pre-grant form
 *  (pre-reg invariant I5). */
export interface CanonicalGrant {
  readonly notBefore: number | null;
  readonly notAfter: number | null;
  readonly purpose: readonly string[];
}

/** Does this grant carry any binding at all? */
export function hasGrant(grant: AuthorityGrant | undefined): grant is AuthorityGrant {
  if (!grant) {
    return false;
  }
  return (
    grant.notBefore !== undefined ||
    grant.notAfter !== undefined ||
    (grant.purpose !== undefined && grant.purpose.length > 0)
  );
}

/** Canonicalize a grant for the signed preimage. Returns `null` for an
 *  absent/empty grant so the payload stays byte-identical to the no-grant form. */
export function canonicalGrant(grant: AuthorityGrant | undefined): CanonicalGrant | null {
  if (!hasGrant(grant)) {
    return null;
  }
  const purpose =
    grant.purpose === undefined
      ? []
      : [...new Set(grant.purpose)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return {
    notBefore: grant.notBefore ?? null,
    notAfter: grant.notAfter ?? null,
    purpose,
  };
}

/**
 * Declarative scope-match: a declared purpose `p` matches bound scopes `S` iff
 * `p ∈ S` or some `s ∈ S` is a dot-prefix of `p` (`s === p` or
 * `p.startsWith(s + '.')`). A `null`/absent declared purpose against a
 * non-empty bound scope is a mismatch (fail-closed).
 */
export function purposeMatches(bound: readonly string[], declared: string | undefined): boolean {
  if (bound.length === 0) {
    return true; // no purpose bound → nothing to enforce
  }
  if (declared === undefined || declared === '') {
    return false; // fail-closed: a bound scope with no declared purpose
  }
  for (const s of bound) {
    if (declared === s || declared.startsWith(s + '.')) {
      return true;
    }
  }
  return false;
}

/**
 * Enforce a grant against an injected turn context. PURE — no clock, no
 * randomness. Returns the violation reason, or `null` when the grant is
 * satisfied (or absent). Window bounds are inclusive.
 */
export function enforceGrant(
  grant: AuthorityGrant | undefined,
  ctx: TurnAuthorityContext,
): GrantViolationReason | null {
  if (!hasGrant(grant)) {
    return null;
  }
  if (grant.notBefore !== undefined && ctx.turnTs < grant.notBefore) {
    return 'WINDOW_NOT_YET_VALID';
  }
  if (grant.notAfter !== undefined && ctx.turnTs > grant.notAfter) {
    return 'WINDOW_EXPIRED';
  }
  if (grant.purpose !== undefined && grant.purpose.length > 0) {
    if (!purposeMatches(grant.purpose, ctx.declaredPurpose)) {
      return 'PURPOSE_MISMATCH';
    }
  }
  return null;
}
