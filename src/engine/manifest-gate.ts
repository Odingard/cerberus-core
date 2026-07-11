/**
 * Manifest Gate — Cryptographic authorization gate for per-turn execution.
 *
 * Runs before any tool executor is invoked. If the session carries a signed
 * execution-graph manifest (the multi-agent delegation graph today), the
 * manifest's signature is verified against its bound canonical payload. Any
 * failure produces a {@link ManifestSignatureInvalidSignal} and the
 * interceptor will short-circuit the turn to a `BLOCKED` outcome — this is
 * the "no valid signature → no state transition" rule.
 *
 * The gate is intentionally fail-closed: a missing verifier, an algorithm
 * mismatch, a keyId mismatch, or a bad signature all return the same signal.
 * Callers must not downgrade this to a soft alert — the interceptor bypasses
 * `resolveAction` for integrity signals.
 */
import type { DelegationGraph } from '../graph/delegation.js';
import { getGraphVerifier, verifyGraphIntegrity } from '../graph/delegation.js';
import type { AuthorityGrant, TurnAuthorityContext } from '../graph/authority-grant.js';
import { enforceGrant } from '../graph/authority-grant.js';
import type { Verifier } from '../crypto/signer.js';
import type {
  AuthorityGrantViolationSignal,
  ManifestSignatureInvalidSignal,
  SessionId,
  TurnId,
} from '../types/signals.js';

/**
 * Verify the session's signed manifest before a turn begins.
 *
 * Returns `null` when the session has no manifest (single-agent mode) or when
 * verification succeeds. Returns a {@link ManifestSignatureInvalidSignal} when
 * verification fails for any reason.
 *
 * @param graph - Signed manifest to verify (or undefined for single-agent).
 * @param sessionId - Session identifier to bind the signal to.
 * @param turnId - Turn identifier to bind the signal to.
 * @param verifier - Optional verifier override. When omitted the verifier
 *   associated with the graph at creation time is used.
 */
export function verifyManifestBeforeTurn(
  graph: DelegationGraph | undefined,
  sessionId: SessionId,
  turnId: TurnId,
  verifier?: Verifier,
): ManifestSignatureInvalidSignal | null {
  if (!graph) {
    return null;
  }

  // Fast path: explicit key/algorithm mismatch before invoking the verifier.
  if (verifier) {
    if (verifier.algorithm !== graph.algorithm) {
      return {
        layer: 'INTEGRITY',
        signal: 'MANIFEST_SIGNATURE_INVALID',
        turnId,
        sessionId,
        algorithm: graph.algorithm,
        keyId: graph.keyId,
        reason: 'ALGORITHM_MISMATCH',
        timestamp: Date.now(),
      };
    }
    if (verifier.keyId !== graph.keyId) {
      return {
        layer: 'INTEGRITY',
        signal: 'MANIFEST_SIGNATURE_INVALID',
        turnId,
        sessionId,
        algorithm: graph.algorithm,
        keyId: graph.keyId,
        reason: 'KEY_ID_MISMATCH',
        timestamp: Date.now(),
      };
    }
  }

  const ok = verifyGraphIntegrity(graph, verifier);
  if (ok) {
    return null;
  }

  // Distinguish "no verifier available at all" from "verifier rejected
  // the signature". Both are BLOCK outcomes but the reason helps audit.
  const available = verifier ?? getGraphVerifier(graph);
  return {
    layer: 'INTEGRITY',
    signal: 'MANIFEST_SIGNATURE_INVALID',
    turnId,
    sessionId,
    algorithm: graph.algorithm,
    keyId: graph.keyId,
    reason: available ? 'SIGNATURE_MISMATCH' : 'VERIFIER_MISSING',
    timestamp: Date.now(),
  };
}

/**
 * Enforce the purpose-bound / time-bound authority grants carried by the
 * session's signed manifest before a turn begins (Track B #3). Runs AFTER the
 * signature gate — the signature proves the grant is authentic; this proves it
 * is still valid *now* and *for this purpose*.
 *
 * Enforcement is a pure function of `(grant, turnContext)`: the turn timestamp
 * and declared purpose are injected by the caller (the interceptor reads the
 * clock at its boundary and passes the value in), never read from `Date.now()`
 * here. This mirrors the governor's injected-TTL discipline and keeps the
 * verdict reproducible (pre-reg invariants I3/I4).
 *
 * Returns the first violating {@link AuthorityGrantViolationSignal} (root
 * manifest grant checked before the active delegated-edge grant), or `null`
 * when every grant in force is satisfied (or absent). A violation is
 * fail-closed: the caller must BLOCK, never downgrade to a soft alert.
 *
 * @param graph - The session's signed manifest (or undefined for single-agent).
 * @param turnCtx - Injected turn context: `{ turnTs, declaredPurpose }`.
 * @param sessionId - Session identifier to bind the signal to.
 * @param turnId - Turn identifier to bind the signal to.
 * @param activeEdgeGrant - Grant on the delegation edge leading to the agent
 *   acting this turn, if any (its window/purpose is enforced alongside the root).
 */
export function enforceManifestGrantsBeforeTurn(
  graph: DelegationGraph | undefined,
  turnCtx: TurnAuthorityContext,
  sessionId: SessionId,
  turnId: TurnId,
  activeEdgeGrant?: AuthorityGrant,
): AuthorityGrantViolationSignal | null {
  if (!graph) {
    return null;
  }

  const manifestReason = enforceGrant(graph.grant, turnCtx);
  if (manifestReason !== null) {
    return {
      layer: 'INTEGRITY',
      signal: 'AUTHORITY_GRANT_VIOLATION',
      turnId,
      sessionId,
      scope: 'MANIFEST',
      reason: manifestReason,
      turnTs: turnCtx.turnTs,
      timestamp: Date.now(),
    };
  }

  const edgeReason = enforceGrant(activeEdgeGrant, turnCtx);
  if (edgeReason !== null) {
    return {
      layer: 'INTEGRITY',
      signal: 'AUTHORITY_GRANT_VIOLATION',
      turnId,
      sessionId,
      scope: 'EDGE',
      reason: edgeReason,
      turnTs: turnCtx.turnTs,
      timestamp: Date.now(),
    };
  }

  return null;
}
