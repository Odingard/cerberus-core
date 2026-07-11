/**
 * Gate-level invariant tests for authority grants (Track B #3 + #4).
 *
 *   I5  No-grant manifests are unchanged — the signed payload (and thus the
 *       signature) is byte-identical to the pre-grant form.
 *   I6  A delegated-edge grant is signature-covered: tampering any bound field
 *       makes verifyGraphIntegrity() return false (Track B #4).
 *   I8  A grant violation is fail-closed and ordered identically to an invalid
 *       signature: it produces an INTEGRITY signal the interceptor routes to
 *       BLOCK, and the signature gate is checked before the grant gate.
 *
 * Pure-enforcement invariants (I1–I4) live in tests/graph/authority-grant.test.ts.
 */
import { describe, it, expect } from 'vitest';

import {
  createDelegationGraph,
  addAgent,
  addSignedAgent,
  verifyGraphIntegrity,
  type DelegationGraph,
} from '../../src/graph/delegation.js';
import {
  verifyManifestBeforeTurn,
  enforceManifestGrantsBeforeTurn,
} from '../../src/engine/manifest-gate.js';
import { Ed25519Signer, HmacSigner } from '../../src/crypto/signer.js';
import type { AuthorityGrant } from '../../src/graph/authority-grant.js';

const T0 = 1_700_000_000_000;

/**
 * Golden signature over a NO-GRANT manifest, computed with a fixed HMAC key.
 * Locks byte-identity: introducing the optional grant field must NOT change the
 * signed payload of a manifest that carries no grant (invariant I5). If this
 * value changes, the no-grant canonical payload was altered — a breaking change.
 */
const GOLDEN_NO_GRANT_SIG =
  '3a31edd39d932b1a5e8d504e532bd8831dec47c2e03dff64a27a2e51bd221351';

function fixedSigner(): HmacSigner {
  return new HmacSigner({ key: Buffer.alloc(32, 7), keyId: 'golden-key' });
}

function goldenGraph(opts?: { grant?: AuthorityGrant }): DelegationGraph {
  return createDelegationGraph(
    'golden-session',
    {
      agentId: 'root',
      agentType: 'orchestrator',
      declaredTools: ['read_email', 'send_email'],
      riskState: { l1: false, l2: false, l3: false },
    },
    fixedSigner(),
    'cov-commit-xyz',
    opts,
  );
}

describe('I5 — no-grant manifests are byte-identical (unchanged)', () => {
  it('a no-grant manifest matches the pre-grant golden signature', () => {
    expect(goldenGraph().signature).toBe(GOLDEN_NO_GRANT_SIG);
  });

  it('an empty / empty-purpose grant is equivalent to no grant', () => {
    expect(goldenGraph({ grant: {} }).signature).toBe(GOLDEN_NO_GRANT_SIG);
    expect(goldenGraph({ grant: { purpose: [] } }).signature).toBe(GOLDEN_NO_GRANT_SIG);
  });

  it('a present grant produces a distinct signed payload', () => {
    expect(goldenGraph({ grant: { notAfter: T0 } }).signature).not.toBe(GOLDEN_NO_GRANT_SIG);
  });

  it('a grant-bearing manifest still verifies against its own signature', () => {
    const g = goldenGraph({ grant: { notAfter: T0, purpose: ['support'] } });
    expect(verifyGraphIntegrity(g)).toBe(true);
  });
});

describe('I6 — delegated-edge grants are signature-covered (#4)', () => {
  it('a signed edge with an intact grant verifies', () => {
    const signer = new Ed25519Signer();
    const graph = createDelegationGraph(
      's',
      { agentId: 'root', agentType: 'orchestrator', declaredTools: ['a'], riskState: { l1: false, l2: false, l3: false } },
      signer,
    );
    const ok = addSignedAgent(
      graph,
      { agentId: 'child', agentType: 'subagent', declaredTools: ['b'], riskState: { l1: false, l2: false, l3: false } },
      'root',
      'handoff-context',
      { notAfter: T0, purpose: ['research'] },
      signer,
    );
    expect(ok).toBe(true);
    expect(verifyGraphIntegrity(graph)).toBe(true);
  });

  it('tampering a bound grant field breaks edge verification', () => {
    const signer = new Ed25519Signer();
    const graph = createDelegationGraph(
      's',
      { agentId: 'root', agentType: 'orchestrator', declaredTools: ['a'], riskState: { l1: false, l2: false, l3: false } },
      signer,
    );
    addSignedAgent(
      graph,
      { agentId: 'child', agentType: 'subagent', declaredTools: ['b'], riskState: { l1: false, l2: false, l3: false } },
      'root',
      'handoff-context',
      { notAfter: T0 },
      signer,
    );
    expect(verifyGraphIntegrity(graph)).toBe(true);

    // Widen the validity window without re-signing — the edge signature no
    // longer covers the mutated grant.
    const edge = graph.edges[0];
    graph.edges[0] = { ...edge, grant: { notAfter: T0 + 1_000_000 } };
    expect(verifyGraphIntegrity(graph)).toBe(false);
  });

  it('stripping a signed edge grant (downgrade) breaks verification', () => {
    const signer = new Ed25519Signer();
    const graph = createDelegationGraph(
      's',
      { agentId: 'root', agentType: 'orchestrator', declaredTools: ['a'], riskState: { l1: false, l2: false, l3: false } },
      signer,
    );
    addSignedAgent(
      graph,
      { agentId: 'child', agentType: 'subagent', declaredTools: ['b'], riskState: { l1: false, l2: false, l3: false } },
      'root',
      'ctx',
      { purpose: ['scoped'] },
      signer,
    );
    const edge = graph.edges[0];
    const { grant: _dropped, ...withoutGrant } = edge;
    graph.edges[0] = withoutGrant;
    expect(verifyGraphIntegrity(graph)).toBe(false);
  });

  it('legacy unsigned edges (addAgent) stay structurally checked — no regression', () => {
    const signer = new Ed25519Signer();
    const graph = createDelegationGraph(
      's',
      { agentId: 'root', agentType: 'orchestrator', declaredTools: ['a'], riskState: { l1: false, l2: false, l3: false } },
      signer,
    );
    addAgent(
      graph,
      { agentId: 'child', agentType: 'subagent', declaredTools: ['b'], riskState: { l1: false, l2: false, l3: false } },
      'root',
      'ctx',
    );
    expect(graph.edges[0].signature).toBeUndefined();
    expect(verifyGraphIntegrity(graph)).toBe(true);
  });
});

describe('I8 — grant violation is fail-closed and ordered like a bad signature', () => {
  function grantGraph(grant: AuthorityGrant): DelegationGraph {
    return createDelegationGraph(
      'sess',
      { agentId: 'root', agentType: 'orchestrator', declaredTools: ['a'], riskState: { l1: false, l2: false, l3: false } },
      new Ed25519Signer(),
      '',
      { grant },
    );
  }

  it('an expired manifest grant yields an INTEGRITY blocking signal', () => {
    const graph = grantGraph({ notAfter: T0 });
    const sig = enforceManifestGrantsBeforeTurn(graph, { turnTs: T0 + 1 }, 'sess', 'turn-1');
    expect(sig).not.toBeNull();
    expect(sig?.layer).toBe('INTEGRITY');
    expect(sig?.signal).toBe('AUTHORITY_GRANT_VIOLATION');
    expect(sig?.scope).toBe('MANIFEST');
    expect(sig?.reason).toBe('WINDOW_EXPIRED');
    expect(sig?.turnTs).toBe(T0 + 1);
  });

  it('a purpose-mismatch manifest grant fails closed', () => {
    const graph = grantGraph({ purpose: ['billing'] });
    const sig = enforceManifestGrantsBeforeTurn(
      graph,
      { turnTs: T0, declaredPurpose: 'exfiltrate' },
      'sess',
      'turn-2',
    );
    expect(sig?.reason).toBe('PURPOSE_MISMATCH');
  });

  it('a valid, in-window, in-scope grant passes the gate (null)', () => {
    const graph = grantGraph({ notBefore: T0, notAfter: T0 + 1_000, purpose: ['billing'] });
    const sig = enforceManifestGrantsBeforeTurn(
      graph,
      { turnTs: T0 + 500, declaredPurpose: 'billing.read' },
      'sess',
      'turn-3',
    );
    expect(sig).toBeNull();
  });

  it('enforces an active delegated-edge grant alongside the manifest', () => {
    const graph = grantGraph({ notAfter: T0 + 10_000 });
    const edgeGrant: AuthorityGrant = { notAfter: T0 };
    const sig = enforceManifestGrantsBeforeTurn(
      graph,
      { turnTs: T0 + 1 },
      'sess',
      'turn-4',
      edgeGrant,
    );
    expect(sig?.scope).toBe('EDGE');
    expect(sig?.reason).toBe('WINDOW_EXPIRED');
  });

  it('checks the manifest grant before the edge grant (ordering)', () => {
    const graph = grantGraph({ notAfter: T0 });
    const sig = enforceManifestGrantsBeforeTurn(
      graph,
      { turnTs: T0 + 1 },
      'sess',
      'turn-5',
      { notAfter: T0 }, // edge also expired, but manifest is reported first
    );
    expect(sig?.scope).toBe('MANIFEST');
  });

  it('signature failure takes precedence over grant validity (fail-closed ordering)', () => {
    // A tampered, expired-grant manifest: the signature gate fires first, so
    // the reported failure is the signature — never a softer grant reason.
    const graph = grantGraph({ notAfter: T0 });
    const root = graph.nodes.get('root');
    if (!root) throw new Error('root missing');
    graph.nodes.set('root', { ...root, declaredTools: [] }); // tamper
    const sigResult = verifyManifestBeforeTurn(graph, 'sess', 'turn-6');
    expect(sigResult?.signal).toBe('MANIFEST_SIGNATURE_INVALID');
  });

  it('no grant present → gate is a no-op (null)', () => {
    const graph = createDelegationGraph(
      'sess',
      { agentId: 'root', agentType: 'orchestrator', declaredTools: ['a'], riskState: { l1: false, l2: false, l3: false } },
      new Ed25519Signer(),
    );
    expect(enforceManifestGrantsBeforeTurn(graph, { turnTs: T0 }, 'sess', 'turn-7')).toBeNull();
    expect(enforceManifestGrantsBeforeTurn(undefined, { turnTs: T0 }, 'sess', 'turn-8')).toBeNull();
  });
});
