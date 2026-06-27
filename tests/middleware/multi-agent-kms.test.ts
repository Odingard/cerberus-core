/**
 * KMS / public-key-only verifier-override path for the signed-manifest gate.
 *
 * Exercises the H3 integrity-model requirement end-to-end through
 * `guardMultiAgent`: a deployment whose private key lives in a KMS/HSM signs
 * the delegation manifest with a sign-only `Signer` and verifies every turn
 * with a public-key-only `Verifier` (the gateway never holds the private key).
 */

import { describe, it, expect } from 'vitest';
import { Ed25519Signer, Ed25519Verifier } from '../../src/crypto/signer.js';
import type { Signer } from '../../src/crypto/signer.js';
import { verifyGraphIntegrity } from '../../src/graph/delegation.js';
import { guardMultiAgent } from '../../src/middleware/multi-agent.js';
import { guard } from '../../src/middleware/wrap.js';
import type { CerberusConfig } from '../../src/types/config.js';

/**
 * Build a sign-only adapter (no `verify()` — the typical KMS/HSM shape) plus
 * the matching public-key verifier, both bound to the same Ed25519 keypair so
 * their keyIds (SPKI fingerprints) line up.
 */
function makeKmsPair(): { signer: Signer; verifier: Ed25519Verifier } {
  const kms = new Ed25519Signer();
  const signer: Signer = {
    algorithm: kms.algorithm,
    keyId: kms.keyId,
    sign: (payload: string): string => kms.sign(payload),
  };
  const verifier = new Ed25519Verifier({ publicKey: kms.publicKey });
  return { signer, verifier };
}

const executors = {
  noop: (): Promise<string> => Promise.resolve('ok'),
};

const baseConfig: CerberusConfig = {
  alertMode: 'alert',
  multiAgent: true,
  agentType: 'orchestrator',
};

describe('guardMultiAgent — KMS / public-key-only verifier override', () => {
  it('rejects a sign-only manifestSigner with no manifestVerifier (fail fast)', () => {
    const { signer } = makeKmsPair();
    expect(() =>
      guardMultiAgent(executors, { ...baseConfig, manifestSigner: signer }, [], 'root'),
    ).toThrow(/manifestSigner.*sign-only.*manifestVerifier/s);
  });

  it('does NOT fire the sign-only guard for a single-agent guard() config', () => {
    const { signer } = makeKmsPair();
    // multiAgent omitted → the manifest signer is never consulted, so a
    // sign-only signer with no verifier must not throw.
    expect(() => guard(executors, { manifestSigner: signer }, [])).not.toThrow();
  });

  it('signs with a sign-only signer and verifies turns with the public-key verifier', async () => {
    const { signer, verifier } = makeKmsPair();
    const guarded = guardMultiAgent(
      executors,
      { ...baseConfig, manifestSigner: signer, manifestVerifier: verifier },
      [],
      'root',
    );

    const graph = guarded.getDelegationGraph();
    expect(graph.algorithm).toBe('Ed25519');
    expect(graph.keyId).toBe(signer.keyId);
    // The graph self-registered NO verifier (sign-only), so the override is
    // the only way it verifies.
    expect(verifyGraphIntegrity(graph)).toBe(false);
    expect(verifyGraphIntegrity(graph, verifier)).toBe(true);

    // A turn passes the per-turn gate and the executor runs normally.
    const out = await guarded.executors.noop({});
    expect(out).toBe('ok');
    expect(guarded.getLastOutcome()?.blocked).not.toBe(true);
  });

  it('blocks every turn when the override verifier key does not match the manifest', async () => {
    const { signer } = makeKmsPair();
    const wrong = new Ed25519Verifier({ publicKey: new Ed25519Signer().publicKey });
    const guarded = guardMultiAgent(
      executors,
      { ...baseConfig, manifestSigner: signer, manifestVerifier: wrong },
      [],
      'root',
    );

    const out = await guarded.executors.noop({});
    expect(out).toContain('blocked');

    const signals = guarded.session.signalsByTurn.get('turn-000') ?? [];
    expect(signals.some((s) => s.signal === 'MANIFEST_SIGNATURE_INVALID')).toBe(true);
  });

  it('honours the verifier override in spawnAgent integrity checks', () => {
    const { signer, verifier } = makeKmsPair();
    const wrong = new Ed25519Verifier({ publicKey: new Ed25519Signer().publicKey });

    const ok = guardMultiAgent(
      executors,
      { ...baseConfig, manifestSigner: signer, manifestVerifier: verifier },
      [],
      'root',
    );
    expect(ok.spawnAgent('child', 'subagent', [], 'task').success).toBe(true);

    const bad = guardMultiAgent(
      executors,
      { ...baseConfig, manifestSigner: signer, manifestVerifier: wrong },
      [],
      'root',
    );
    const result = bad.spawnAgent('child', 'subagent', [], 'task');
    expect(result.success).toBe(false);
    expect(result.error).toBe('Graph integrity check failed');
  });

  it('works with a full SignerVerifier (Ed25519Signer) and no separate verifier', async () => {
    const signer = new Ed25519Signer();
    const guarded = guardMultiAgent(
      executors,
      { ...baseConfig, manifestSigner: signer },
      [],
      'root',
    );

    // A full signer self-registers as its own verifier — no override needed.
    expect(verifyGraphIntegrity(guarded.getDelegationGraph())).toBe(true);
    const out = await guarded.executors.noop({});
    expect(out).toBe('ok');
    expect(guarded.getLastOutcome()?.blocked).not.toBe(true);
  });
});
