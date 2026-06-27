/**
 * Per-agent authorship (AL3) — type contracts (open tier).
 *
 * These are the AL3 authorship TYPE contracts only. The Ed25519 keypair /
 * signing / verification IMPLEMENTATION (`generateAgentKeyPair`, `signCommitment`,
 * `verifySignature`, `createAgentSigner`, `createAgentKeyRegistry`, …) is the
 * licensed per-agent authorship layer and lives in `@cerberus-ai/enterprise`
 * (`graph/authorship.ts`). The open tier ships only the contracts so a caller
 * can type a `signer` on a provenance write and the ledger types stay complete
 * without shipping the paid signing implementation.
 *
 * Depends on: node:crypto (type-only — `KeyObject`).
 */

import type { KeyObject } from 'node:crypto';

/** An Ed25519 keypair for an agent/writer. */
export interface AgentKeyPair {
  readonly publicKey: KeyObject;
  readonly privateKey: KeyObject;
}

/**
 * A bound signer for one agent/writer. Wraps the agent's identity (`author`)
 * and its private key so the ledger write path can sign a commitment without
 * ever seeing the private key directly. Pass to a provenance write input.
 */
export interface AgentSigner {
  /** The agent/writer identity this signer signs as. */
  readonly author: string;
  /** Sign a content+deps commitment as `author`; returns a base64 signature. */
  readonly sign: (commitment: string) => string;
}

/**
 * Minimal registry mapping an author identity to its public (verification) key.
 * Holds ONLY public keys — never private keys. Verification on read/audit looks
 * up the *claimed* author's key here, so a forged signature minted by an
 * unregistered or different key cannot verify.
 */
export interface AgentKeyRegistry {
  /** Register (or replace) an author's public key. Accepts a KeyObject or SPKI PEM. */
  readonly register: (author: string, publicKey: KeyObject | string) => void;
  /** The registered public key for an author, or `undefined` if unknown. */
  readonly getPublicKey: (author: string) => KeyObject | undefined;
  /** Whether an author has a registered public key. */
  readonly has: (author: string) => boolean;
  /** All registered author identities. */
  readonly authors: () => readonly string[];
}
