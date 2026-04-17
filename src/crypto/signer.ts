/**
 * Signer / Verifier — cryptographic authorization primitives for Cerberus.
 *
 * Used to sign and verify execution-graph manifests (delegation graph, EGI)
 * so that any mutation after initialization is cryptographically detectable.
 *
 * Two adapters ship with the public core:
 *
 *   - HmacSigner    — HMAC-SHA256 with a caller-supplied key. Symmetric.
 *                     Retained for backward compatibility and for dev setups
 *                     where a shared secret is acceptable.
 *
 *   - Ed25519Signer — EdDSA over Curve25519. Asymmetric. The default.
 *                     Sign with the private key, verify with the public key.
 *                     This is the primitive used by the "cryptographic
 *                     authorization gate" model — a manifest signed by an
 *                     authorized signer can be verified by any party holding
 *                     the public key, and late-registration amendments must
 *                     be produced by a key holder (not the runtime itself).
 *
 * Enterprise deployments should plug in a KMS/HSM-backed Signer that
 * implements the same interface. The core never needs to see a raw private
 * key — `sign()` can be routed through AWS KMS, GCP KMS, Azure Key Vault,
 * or HashiCorp Vault Transit.
 *
 * Depends on: node:crypto (built in).
 */

import {
  createHash,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPublicKey,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

// ── Types ───────────────────────────────────────────────────────────

/** Supported signing algorithms. */
export type SigningAlgorithm = "HMAC-SHA256" | "Ed25519";

/**
 * Signs a canonical payload. Implementations may route `sign()` to a local
 * key, a KMS/HSM, or a remote gateway; callers must not assume the private
 * key material is in-process.
 */
export interface Signer {
  readonly algorithm: SigningAlgorithm;
  /** Short identifier for the key that produced the signature (e.g. the
   *  SHA-256 prefix of the public key or HMAC key). Included in signed
   *  payloads so verifiers can pick the right key. */
  readonly keyId: string;
  /** Returns a hex-encoded signature for the given canonical payload. */
  sign(payload: string): string;
}

/**
 * Verifies a signature against a canonical payload.
 */
export interface Verifier {
  readonly algorithm: SigningAlgorithm;
  readonly keyId: string;
  verify(payload: string, signature: string): boolean;
}

/** A signer that can also verify (i.e. holds both halves of the key pair,
 *  or the symmetric HMAC key). */
export interface SignerVerifier extends Signer, Verifier {}

// ── HMAC (symmetric) ────────────────────────────────────────────────

export interface HmacSignerOptions {
  /** Raw HMAC key. If omitted, a random 32-byte key is generated. */
  readonly key?: Buffer;
  /** Optional key identifier. If omitted, derived from SHA-256(key). */
  readonly keyId?: string;
}

/**
 * Symmetric HMAC-SHA256 signer/verifier. Retained for backward
 * compatibility and dev setups where a shared secret is acceptable.
 * Not suitable for the enterprise "authorized signer" gate model — use
 * `Ed25519Signer` there, since HMAC requires verifiers to hold the
 * private key material.
 */
export class HmacSigner implements SignerVerifier {
  readonly algorithm: SigningAlgorithm = "HMAC-SHA256";
  readonly keyId: string;
  readonly #key: Buffer;

  constructor(opts: HmacSignerOptions = {}) {
    this.#key = opts.key ?? randomBytes(32);
    this.keyId =
      opts.keyId ??
      createHash("sha256").update(this.#key).digest("hex").slice(0, 16);
  }

  sign(payload: string): string {
    return createHmac("sha256", this.#key).update(payload).digest("hex");
  }

  verify(payload: string, signature: string): boolean {
    const expected = this.sign(payload);
    if (expected.length !== signature.length) {
      return false;
    }
    try {
      return timingSafeEqual(
        Buffer.from(expected, "hex"),
        Buffer.from(signature, "hex"),
      );
    } catch {
      return false;
    }
  }
}

// ── Ed25519 (asymmetric) ────────────────────────────────────────────

export interface Ed25519SignerOptions {
  /** Existing Ed25519 private key. If omitted, a fresh keypair is generated. */
  readonly privateKey?: KeyObject;
  /** Optional matching public key. Derived from `privateKey` if not given. */
  readonly publicKey?: KeyObject;
  /** Optional key identifier. If omitted, derived from the SPKI of the public key. */
  readonly keyId?: string;
}

/**
 * Asymmetric Ed25519 (EdDSA over Curve25519) signer/verifier. Default
 * for cryptographic manifest authorization. Sign with the private key,
 * verify with the public key. If no private key is supplied a fresh
 * keypair is generated in memory. Enterprise deployments should inject
 * a KMS/HSM-backed signer that implements this same interface.
 */
export class Ed25519Signer implements SignerVerifier {
  readonly algorithm: SigningAlgorithm = "Ed25519";
  readonly keyId: string;
  readonly publicKey: KeyObject;
  readonly #privateKey: KeyObject;

  constructor(opts: Ed25519SignerOptions = {}) {
    if (opts.privateKey) {
      this.#privateKey = opts.privateKey;
      this.publicKey = opts.publicKey ?? createPublicKey(opts.privateKey);
    } else {
      const pair = generateKeyPairSync("ed25519");
      this.#privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
    }
    this.keyId = opts.keyId ?? fingerprintPublicKey(this.publicKey);
  }

  sign(payload: string): string {
    return cryptoSign(null, Buffer.from(payload), this.#privateKey).toString(
      "hex",
    );
  }

  verify(payload: string, signature: string): boolean {
    try {
      return cryptoVerify(
        null,
        Buffer.from(payload),
        this.publicKey,
        Buffer.from(signature, "hex"),
      );
    } catch {
      return false;
    }
  }
}

export interface Ed25519VerifierOptions {
  readonly publicKey: KeyObject;
  readonly keyId?: string;
}

/** Verify-only adapter — use when the private key lives in a KMS/HSM and
 *  only the public key is available for verification. */
export class Ed25519Verifier implements Verifier {
  readonly algorithm: SigningAlgorithm = "Ed25519";
  readonly keyId: string;
  readonly #publicKey: KeyObject;

  constructor(opts: Ed25519VerifierOptions) {
    this.#publicKey = opts.publicKey;
    this.keyId = opts.keyId ?? fingerprintPublicKey(opts.publicKey);
  }

  verify(payload: string, signature: string): boolean {
    try {
      return cryptoVerify(
        null,
        Buffer.from(payload),
        this.#publicKey,
        Buffer.from(signature, "hex"),
      );
    } catch {
      return false;
    }
  }
}

function fingerprintPublicKey(pub: KeyObject): string {
  const der = pub.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}

// ── Default signer registry ─────────────────────────────────────────
//
// For dev/OSS usage we keep a process-local default signer so callers that
// don't inject one still get real crypto (Ed25519 by default) rather than
// the old hard-coded HMAC literal. Enterprise deployments should always
// call setDefaultSigner() with a KMS-backed adapter at startup.

let defaultSigner: SignerVerifier | null = null;

/** Get the process-wide default signer, creating an ephemeral Ed25519
 *  signer on first use. */
export function getDefaultSigner(): SignerVerifier {
  if (!defaultSigner) {
    defaultSigner = new Ed25519Signer();
  }
  return defaultSigner;
}

/** Install a process-wide default signer. Typically called once at startup
 *  by the host application to bind the runtime to a KMS/HSM-backed key. */
export function setDefaultSigner(signer: SignerVerifier): void {
  defaultSigner = signer;
}

/** Reset the default signer — primarily for tests. */
export function resetDefaultSigner(): void {
  defaultSigner = null;
}
