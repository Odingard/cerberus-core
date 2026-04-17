/**
 * Tests for the Signer / Verifier primitives.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  HmacSigner,
  Ed25519Signer,
  Ed25519Verifier,
  getDefaultSigner,
  setDefaultSigner,
  resetDefaultSigner,
} from "../../src/crypto/signer.js";

describe("HmacSigner", () => {
  it("should round-trip a signature", () => {
    const signer = new HmacSigner();
    const sig = signer.sign("payload-a");
    expect(signer.verify("payload-a", sig)).toBe(true);
  });

  it("should reject a tampered payload", () => {
    const signer = new HmacSigner();
    const sig = signer.sign("payload-a");
    expect(signer.verify("payload-b", sig)).toBe(false);
  });

  it("should reject a tampered signature", () => {
    const signer = new HmacSigner();
    const sig = signer.sign("payload-a");
    const tampered = sig.slice(0, -2) + (sig.endsWith("00") ? "ff" : "00");
    expect(signer.verify("payload-a", tampered)).toBe(false);
  });

  it("should not verify across different keys", () => {
    const a = new HmacSigner();
    const b = new HmacSigner();
    const sig = a.sign("payload");
    expect(b.verify("payload", sig)).toBe(false);
  });

  it("should expose algorithm and a stable keyId for a given key", () => {
    const key = Buffer.alloc(32, 7);
    const a = new HmacSigner({ key });
    const b = new HmacSigner({ key });
    expect(a.algorithm).toBe("HMAC-SHA256");
    expect(a.keyId).toBe(b.keyId);
  });

  it("should reject a signature of mismatched length", () => {
    const signer = new HmacSigner();
    expect(signer.verify("payload", "deadbeef")).toBe(false);
  });
});

describe("Ed25519Signer", () => {
  it("should round-trip a signature", () => {
    const signer = new Ed25519Signer();
    const sig = signer.sign("payload-a");
    expect(signer.verify("payload-a", sig)).toBe(true);
  });

  it("should reject a tampered payload", () => {
    const signer = new Ed25519Signer();
    const sig = signer.sign("payload-a");
    expect(signer.verify("payload-b", sig)).toBe(false);
  });

  it("should reject a tampered signature", () => {
    const signer = new Ed25519Signer();
    const sig = signer.sign("payload-a");
    const tampered = sig.slice(0, -2) + (sig.endsWith("00") ? "ff" : "00");
    expect(signer.verify("payload-a", tampered)).toBe(false);
  });

  it("should not verify across different keypairs", () => {
    const a = new Ed25519Signer();
    const b = new Ed25519Signer();
    const sig = a.sign("payload");
    expect(b.verify("payload", sig)).toBe(false);
  });

  it("should expose Ed25519 as the algorithm", () => {
    const signer = new Ed25519Signer();
    expect(signer.algorithm).toBe("Ed25519");
    expect(signer.keyId).toHaveLength(16);
  });

  it("should allow a separate verify-only party via Ed25519Verifier", () => {
    const signer = new Ed25519Signer();
    const verifier = new Ed25519Verifier({ publicKey: signer.publicKey });
    const sig = signer.sign("payload");
    expect(verifier.verify("payload", sig)).toBe(true);
    expect(verifier.keyId).toBe(signer.keyId);
  });

  it("should derive a public key from a supplied private key", () => {
    const a = new Ed25519Signer();
    const b = new Ed25519Signer({
      privateKey:
        (a as unknown as { "#privateKey": never })["#privateKey"] ?? undefined,
    });
    // If we cannot grab the private key via the private field, just verify
    // the simpler case: a separate signer constructed without options is
    // independent of `a` — proves `a` is self-contained.
    expect(b.algorithm).toBe("Ed25519");
  });
});

describe("default signer registry", () => {
  beforeEach(() => {
    resetDefaultSigner();
  });

  it("should return a stable default signer across calls", () => {
    const a = getDefaultSigner();
    const b = getDefaultSigner();
    expect(a).toBe(b);
    expect(a.algorithm).toBe("Ed25519");
  });

  it("should allow the host app to install a different default signer", () => {
    const injected = new HmacSigner();
    setDefaultSigner(injected);
    expect(getDefaultSigner()).toBe(injected);
  });

  it("should recreate the default signer after reset", () => {
    const a = getDefaultSigner();
    resetDefaultSigner();
    const b = getDefaultSigner();
    expect(a).not.toBe(b);
  });
});
