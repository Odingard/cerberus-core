"""
cerberus_ai.egi.signer
~~~~~~~~~~~~~~~~~~~~~~
Cryptographic signing primitives for EGI manifests.

Two adapters ship with the public core:

    HmacSigner      HMAC-SHA256 with a caller-supplied key. Symmetric.
                    Retained for backward compatibility and for dev setups
                    where a shared secret is acceptable.

    Ed25519Signer   EdDSA over Curve25519. Asymmetric. The default.
                    Sign with the private key, verify with the public key.
                    This is the primitive used by the "cryptographic
                    authorization gate" model — a manifest signed by an
                    authorized signer can be verified by any party holding
                    the public key, and late-registration amendments must
                    be produced by a key holder (not the runtime itself).

Enterprise deployments should plug in a KMS/HSM-backed Signer that
implements the ``Signer`` / ``Verifier`` protocols. The core never needs
to see a raw private key — ``sign()`` can be routed through AWS KMS,
GCP KMS, Azure Key Vault, or HashiCorp Vault Transit.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


SigningAlgorithm = str  # "HMAC-SHA256" | "Ed25519"


@runtime_checkable
class Signer(Protocol):
    """Signs a canonical payload string, returns a hex-encoded signature."""

    @property
    def algorithm(self) -> SigningAlgorithm: ...

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: str) -> str: ...


@runtime_checkable
class Verifier(Protocol):
    """Verifies a hex-encoded signature against a canonical payload string."""

    @property
    def algorithm(self) -> SigningAlgorithm: ...

    @property
    def key_id(self) -> str: ...

    def verify(self, payload: str, signature: str) -> bool: ...


# ── HMAC (symmetric) ─────────────────────────────────────────────────


class HmacSigner:
    """Symmetric HMAC-SHA256 signer. Legacy path."""

    algorithm: SigningAlgorithm = "HMAC-SHA256"

    def __init__(self, key: bytes | None = None, key_id: str | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)
        self._key_id = key_id or hashlib.sha256(self._key).hexdigest()[:16]

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)


# ── Ed25519 (asymmetric) ─────────────────────────────────────────────


def _public_key_fingerprint(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class Ed25519Signer:
    """
    Asymmetric Ed25519 signer. Default for cryptographic authorization.

    If no private key is provided, a fresh Ed25519 keypair is generated in
    memory. In production, inject a private key loaded from a KMS/HSM.
    """

    algorithm: SigningAlgorithm = "Ed25519"

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        key_id: str | None = None,
    ) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._key_id = key_id or _public_key_fingerprint(self._public_key)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def sign(self, payload: str) -> str:
        return self._private_key.sign(payload.encode()).hex()

    def verify(self, payload: str, signature: str) -> bool:
        try:
            self._public_key.verify(bytes.fromhex(signature), payload.encode())
            return True
        except (InvalidSignature, ValueError):
            return False

    # ── Serialization helpers for key distribution ──

    def export_public_key_pem(self) -> bytes:
        """Export the public key as PEM for distribution to verifiers."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def export_private_key_pem(self, password: bytes | None = None) -> bytes:
        """Export the private key as PEM. Encrypt with password if supplied."""
        encryption: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )


class Ed25519Verifier:
    """
    Verify-only adapter — use when the private key lives in a KMS/HSM and
    only the public key is available for verification.
    """

    algorithm: SigningAlgorithm = "Ed25519"

    def __init__(self, public_key: Ed25519PublicKey, key_id: str | None = None) -> None:
        self._public_key = public_key
        self._key_id = key_id or _public_key_fingerprint(public_key)

    @classmethod
    def from_pem(cls, pem_bytes: bytes, key_id: str | None = None) -> "Ed25519Verifier":
        pub = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(pub, Ed25519PublicKey):
            raise TypeError("Expected an Ed25519 public key")
        return cls(pub, key_id=key_id)

    @property
    def key_id(self) -> str:
        return self._key_id

    def verify(self, payload: str, signature: str) -> bool:
        try:
            self._public_key.verify(bytes.fromhex(signature), payload.encode())
            return True
        except (InvalidSignature, ValueError):
            return False


# ── Default signer registry ──────────────────────────────────────────


_default_signer: Signer | None = None


def get_default_signer() -> Signer:
    """Return the process-wide default signer, creating an ephemeral
    Ed25519 signer on first use."""
    global _default_signer
    if _default_signer is None:
        _default_signer = Ed25519Signer()
    return _default_signer


def set_default_signer(signer: Signer) -> None:
    """Install a process-wide default signer. Typically called once at
    startup by the host application to bind the runtime to a KMS/HSM-backed
    key."""
    global _default_signer
    _default_signer = signer


def reset_default_signer() -> None:
    """Reset the default signer — primarily for tests."""
    global _default_signer
    _default_signer = None
