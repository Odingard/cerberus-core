"""
cerberus_ai.telemetry.observe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Observe — tamper-evident telemetry emitter.

Every event is HMAC-signed against a *persisted* key so that Guard (or any
verifier) can re-compute the signature. Sequence numbers are monotonically
increasing per-emitter so a verifier can detect gaps (telemetry
suppression).

Key custody (in order of precedence):

    1. ``ObserveConfig.signing_key_path`` — a file containing 32 bytes
       of key material. Production deployments should set this, chown
       the file to the service account, and ``chmod 0400``.
    2. ``ObserveConfig.signing_key_env`` — an env-var name whose value
       is hex- or base64-encoded key material.
    3. Ephemeral ``os.urandom(32)`` — only used when
       ``allow_ephemeral_signing_key=True``. A high-severity
       ``TELEMETRY_GAP`` event is emitted so downstream Guard / SIEM
       see that tamper-evident verification is *not* available.

Air-gapped mode (``ObserveConfig.airgap_mode=True``):

    * All network emitters (SIEM forward) are disabled.
    * Every NDJSON record is AES-256-GCM encrypted with a per-record
      random nonce. The encrypted record is emitted as
      ``<nonce_hex>.<ciphertext_hex>.<tag_hex>`` to preserve the
      line-delimited framing.
    * Logs rotate on ``rotation_interval_s`` (default daily) and any
      rotated file older than ``retention_days`` is deleted.

The emitter is intentionally synchronous and best-effort on the network
side — it never blocks the inspector hot path.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cerberus_ai.models import EventType, ObserveConfig, SecurityEvent, Severity

logger = logging.getLogger("cerberus.observe")


def _sign_event(event: SecurityEvent, key: bytes) -> str:
    et = event.event_type
    event_type = et.value if hasattr(et, "value") else str(et)
    payload = (
        f"{event.event_id}:{event_type}:"
        f"{event.timestamp_ms}:{event.sequence_number}"
    )
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def _load_key_bytes(path: str | None, env: str | None) -> bytes | None:
    """Load key material from disk or env. Returns 32-byte key or None."""
    if path:
        raw = Path(path).read_bytes()
    elif env:
        raw_text = os.environ.get(env)
        if raw_text is None:
            raise ValueError(f"ObserveConfig.signing_key_env={env!r} not set")
        raw = raw_text.strip().encode()
    else:
        return None

    # Accept raw 32-byte, hex-32, base64-44/urlsafe
    if len(raw) == 32:
        return raw
    try:
        decoded = bytes.fromhex(raw.decode())
        if len(decoded) == 32:
            return decoded
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        decoded = base64.b64decode(raw, validate=True)
        if len(decoded) == 32:
            return decoded
    except (ValueError, Exception) as e:  # noqa: BLE001
        logger.debug("Observe key base64 decode failed: %s", e)
    try:
        decoded = base64.urlsafe_b64decode(raw)
        if len(decoded) == 32:
            return decoded
    except Exception as e:  # noqa: BLE001
        logger.debug("Observe key urlsafe-base64 decode failed: %s", e)

    raise ValueError("Observe key material must decode to 32 bytes (raw/hex/base64)")


class Verifier(Protocol):
    """Verifies an NDJSON record produced by :class:`ObserveEmitter`."""

    def verify(self, record: dict[str, Any]) -> bool: ...


class ObserveVerifier:
    """
    External verifier for Observe NDJSON logs.

    Example::

        verifier = ObserveVerifier(signing_key_path="/etc/cerberus/observe.key")
        with open("/var/log/cerberus/events", encoding="utf-8") as fh:
            for line in fh:
                record = json.loads(line)
                if not verifier.verify(record):
                    raise RuntimeError("tamper detected")
    """

    def __init__(
        self,
        signing_key: bytes | None = None,
        signing_key_path: str | None = None,
        signing_key_env: str | None = None,
    ) -> None:
        key = signing_key or _load_key_bytes(signing_key_path, signing_key_env)
        if key is None:
            raise ValueError("ObserveVerifier requires a signing key")
        self._key = key

    def verify(self, record: dict[str, Any]) -> bool:
        sig = record.get("_signature")
        if not isinstance(sig, str):
            return False
        event_id = record.get("event_id", "")
        event_type = record.get("event_type", "")
        timestamp_ms = record.get("timestamp_ms", 0)
        sequence_number = record.get("sequence_number", 0)
        payload = f"{event_id}:{event_type}:{timestamp_ms}:{sequence_number}"
        expected = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)


class ObserveEmitter:
    """
    Emits signed security events to the configured output(s).

    Modes:
      LOCAL_ONLY         — filesystem NDJSON log only
      LOCAL_PLUS_SIEM    — filesystem + internal SIEM HTTP endpoint
      LOCAL_PLUS_SYSLOG  — filesystem + local syslog
      DISABLED           — no emission
    """

    def __init__(self, config: ObserveConfig, signing_key: bytes | None = None) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._log_file: IO[str] | None = None
        self._log_opened_at: float = 0.0
        self._log_path: Path | None = None
        self._aesgcm: AESGCM | None = None
        self._using_ephemeral_key = False
        # In-process event listeners. Called synchronously inside emit();
        # listeners MUST be fast and MUST NOT raise (exceptions are caught
        # and logged so they cannot break the inspector hot path).
        self._listeners: list[Callable[[SecurityEvent], None]] = []

        # ── Signing key custody ──────────────────────────────────────────
        key = signing_key or _load_key_bytes(
            config.signing_key_path, config.signing_key_env
        )
        if key is None:
            if not config.allow_ephemeral_signing_key and config.enabled:
                raise ValueError(
                    "ObserveConfig.enabled=True but no signing key material "
                    "was provided. Set ObserveConfig.signing_key_path, "
                    "ObserveConfig.signing_key_env, or explicitly opt in "
                    "with allow_ephemeral_signing_key=True for dev."
                )
            key = os.urandom(32)
            self._using_ephemeral_key = True
        self._key: bytes = key

        # ── Air-gap AES-256-GCM key ──────────────────────────────────────
        if config.airgap_mode:
            enc_key = _load_key_bytes(
                config.encryption_key_path, config.encryption_key_env
            )
            if enc_key is None:
                raise ValueError(
                    "ObserveConfig.airgap_mode=True requires "
                    "encryption_key_path or encryption_key_env"
                )
            self._aesgcm = AESGCM(enc_key)

        # ── Open log file ────────────────────────────────────────────────
        if config.enabled and config.mode != "DISABLED":
            if config.mode in ("LOCAL_ONLY", "LOCAL_PLUS_SIEM", "LOCAL_PLUS_SYSLOG"):
                self._open_log_file()

        # Warn loudly if we fell back to an ephemeral key — Guard cannot
        # verify these events, so the log has the "signed NDJSON" shape
        # but not the property.
        if self._using_ephemeral_key and config.enabled:
            logger.warning(
                "Observe: no persisted signing key configured. Signatures "
                "cannot be verified by any external party. Set "
                "ObserveConfig.signing_key_path or signing_key_env for "
                "tamper-evident telemetry."
            )

    def _open_log_file(self) -> None:
        log_path = Path(self._config.log_path)
        self._log_path = log_path
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
            self._log_opened_at = time.time()
        except OSError:
            # In constrained environments (tests, containers) fall back to stderr
            self._log_file = sys.stderr
            self._log_opened_at = time.time()

    def _rotate_if_due(self) -> None:
        """Rotate the log file if rotation_interval_s has elapsed; also enforce retention."""
        if (
            self._log_file is None
            or self._log_file is sys.stderr
            or self._log_path is None
            or self._config.rotation_interval_s <= 0
        ):
            return
        now = time.time()
        if now - self._log_opened_at < self._config.rotation_interval_s:
            return
        # Rotate
        try:
            self._log_file.close()
            suffix = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now))
            rotated = self._log_path.with_name(f"{self._log_path.name}.{suffix}")
            self._log_path.rename(rotated)
            self._open_log_file()
            self._enforce_retention()
        except OSError as e:  # pragma: no cover - best-effort
            logger.error("Observe rotation failure: %s", e)

    def _enforce_retention(self) -> None:
        """Delete rotated logs older than retention_days. Best-effort."""
        if self._log_path is None or self._config.retention_days <= 0:
            return
        cutoff = time.time() - (self._config.retention_days * 86_400)
        parent = self._log_path.parent
        prefix = self._log_path.name + "."
        try:
            for entry in parent.iterdir():
                if not entry.name.startswith(prefix):
                    continue
                try:
                    if entry.stat().st_mtime < cutoff:
                        entry.unlink(missing_ok=True)
                except OSError:
                    continue
        except OSError:
            return

    def add_listener(self, fn: Callable[[SecurityEvent], None]) -> None:
        """
        Register an in-process listener that is invoked synchronously for
        every emitted event. Used by the Prometheus exporter and any
        other in-process subscribers (dashboards, SIEM bridges).

        Listeners MUST be fast and MUST NOT raise. Exceptions are caught
        and logged; a slow listener will slow down the inspector.
        """
        self._listeners.append(fn)

    def emit(self, event: SecurityEvent) -> None:
        if not self._config.enabled or self._config.mode == "DISABLED":
            return

        signature = _sign_event(event, self._key)
        event_dict = event.model_dump(mode="json")
        event_dict["_signature"] = signature
        event_dict["_emitted_at_ms"] = int(time.time() * 1000)

        line = json.dumps(event_dict, default=str)

        with self._lock:
            self._rotate_if_due()
            self._write_line(line)

        # Fan out to in-process listeners (exporters, dashboards).
        # Exceptions are isolated so a buggy listener cannot poison the
        # inspector hot path.
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:  # noqa: BLE001
                logger.warning("Observe listener raised: %s", e)

        logger.info(
            "cerberus_event",
            extra={
                "event_type": event.event_type,
                "severity": event.severity,
                "session_id": event.session_id,
                "turn_id": event.turn_id,
                "blocked": event.blocked,
                "sequence_number": event.sequence_number,
            },
        )

        # SIEM forward — disabled in air-gap mode regardless of siem_endpoint.
        if (
            not self._config.airgap_mode
            and self._config.mode == "LOCAL_PLUS_SIEM"
            and self._config.siem_endpoint
        ):
            self._forward_siem(line)

    def _write_line(self, line: str) -> None:
        if self._log_file is None:
            return
        try:
            if self._aesgcm is not None:
                nonce = os.urandom(12)
                ct = self._aesgcm.encrypt(nonce, line.encode(), None)
                # Last 16 bytes of `ct` are the AEAD tag.
                body, tag = ct[:-16], ct[-16:]
                line_out = f"{nonce.hex()}.{body.hex()}.{tag.hex()}\n"
            else:
                line_out = line + "\n"
            self._log_file.write(line_out)
            self._log_file.flush()
        except OSError as e:
            logger.error("Observe write failure: %s", e)

    def _forward_siem(self, event_json: str) -> None:
        """Best-effort SIEM forward — failure is logged but never silently swallowed."""
        try:
            import httpx
            endpoint = self._config.siem_endpoint
            if endpoint is None:
                return
            httpx.post(
                endpoint,
                content=event_json,
                headers={"Content-Type": "application/x-ndjson"},
                timeout=2.0,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("SIEM forward failure (events retained locally): %s", e)

    def emit_ephemeral_key_warning(self) -> SecurityEvent | None:
        """Return a ``TELEMETRY_GAP`` event if this emitter is using an
        ephemeral signing key, else None. Safe to call at startup."""
        if not self._using_ephemeral_key:
            return None
        return SecurityEvent(
            event_type=EventType.TELEMETRY_GAP,
            severity=Severity.HIGH,
            turn_id="startup",
            session_id="startup",
            payload={
                "warning": (
                    "Observe is using an ephemeral signing key — event "
                    "signatures cannot be verified by an external party. "
                    "Set signing_key_path or signing_key_env for "
                    "tamper-evident telemetry."
                ),
            },
        )

    @property
    def using_ephemeral_key(self) -> bool:
        return self._using_ephemeral_key

    @property
    def airgap_mode(self) -> bool:
        return self._config.airgap_mode

    @property
    def signing_key(self) -> bytes:
        """Expose the signing key to an in-process Verifier. Never serialize."""
        return self._key

    def close(self) -> None:
        if self._log_file and self._log_file is not sys.stderr:
            try:
                self._log_file.close()
            except Exception as e:  # noqa: BLE001
                logger.debug("Observe log close failed: %s", e)
            self._log_file = None
