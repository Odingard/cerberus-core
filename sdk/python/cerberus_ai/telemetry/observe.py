"""
cerberus_ai.telemetry.observe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Observe — tamper-evident telemetry emitter.

Events are signed before emission. Guard validates signatures.
Sequence numbers enable continuity monitoring (gap = suppression alert).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
from pathlib import Path

from cerberus_ai.models import ObserveConfig, SecurityEvent

logger = logging.getLogger("cerberus.observe")


def _sign_event(event: SecurityEvent, key: bytes) -> str:
    payload = f"{event.event_id}:{event.event_type}:{event.timestamp_ms}:{event.sequence_number}"
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


class ObserveEmitter:
    """
    Emits signed security events to the configured output(s).

    Modes:
      LOCAL_ONLY         — filesystem NDJSON log only
      LOCAL_PLUS_SIEM    — filesystem + internal SIEM HTTP endpoint
      LOCAL_PLUS_SYSLOG  — filesystem + local syslog
    """

    def __init__(self, config: ObserveConfig, signing_key: bytes | None = None) -> None:
        self._config = config
        self._key = signing_key or os.urandom(32)
        self._log_file = None

        if config.enabled and config.mode != "DISABLED":
            if config.mode in ("LOCAL_ONLY", "LOCAL_PLUS_SIEM", "LOCAL_PLUS_SYSLOG"):
                log_path = Path(config.log_path)
                try:
                    log_path.parent.mkdir(parents=True, exist_ok=True)
                    self._log_file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115
                except OSError:
                    # In constrained environments (tests, containers) fall back to stderr
                    self._log_file = sys.stderr  # type: ignore[assignment]

    def emit(self, event: SecurityEvent) -> None:
        if not self._config.enabled:
            return

        # Sign the event
        signature = _sign_event(event, self._key)
        event_dict = event.model_dump(mode="json")
        event_dict["_signature"] = signature
        event_dict["_emitted_at_ms"] = int(time.time() * 1000)

        line = json.dumps(event_dict, default=str)

        # Write to local log
        if self._log_file is not None:
            try:
                self._log_file.write(line + "\n")
                self._log_file.flush()
            except OSError as e:
                logger.error("Observe write failure: %s", e)

        # Structured log to stderr/stdout for container environments
        logger.info(
            "cerberus_event",
            extra={
                "event_type": event.event_type,
                "severity": event.severity,
                "session_id": event.session_id,
                "turn_id": event.turn_id,
                "blocked": event.blocked,
                "sequence_number": event.sequence_number,
            }
        )

        # SIEM forward (if configured)
        if self._config.mode == "LOCAL_PLUS_SIEM" and self._config.siem_endpoint:
            self._forward_siem(line)

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
        except Exception as e:
            logger.warning("SIEM forward failure (events retained locally): %s", e)

    def close(self) -> None:
        if self._log_file and self._log_file is not sys.stderr:
            self._log_file.close()
